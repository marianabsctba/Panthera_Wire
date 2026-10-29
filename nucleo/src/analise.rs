//! Junta tudo: recebe os pacotes do leitor, monta fluxos e hosts, guarda os
//! eventos de aplicação e entrega o relatório no fim.

use std::cmp::Reverse;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::net::IpAddr;

use serde::Serialize;

use crate::aplicacao::{dhcp, dns, http, tls, x509};
use crate::remontagem::Direcao;
use crate::bytes::mac_texto;
use crate::captura::{ErroCaptura, LeitorCaptura, PacoteBruto};
use crate::decodificacao::{self as dec, Rede, Transporte, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
use crate::{deteccao, historia};
use crate::relatorio::{
    Aviso, Contagem, EventoDhcp, EventoDns, EventoHttp, EventoTls, Fluxo, Host, Relatorio, ResumoCaptura,
};

// Limites do que fica em memória durante a leitura.
const MAX_FLUXOS: usize = 2_000_000;
const MAX_HOSTS: usize = 1_000_000;
const MAX_EVENTOS: usize = 500_000;
const MAX_NOMES_POR_HOST: usize = 16;

// Limites do que vai para a interface.
const SAIDA_FLUXOS: usize = 50_000;
const SAIDA_HOSTS: usize = 20_000;
const SAIDA_EVENTOS: usize = 50_000;

// Depois desse silêncio, a mesma 5-tupla vira um fluxo novo (como no Zeek).
const INATIVIDADE_TCP_US: u64 = 300_000_000;
const INATIVIDADE_UDP_US: u64 = 60_000_000;

/// Quantos segmentos com dados de um fluxo TCP são inspecionados até
/// desistir de reconhecer a aplicação.
const TENTATIVAS_APLICACAO: u8 = 8;

// Remontagem do handshake TLS: quanto de cada direção, e quantas ao mesmo tempo.
const REMONTAGEM_CLIENTE: usize = 16 * 1024;
const REMONTAGEM_SERVIDOR: usize = 32 * 1024;
const MAX_REMONTAGENS: usize = 8192;
/// Cabeçalho HTTP partido em vários segmentos: até quanto remontar.
const REMONTAGEM_HTTP: usize = 8 * 1024;

#[derive(Serialize)]
pub struct Progresso {
    pub pacotes: u64,
    pub fluxos: u64,
}

pub struct Analise {
    leitor: LeitorCaptura,
    estado: Estado,
}

impl Default for Analise {
    fn default() -> Self {
        Self::new()
    }
}

impl Analise {
    pub fn new() -> Self {
        Self { leitor: LeitorCaptura::new(), estado: Estado::default() }
    }

    /// Processa mais um bloco do arquivo. Depois de um erro, o que já foi lido
    /// continua valendo: `finalizar` entrega o relatório parcial com o aviso.
    pub fn alimentar(&mut self, dados: &[u8]) -> Result<Progresso, ErroCaptura> {
        let Analise { leitor, estado } = self;
        leitor.alimentar(dados, |p| estado.pacote(p))?;
        Ok(self.progresso())
    }

    pub fn progresso(&self) -> Progresso {
        Progresso { pacotes: self.estado.pacotes, fluxos: self.estado.fluxos.len() as u64 }
    }

    pub fn finalizar(self) -> Relatorio {
        let Analise { leitor, estado } = self;
        estado.relatorio(&leitor)
    }
}

#[derive(PartialEq, Eq, Hash)]
struct Chave {
    protocolo: u8,
    a: (IpAddr, u16),
    b: (IpAddr, u16),
}

struct FluxoInterno {
    f: Fluxo,
    flags_ida: u8,
    flags_volta: u8,
    tentativas: u8,
    /// Primeiro número de sequência de dados de cada direção (ida, volta),
    /// tirado do SYN ou do SYN-ACK: é a base da remontagem.
    inicio_seq: [Option<u32>; 2],
    /// O handshake TLS desta direção já foi lido (ida, volta).
    tls_lido: [bool; 2],
    /// Bytes de dados que nenhum leitor de aplicação reconheceu.
    carga_desconhecida: u64,
}

#[derive(Default)]
struct Estado {
    pacotes: u64,
    bytes: u64,
    nao_decodificados: u64,
    inicio: Option<u64>,
    fim: u64,
    protocolos: HashMap<&'static str, (u64, u64)>,

    chaves: HashMap<Chave, u32>,
    fluxos: Vec<FluxoInterno>,
    fluxos_ignorados: u64,

    hosts: HashMap<IpAddr, Host>,
    hosts_ignorados: u64,
    /// Nomes aprendidos por DNS, SNI, HTTP e DHCP. Vêm muitas vezes antes do
    /// primeiro pacote do host, então ficam à parte até o fim.
    nomes: HashMap<IpAddr, BTreeSet<String>>,

    dns: Vec<EventoDns>,
    dns_pendente: HashMap<(u32, u16), usize>,
    total_dns: u64,
    http: Vec<EventoHttp>,
    http_pendente: HashMap<u32, VecDeque<usize>>,
    total_http: u64,
    tls: Vec<EventoTls>,
    tls_por_fluxo: HashMap<u32, usize>,
    /// Começo remontado de cada direção de fluxo TLS ainda sem handshake lido.
    remontagens: HashMap<(u32, bool), Direcao>,
    /// Pedido HTTP cujo cabeçalho ainda não terminou (só o lado do cliente).
    http_partido: HashMap<u32, Direcao>,
    total_tls: u64,
    dhcp: Vec<EventoDhcp>,
    total_dhcp: u64,
    eventos_ignorados: bool,
}

impl Estado {
    fn pacote(&mut self, p: PacoteBruto<'_>) {
        let ts = p.ts_us;
        let tam = p.tamanho_original as u64;
        self.pacotes += 1;
        self.bytes += tam;
        self.inicio = Some(self.inicio.map_or(ts, |i| i.min(ts)));
        self.fim = self.fim.max(ts);

        let Some(d) = dec::decodificar(p.enlace, p.dados) else {
            self.nao_decodificados += 1;
            self.contar("Outro", tam);
            return;
        };

        match d.rede {
            Rede::Outra => self.contar("Outro", tam),
            Rede::Arp(a) => {
                self.contar("ARP", tam);
                if !a.ip_remetente.is_unspecified() {
                    if let Some(h) = self.host(IpAddr::V4(a.ip_remetente), ts) {
                        h.mac.get_or_insert_with(|| mac_texto(&a.mac_remetente));
                    }
                }
            }
            Rede::Ip(ip) => {
                let nome = match ip.transporte {
                    Transporte::Tcp { .. } => "TCP",
                    Transporte::Udp { .. } => "UDP",
                    Transporte::Icmp { v6: false, .. } => "ICMP",
                    Transporte::Icmp { v6: true, .. } => "ICMPv6",
                    Transporte::Fragmento { .. } => "IP fragmentado",
                    Transporte::Outro { .. } => "IP outro",
                };
                self.contar(nome, tam);

                if let Some(h) = self.host(ip.origem, ts) {
                    h.pacotes_enviados += 1;
                    h.bytes_enviados += tam;
                    // O MAC de um host externo é o do roteador: só vale para a rede local.
                    if h.escopo == "interno" {
                        if let Some(m) = d.mac_origem {
                            h.mac.get_or_insert_with(|| mac_texto(&m));
                        }
                    }
                }
                if let Some(h) = self.host(ip.destino, ts) {
                    h.pacotes_recebidos += 1;
                    h.bytes_recebidos += tam;
                }

                let (po, pd, flags) = match ip.transporte {
                    Transporte::Tcp { origem, destino, flags, .. } => (origem, destino, flags),
                    Transporte::Udp { origem, destino, .. } => (origem, destino, 0),
                    _ => (0, 0, 0),
                };
                let numero = ip.transporte.numero();
                let Some((id, ida)) = self.fluxo(numero, (ip.origem, po), (ip.destino, pd), flags, ts, tam, p.offset)
                else {
                    return;
                };
                if let Transporte::Tcp { seq, flags, .. } = ip.transporte {
                    if flags & TCP_SYN != 0 {
                        self.fluxos[id as usize].inicio_seq[usize::from(!ida)] = Some(seq.wrapping_add(1));
                    }
                }
                match ip.transporte {
                    Transporte::Udp { carga, .. } => self.udp(id, (ip.origem, po), (ip.destino, pd), carga, ts),
                    Transporte::Tcp { seq, carga, .. } if !carga.is_empty() => {
                        self.tcp(id, ida, (ip.origem, po), (ip.destino, pd), seq, carga, ts)
                    }
                    _ => {}
                }
            }
        }
    }

    fn contar(&mut self, nome: &'static str, tam: u64) {
        let c = self.protocolos.entry(nome).or_default();
        c.0 += 1;
        c.1 += tam;
    }

    fn host(&mut self, ip: IpAddr, ts: u64) -> Option<&mut Host> {
        // 0.0.0.0 e :: aparecem em DHCP e afins, mas não são uma máquina.
        if ip.is_unspecified() {
            return None;
        }
        if !self.hosts.contains_key(&ip) && self.hosts.len() >= MAX_HOSTS {
            self.hosts_ignorados += 1;
            return None;
        }
        let h = self.hosts.entry(ip).or_insert_with(|| Host {
            ip,
            escopo: dec::escopo(&ip),
            mac: None,
            nomes: BTreeSet::new(),
            pacotes_enviados: 0,
            pacotes_recebidos: 0,
            bytes_enviados: 0,
            bytes_recebidos: 0,
            fluxos_iniciados: 0,
            fluxos_recebidos: 0,
            primeiro_us: ts,
            ultimo_us: ts,
        });
        h.primeiro_us = h.primeiro_us.min(ts);
        h.ultimo_us = h.ultimo_us.max(ts);
        Some(h)
    }

    fn aprender_nome(&mut self, ip: IpAddr, nome: &str) {
        if nome.is_empty() || (!self.nomes.contains_key(&ip) && self.nomes.len() >= MAX_HOSTS) {
            return;
        }
        let nomes = self.nomes.entry(ip).or_default();
        if nomes.len() < MAX_NOMES_POR_HOST {
            nomes.insert(nome.to_ascii_lowercase());
        }
    }

    /// Encontra ou cria o fluxo do pacote. Devolve o id e se o pacote vai no
    /// sentido de quem abriu o fluxo.
    #[allow(clippy::too_many_arguments)]
    fn fluxo(
        &mut self,
        protocolo: u8,
        origem: (IpAddr, u16),
        destino: (IpAddr, u16),
        flags: u8,
        ts: u64,
        tam: u64,
        offset: u64,
    ) -> Option<(u32, bool)> {
        let (a, b) = if origem <= destino { (origem, destino) } else { (destino, origem) };
        let chave = Chave { protocolo, a, b };

        if let Some(&id) = self.chaves.get(&chave) {
            let fi = &mut self.fluxos[id as usize];
            let ida = (fi.f.origem, fi.f.porta_origem) == origem;
            let inatividade = if protocolo == 6 { INATIVIDADE_TCP_US } else { INATIVIDADE_UDP_US };
            let encerrado = (fi.flags_ida | fi.flags_volta) & (TCP_FIN | TCP_RST) != 0;
            let syn_novo = protocolo == 6 && flags & TCP_SYN != 0 && flags & TCP_ACK == 0 && encerrado;
            if !syn_novo && ts.saturating_sub(fi.f.fim_us) <= inatividade {
                atualizar(fi, ida, flags, ts, tam);
                return Some((id, ida));
            }
        }

        if self.fluxos.len() >= MAX_FLUXOS {
            self.fluxos_ignorados += 1;
            return None;
        }
        // Quem abriu é quem mandou o SYN. Se o primeiro pacote visto é o
        // SYN-ACK, a origem é o outro lado.
        let synack = protocolo == 6 && flags & (TCP_SYN | TCP_ACK) == (TCP_SYN | TCP_ACK);
        // Sem SYN (a captura pegou a conversa no meio), o primeiro pacote pode
        // ser do servidor: se ele sai de uma porta de serviço para uma porta
        // alta, o servidor é a origem dele.
        let meio = protocolo == 6 && flags & TCP_SYN == 0 && origem.1 < 1024 && destino.1 >= 1024;
        let ((o, po), (d, pd), ida) = if synack || meio { (destino, origem, false) } else { (origem, destino, true) };

        let id = self.fluxos.len() as u32;
        let mut fi = FluxoInterno {
            f: Fluxo {
                id,
                protocolo: nome_protocolo(protocolo),
                origem: o,
                porta_origem: po,
                destino: d,
                porta_destino: pd,
                inicio_us: ts,
                fim_us: ts,
                pacotes_ida: 0,
                pacotes_volta: 0,
                bytes_ida: 0,
                bytes_volta: 0,
                aplicacao: None,
                aplicacao_por_porta: false,
                conteudo_desconhecido: false,
                estado: "",
                offset,
            },
            flags_ida: 0,
            flags_volta: 0,
            tentativas: 0,
            inicio_seq: [None; 2],
            tls_lido: [false; 2],
            carga_desconhecida: 0,
        };
        atualizar(&mut fi, ida, flags, ts, tam);
        self.fluxos.push(fi);
        self.chaves.insert(chave, id);
        if let Some(h) = self.hosts.get_mut(&o) {
            h.fluxos_iniciados += 1;
        }
        if let Some(h) = self.hosts.get_mut(&d) {
            h.fluxos_recebidos += 1;
        }
        Some((id, ida))
    }

    fn marcar(&mut self, id: u32, aplicacao: &'static str) {
        self.fluxos[id as usize].f.aplicacao.get_or_insert(aplicacao);
    }

    fn udp(&mut self, id: u32, o: (IpAddr, u16), d: (IpAddr, u16), carga: &[u8], ts: u64) {
        let portas = [o.1, d.1];
        let servico = |p: u16| portas.contains(&p);
        if servico(53) || servico(5353) || servico(5355) {
            if let Some(m) = dns::ler(carga) {
                let nome = if servico(5353) { "mDNS" } else if servico(5355) { "LLMNR" } else { "DNS" };
                self.marcar(id, nome);
                self.evento_dns(id, o.0, d.0, m, ts);
            } else if !carga.is_empty() {
                self.fluxos[id as usize].carga_desconhecida += carga.len() as u64;
            }
        } else if servico(67) && servico(68) {
            if let Some(m) = dhcp::ler(carga) {
                self.marcar(id, "DHCP");
                self.evento_dhcp(m, ts);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn tcp(&mut self, id: u32, ida: bool, o: (IpAddr, u16), d: (IpAddr, u16), seq: u32, carga: &[u8], ts: u64) {
        let fi = &mut self.fluxos[id as usize];
        let (aplicacao, porta_servidor) = (fi.f.aplicacao, fi.f.porta_destino);
        match aplicacao {
            // Conexões persistentes levam várias requisições: o teste de
            // prefixo é barato e roda em todo segmento.
            Some("HTTP") => {
                if ida && self.http_partido.contains_key(&id) {
                    self.http_continua(id, o.0, d.0, porta_servidor, seq, carga, ts);
                } else if http::parece_http(carga) {
                    self.http_inicio(id, ida, o.0, d.0, porta_servidor, seq, carga, ts);
                }
                return;
            }
            // Os segmentos seguintes do handshake não começam com 0x16: vão
            // para a remontagem até o handshake ser lido.
            Some("TLS") => {
                self.tls_segmento(id, ida, o, d, seq, carga, ts);
                return;
            }
            Some(_) => return,
            None if fi.tentativas >= TENTATIVAS_APLICACAO => return,
            None => {
                fi.tentativas += 1;
                // Se nenhum leitor reconhecer abaixo, os bytes ficam contados.
                fi.carga_desconhecida += carga.len() as u64;
            }
        }

        if o.1 == 53 || d.1 == 53 {
            if let Some(m) = carga.get(2..).and_then(dns::ler) {
                self.marcar(id, "DNS");
                self.evento_dns(id, o.0, d.0, m, ts);
            }
        } else if tls::parece_tls(carga) {
            self.marcar(id, "TLS");
            self.tls_segmento(id, ida, o, d, seq, carga, ts);
        } else if tls::registro_tls(carga) {
            // Conversa TLS já em andamento quando a captura começou.
            self.marcar(id, "TLS");
        } else if http::parece_http(carga) {
            self.http_inicio(id, ida, o.0, d.0, porta_servidor, seq, carga, ts);
        }
    }

    /// Começo de uma mensagem HTTP. Se o pedido veio partido (o cabeçalho não
    /// cabe no segmento), guarda para remontar até o fim do cabeçalho.
    #[allow(clippy::too_many_arguments)]
    fn http_inicio(&mut self, id: u32, ida: bool, o: IpAddr, d: IpAddr, porta: u16, seq: u32, carga: &[u8], ts: u64) {
        self.marcar(id, "HTTP");
        let incompleto = ida && !carga.starts_with(b"HTTP/") && !carga.windows(4).any(|j| j == b"\r\n\r\n");
        if incompleto && self.http_partido.len() < MAX_REMONTAGENS {
            let mut r = Direcao::new(seq, REMONTAGEM_HTTP);
            r.segmento(seq, carga);
            self.http_partido.insert(id, r);
            return;
        }
        self.evento_http(id, o, d, porta, carga, ts);
    }

    #[allow(clippy::too_many_arguments)]
    fn http_continua(&mut self, id: u32, o: IpAddr, d: IpAddr, porta: u16, seq: u32, carga: &[u8], ts: u64) {
        let Some(r) = self.http_partido.get_mut(&id) else { return };
        r.segmento(seq, carga);
        if r.cheia() || r.dados().windows(4).any(|j| j == b"\r\n\r\n") {
            if let Some(r) = self.http_partido.remove(&id) {
                self.evento_http(id, o, d, porta, &r.em_bytes(), ts);
            }
        }
    }

    fn cabe_evento(&mut self, quantos: usize) -> bool {
        if quantos >= MAX_EVENTOS {
            self.eventos_ignorados = true;
            return false;
        }
        true
    }

    fn evento_dns(&mut self, id: u32, o: IpAddr, d: IpAddr, m: dns::MensagemDns, ts: u64) {
        if !m.resposta {
            let Some(consulta) = m.consulta else { return };
            // Retransmissão da mesma consulta
            if self.dns_pendente.contains_key(&(id, m.id)) {
                return;
            }
            self.total_dns += 1;
            if !self.cabe_evento(self.dns.len()) {
                return;
            }
            self.dns_pendente.insert((id, m.id), self.dns.len());
            self.dns.push(EventoDns {
                ts_us: ts,
                fluxo: id,
                cliente: o,
                servidor: d,
                consulta,
                tipo: dns::nome_tipo(m.tipo),
                rcode: None,
                respostas: Vec::new(),
                resposta_us: None,
            });
            return;
        }

        let consulta = m.consulta.unwrap_or_default();
        for r in &m.respostas {
            if matches!(r.tipo, 1 | 28) {
                if let Ok(ip) = r.valor.parse() {
                    self.aprender_nome(ip, &consulta);
                }
            }
        }
        let respostas: Vec<String> = m.respostas.into_iter().map(|r| r.valor).collect();
        if let Some(i) = self.dns_pendente.remove(&(id, m.id)) {
            let e = &mut self.dns[i];
            e.rcode = Some(m.rcode);
            e.respostas = respostas;
            e.resposta_us = Some(ts);
        } else {
            // Resposta cuja consulta ficou fora da captura
            self.total_dns += 1;
            if !self.cabe_evento(self.dns.len()) {
                return;
            }
            self.dns.push(EventoDns {
                ts_us: ts,
                fluxo: id,
                cliente: d,
                servidor: o,
                consulta,
                tipo: dns::nome_tipo(m.tipo),
                rcode: Some(m.rcode),
                respostas,
                resposta_us: Some(ts),
            });
        }
    }

    fn evento_http(&mut self, id: u32, o: IpAddr, d: IpAddr, porta: u16, carga: &[u8], ts: u64) {
        match http::ler(carga) {
            Some(http::MensagemHttp::Requisicao { metodo, caminho, host, user_agent, autorizacao, senha_em_claro }) => {
                self.marcar(id, "HTTP");
                if let Some(h) = &host {
                    let sem_porta = if h.starts_with('[') { h.as_str() } else { h.split(':').next().unwrap_or(h) };
                    if sem_porta.parse::<IpAddr>().is_err() {
                        self.aprender_nome(d, sem_porta);
                    }
                }
                self.total_http += 1;
                if !self.cabe_evento(self.http.len()) {
                    return;
                }
                self.http_pendente.entry(id).or_default().push_back(self.http.len());
                self.http.push(EventoHttp {
                    ts_us: ts,
                    fluxo: id,
                    cliente: o,
                    servidor: d,
                    porta,
                    metodo,
                    host,
                    caminho,
                    user_agent,
                    autorizacao,
                    senha_em_claro,
                    status: None,
                    tipo_conteudo: None,
                    tamanho: None,
                    servidor_http: None,
                });
            }
            Some(http::MensagemHttp::Resposta { status, tipo_conteudo, tamanho, servidor }) => {
                self.marcar(id, "HTTP");
                let Some(i) = self.http_pendente.get_mut(&id).and_then(VecDeque::pop_front) else { return };
                let e = &mut self.http[i];
                e.status = Some(status);
                e.tipo_conteudo = tipo_conteudo;
                e.tamanho = tamanho;
                e.servidor_http = servidor;
            }
            None => {}
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn tls_segmento(&mut self, id: u32, ida: bool, o: (IpAddr, u16), d: (IpAddr, u16), seq: u32, carga: &[u8], ts: u64) {
        let lado = usize::from(!ida);
        if self.fluxos[id as usize].tls_lido[lado] {
            return;
        }
        let chave = (id, ida);
        let lido = |e: &mut Self| {
            e.remontagens.remove(&chave);
            e.fluxos[id as usize].tls_lido[lado] = true;
        };

        if !self.remontagens.contains_key(&chave) {
            let limite = if ida { REMONTAGEM_CLIENTE } else { REMONTAGEM_SERVIDOR };
            // Base: o SYN da direção, se estiver na captura e o segmento cair
            // na janela dele; senão, o primeiro segmento (captura começou no
            // meio, ou números de sequência que não seguem o SYN).
            let base = self.fluxos[id as usize].inicio_seq[lado]
                .filter(|isn| (seq.wrapping_sub(*isn) as usize) < limite)
                .unwrap_or(seq);
            // Caminho rápido, o mais comum: o handshake desta direção cabe
            // inteiro no primeiro segmento e não precisa de remontagem.
            if seq == base {
                let (msgs, acabou) = tls::mensagens(carga);
                if self.tls_mensagens(id, o, d, msgs, ts) || acabou {
                    lido(self);
                    return;
                }
            }
            if self.remontagens.len() >= MAX_REMONTAGENS {
                // Sem espaço para remontar: fica o que deu para ler do segmento.
                return;
            }
            self.remontagens.insert(chave, Direcao::new(base, limite));
        }

        let Some(r) = self.remontagens.get_mut(&chave) else { return };
        if !r.segmento(seq, carga) {
            return;
        }
        let cheia = r.cheia();
        let (msgs, acabou) = tls::mensagens(r.dados());
        if self.tls_mensagens(id, o, d, msgs, ts) || cheia || acabou {
            lido(self);
        }
    }

    /// Registra o que veio do handshake. Devolve se esta direção já deu o
    /// que tinha para dar (ClientHello, ou certificado, ou TLS 1.3).
    fn tls_mensagens(&mut self, id: u32, o: (IpAddr, u16), d: (IpAddr, u16), msgs: Vec<tls::Handshake>, ts: u64) -> bool {
        let mut lido = false;
        for m in msgs {
            match m {
                tls::Handshake::Cliente(h) => {
                    lido = true;
                    if self.tls_por_fluxo.contains_key(&id) {
                        continue;
                    }
                    if let Some(s) = &h.sni {
                        self.aprender_nome(d.0, s);
                    }
                    self.total_tls += 1;
                    if !self.cabe_evento(self.tls.len()) {
                        continue;
                    }
                    self.tls_por_fluxo.insert(id, self.tls.len());
                    let (ja3, ja4) = (h.ja3(), h.ja4());
                    self.tls.push(EventoTls {
                        ts_us: ts,
                        fluxo: id,
                        cliente: o.0,
                        servidor: d.0,
                        porta: d.1,
                        sni: h.sni,
                        alpn: h.alpn,
                        versao_oferecida: tls::nome_versao(h.versao),
                        versao: None,
                        cifra: None,
                        ja3: Some(ja3),
                        ja4: Some(ja4),
                        ja3s: None,
                        certificado: None,
                    });
                }
                tls::Handshake::Servidor(h) => {
                    // No TLS 1.3 o certificado vem cifrado: não há mais o que ler.
                    lido |= h.versao == 0x0304;
                    if let Some(&i) = self.tls_por_fluxo.get(&id) {
                        let e = &mut self.tls[i];
                        e.versao.get_or_insert_with(|| tls::nome_versao(h.versao));
                        e.cifra.get_or_insert_with(|| format!("0x{:04x}", h.cifra));
                        if e.ja3s.is_none() {
                            e.ja3s = Some(h.ja3s());
                        }
                    }
                }
                tls::Handshake::Certificado(der) => {
                    lido = true;
                    let Some(&i) = self.tls_por_fluxo.get(&id) else { continue };
                    if self.tls[i].certificado.is_some() {
                        continue;
                    }
                    if let Some(c) = x509::ler(&der) {
                        let servidor = self.tls[i].servidor;
                        for n in c.nomes.iter().take(4).filter(|n| !n.starts_with('*')) {
                            self.aprender_nome(servidor, n);
                        }
                        self.tls[i].certificado = Some(c);
                    }
                }
            }
        }
        lido
    }

    fn evento_dhcp(&mut self, m: dhcp::MensagemDhcp, ts: u64) {
        let ip = m.ip.map(IpAddr::V4);
        if let (Some(ip), Some(nome)) = (ip, &m.nome_host) {
            self.aprender_nome(ip, nome);
        }
        self.total_dhcp += 1;
        if !self.cabe_evento(self.dhcp.len()) {
            return;
        }
        self.dhcp.push(EventoDhcp {
            ts_us: ts,
            mac: mac_texto(&m.mac),
            tipo: m.tipo.map_or("?", dhcp::nome_tipo),
            nome_host: m.nome_host,
            ip,
        });
    }

    fn relatorio(mut self, leitor: &LeitorCaptura) -> Relatorio {
        let mut avisos = Vec::new();
        match leitor.erro() {
            Some(e) => avisos.push(Aviso { codigo: e.codigo, offset: Some(e.offset) }),
            None => {
                let (offset, sobra) = leitor.pendente();
                if sobra > 0 {
                    avisos.push(Aviso { codigo: "arquivo_truncado", offset: Some(offset) });
                }
            }
        }
        for (houve, codigo) in [
            (self.fluxos_ignorados > 0, "limite_fluxos"),
            (self.hosts_ignorados > 0, "limite_hosts"),
            (self.eventos_ignorados, "limite_eventos"),
        ] {
            if houve {
                avisos.push(Aviso { codigo, offset: None });
            }
        }

        let mut aplicacoes: HashMap<&'static str, Contagem> = HashMap::new();
        for fi in &mut self.fluxos {
            if fi.f.aplicacao.is_none() {
                let palpite = por_porta(fi.f.protocolo, fi.f.porta_destino).or(por_porta(fi.f.protocolo, fi.f.porta_origem));
                fi.f.aplicacao = palpite;
                fi.f.aplicacao_por_porta = palpite.is_some();
                // 64 bytes: menos que isso pode ser resto de handshake cortado.
                fi.f.conteudo_desconhecido = fi.carga_desconhecida >= 64;
            }
            fi.f.estado = estado(fi);
            let nome = fi.f.aplicacao.unwrap_or("Outro");
            let c = aplicacoes.entry(nome).or_insert_with(|| Contagem { nome: nome.into(), pacotes: 0, bytes: 0, fluxos: 0 });
            c.pacotes += fi.f.pacotes_ida + fi.f.pacotes_volta;
            c.bytes += fi.f.bytes_ida + fi.f.bytes_volta;
            c.fluxos += 1;
        }

        let total_fluxos = self.fluxos.len() as u64 + self.fluxos_ignorados;
        let mut fluxos: Vec<Fluxo> = self.fluxos.into_iter().map(|fi| fi.f).collect();

        // Detecção e história olham a captura inteira, antes de qualquer corte.
        let dados = deteccao::Dados { fluxos: &fluxos, dns: &self.dns, http: &self.http, tls: &self.tls, nomes: &self.nomes };
        let alertas = deteccao::detectar(&dados);
        let diagnosticos = crate::diagnostico::diagnosticar(&dados, &alertas);
        let historia = historia::montar(&historia::Contexto {
            alertas: &alertas,
            fluxos: &fluxos,
            tem_tls: self.total_tls > 0,
            tem_avisos: !avisos.is_empty(),
        });

        for (ip, nomes) in std::mem::take(&mut self.nomes) {
            if let Some(h) = self.hosts.get_mut(&ip) {
                h.nomes.extend(nomes.into_iter().take(MAX_NOMES_POR_HOST));
            }
        }

        // Os maiores fluxos vão para a interface, e os que são evidência de
        // algum alerta vão sempre, mesmo pequenos.
        let evidencias: HashSet<u32> = alertas.iter().flat_map(|a| a.fluxos.iter().copied()).collect();
        fluxos.sort_unstable_by_key(|f| Reverse(f.bytes_ida + f.bytes_volta));
        if fluxos.len() > SAIDA_FLUXOS {
            let resto = fluxos.split_off(SAIDA_FLUXOS);
            fluxos.extend(resto.into_iter().filter(|f| evidencias.contains(&f.id)));
        }

        let total_hosts = self.hosts.len() as u64 + self.hosts_ignorados;
        let mut hosts: Vec<Host> = self.hosts.into_values().collect();
        hosts.sort_unstable_by_key(|h| Reverse(h.bytes_enviados + h.bytes_recebidos));
        hosts.truncate(SAIDA_HOSTS);

        let mut protocolos: Vec<Contagem> = self
            .protocolos
            .into_iter()
            .map(|(nome, (pacotes, bytes))| Contagem { nome: nome.into(), pacotes, bytes, fluxos: 0 })
            .collect();
        protocolos.sort_unstable_by_key(|c| Reverse(c.bytes));
        let mut aplicacoes: Vec<Contagem> = aplicacoes.into_values().collect();
        aplicacoes.sort_unstable_by_key(|c| Reverse(c.bytes));

        let mut dns = self.dns;
        let mut http = self.http;
        let mut tls = self.tls;
        let mut dhcp = self.dhcp;
        dns.truncate(SAIDA_EVENTOS);
        http.truncate(SAIDA_EVENTOS);
        tls.truncate(SAIDA_EVENTOS);
        dhcp.truncate(SAIDA_EVENTOS);

        Relatorio {
            captura: ResumoCaptura {
                formato: leitor.formato(),
                enlaces: leitor.enlaces().iter().map(|&e| dec::nome_enlace(e)).collect(),
                inicio_us: self.inicio.unwrap_or(0),
                fim_us: self.fim,
                pacotes: self.pacotes,
                bytes: self.bytes,
                nao_decodificados: self.nao_decodificados,
                avisos,
            },
            protocolos,
            aplicacoes,
            hosts,
            total_hosts,
            fluxos,
            total_fluxos,
            dns,
            total_dns: self.total_dns,
            http,
            total_http: self.total_http,
            tls,
            total_tls: self.total_tls,
            dhcp,
            total_dhcp: self.total_dhcp,
            alertas,
            diagnosticos,
            historia,
        }
    }
}

fn atualizar(fi: &mut FluxoInterno, ida: bool, flags: u8, ts: u64, tam: u64) {
    fi.f.inicio_us = fi.f.inicio_us.min(ts);
    fi.f.fim_us = fi.f.fim_us.max(ts);
    if ida {
        fi.f.pacotes_ida += 1;
        fi.f.bytes_ida += tam;
        fi.flags_ida |= flags;
    } else {
        fi.f.pacotes_volta += 1;
        fi.f.bytes_volta += tam;
        fi.flags_volta |= flags;
    }
}

fn estado(fi: &FluxoInterno) -> &'static str {
    if fi.f.protocolo != "TCP" {
        return if fi.f.pacotes_volta > 0 { "com_resposta" } else { "sem_resposta" };
    }
    let syn = fi.flags_ida & TCP_SYN != 0;
    let synack = fi.flags_volta & (TCP_SYN | TCP_ACK) == (TCP_SYN | TCP_ACK);
    // SYN sem SYN-ACK visto: só é "sem resposta" se o outro lado não mandou
    // nada. Se mandou dados, o SYN-ACK apenas ficou fora da captura.
    if syn && !synack && (fi.flags_volta & TCP_RST != 0 || fi.f.pacotes_volta == 0) {
        if fi.flags_volta & TCP_RST != 0 { "recusada" } else { "sem_resposta" }
    } else if (fi.flags_ida | fi.flags_volta) & (TCP_FIN | TCP_RST) != 0 {
        "encerrada"
    } else if synack || syn {
        "aberta"
    } else {
        // O início da conexão ficou fora da captura.
        "em_andamento"
    }
}

fn nome_protocolo(n: u8) -> &'static str {
    match n {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        47 => "GRE",
        50 => "ESP",
        58 => "ICMPv6",
        132 => "SCTP",
        _ => "IP",
    }
}

/// Palpite pela porta, usado só quando o conteúdo não confirmou nada.
fn por_porta(protocolo: &str, porta: u16) -> Option<&'static str> {
    let nome = match (protocolo, porta) {
        ("TCP", 20 | 21) => "FTP",
        ("TCP", 22) => "SSH",
        ("TCP", 23) => "Telnet",
        ("TCP", 25 | 465 | 587) => "SMTP",
        ("TCP", 80 | 8000 | 8080) => "HTTP",
        ("TCP" | "UDP", 88) => "Kerberos",
        ("TCP", 110 | 995) => "POP3",
        ("TCP", 135) => "RPC",
        ("TCP", 139 | 445) => "SMB",
        ("TCP", 143 | 993) => "IMAP",
        ("TCP" | "UDP", 389) => "LDAP",
        ("TCP", 443 | 8443) => "TLS",
        ("TCP", 636) => "LDAPS",
        ("TCP", 1433) => "MSSQL",
        ("TCP", 3306) => "MySQL",
        ("TCP", 3389) => "RDP",
        ("TCP", 5432) => "PostgreSQL",
        ("TCP", 5985 | 5986) => "WinRM",
        ("TCP", 6379) => "Redis",
        ("TCP" | "UDP", 53) => "DNS",
        ("UDP", 67 | 68) => "DHCP",
        ("UDP", 69) => "TFTP",
        ("UDP", 123) => "NTP",
        ("UDP", 137 | 138) => "NetBIOS",
        ("UDP", 161 | 162) => "SNMP",
        ("UDP", 443) => "QUIC",
        ("UDP", 500 | 4500) => "IPsec",
        ("UDP", 514) => "Syslog",
        ("UDP", 1900) => "SSDP",
        ("UDP", 3478) => "STUN",
        ("UDP", 5353) => "mDNS",
        ("UDP", 5355) => "LLMNR",
        ("UDP", 51820) => "WireGuard",
        _ => return None,
    };
    Some(nome)
}
