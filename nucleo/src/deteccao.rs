//! Analisadores: olham fluxos e eventos da captura inteira (antes de qualquer
//! corte para a interface) e geram alertas com a evidência.
//!
//! Cada regra é deliberadamente simples e explicável: o alerta diz o que foi
//! visto e com quais números, para a pessoa poder discordar.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

use crate::decodificacao::escopo;
use crate::relatorio::{Alerta, EventoDns, EventoHttp, EventoTls, Fluxo};

pub struct Dados<'a> {
    pub fluxos: &'a [Fluxo],
    pub dns: &'a [EventoDns],
    pub http: &'a [EventoHttp],
    pub tls: &'a [EventoTls],
    pub nomes: &'a HashMap<IpAddr, BTreeSet<String>>,
}

/// O que cada regra detecta (ATT&CK), em que fase da história entra e qual
/// contramedida D3FEND ela própria implementa. A interface lê a mesma tabela
/// de `web/src/regras.json`; um teste garante que as duas não se separem.
pub struct Regra {
    pub regra: &'static str,
    pub tecnica: Option<&'static str>,
    pub fase: &'static str,
    /// Lido pela interface (regras.json), conferido no teste abaixo.
    #[allow(dead_code)]
    pub d3fend: &'static [&'static str],
}

pub const REGRAS: &[Regra] = &[
    Regra { regra: "beaconing", tecnica: Some("T1071"), fase: "comando_e_controle", d3fend: &["D3-PMAD"] },
    Regra { regra: "download_executavel", tecnica: Some("T1105"), fase: "entrega", d3fend: &["D3-APCA"] },
    Regra { regra: "dga", tecnica: Some("T1568.002"), fase: "comando_e_controle", d3fend: &["D3-DNSTA"] },
    Regra { regra: "tunel_dns", tecnica: Some("T1071.004"), fase: "exfiltracao", d3fend: &["D3-DNSTA"] },
    Regra { regra: "credencial_em_claro", tecnica: Some("T1552"), fase: "credenciais", d3fend: &["D3-APCA"] },
    Regra { regra: "varredura_portas", tecnica: Some("T1046"), fase: "descoberta", d3fend: &["D3-CAA"] },
    Regra { regra: "varredura_hosts", tecnica: Some("T1046"), fase: "descoberta", d3fend: &["D3-CAA"] },
    Regra {
        regra: "movimentacao_lateral",
        tecnica: Some("T1021"),
        fase: "movimentacao_lateral",
        d3fend: &["D3-ANAA", "D3-RTSD"],
    },
    Regra { regra: "exfiltracao_volume", tecnica: Some("T1041"), fase: "exfiltracao", d3fend: &["D3-PHDURA"] },
    Regra { regra: "tls_antigo", tecnica: None, fase: "higiene", d3fend: &["D3-PMAD"] },
    Regra { regra: "user_agent_suspeito", tecnica: Some("T1071.001"), fase: "comando_e_controle", d3fend: &["D3-PMAD"] },
    Regra { regra: "porta_incomum", tecnica: Some("T1571"), fase: "comando_e_controle", d3fend: &["D3-PMAD"] },
];

fn regra(nome: &str) -> &'static Regra {
    REGRAS.iter().find(|r| r.regra == nome).expect("toda regra usada precisa estar em REGRAS")
}

const MAX_EVIDENCIAS: usize = 200;
const MIB: u64 = 1024 * 1024;

/// Domínios de infraestrutura muito comum. Estar aqui só rebaixa a
/// severidade: o alerta continua aparecendo.
const CONHECIDOS: &[&str] = &[
    "microsoft.com", "windowsupdate.com", "windows.com", "windows.net", "msftncsi.com", "msftconnecttest.com",
    "live.com", "office.com", "office365.com", "office.net", "bing.com", "skype.com", "apple.com", "icloud.com",
    "mzstatic.com", "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "gvt1.com",
    "youtube.com", "ytimg.com", "mozilla.org", "mozilla.net", "firefox.com", "ubuntu.com", "canonical.com",
    "debian.org", "digicert.com", "letsencrypt.org", "sectigo.com", "globalsign.com", "adobe.com", "zoom.us",
    "whatsapp.net", "facebook.com", "fbcdn.net", "instagram.com", "dns.google", "cloudflare-dns.com",
];

pub fn conhecido(nome: &str) -> bool {
    let nome = nome.trim_end_matches('.').to_ascii_lowercase();
    CONHECIDOS.iter().any(|s| nome == *s || nome.ends_with(&format!(".{s}")))
}

fn interno(ip: &IpAddr) -> bool {
    escopo(ip) == "interno"
}

fn externo(ip: &IpAddr) -> bool {
    escopo(ip) == "externo"
}

impl Dados<'_> {
    fn nome(&self, ip: &IpAddr) -> Option<&str> {
        self.nomes.get(ip).and_then(|n| n.iter().next()).map(String::as_str)
    }

    fn nome_ou_ip(&self, ip: &IpAddr) -> String {
        self.nome(ip).map_or_else(|| ip.to_string(), str::to_owned)
    }
}

/// Agrupa evidências de um alerta enquanto as regras percorrem os dados.
struct Grupo {
    inicio: u64,
    fim: u64,
    fluxos: BTreeSet<u32>,
}

impl Default for Grupo {
    fn default() -> Self {
        Self { inicio: u64::MAX, fim: 0, fluxos: BTreeSet::new() }
    }
}

impl Grupo {
    fn somar(&mut self, ts: u64, fluxo: u32) {
        self.inicio = self.inicio.min(ts);
        self.fim = self.fim.max(ts);
        if self.fluxos.len() < MAX_EVIDENCIAS {
            self.fluxos.insert(fluxo);
        }
    }
}

struct Novo {
    regra: &'static str,
    severidade: &'static str,
    host: IpAddr,
    alvo: Option<String>,
    alvo_ip: Option<IpAddr>,
    parametros: Vec<(&'static str, String)>,
}

fn alerta(n: Novo, g: Grupo) -> Alerta {
    let info = regra(n.regra);
    Alerta {
        id: 0,
        regra: n.regra,
        severidade: n.severidade,
        fase: info.fase,
        tecnica: info.tecnica,
        inicio_us: if g.inicio == u64::MAX { 0 } else { g.inicio },
        fim_us: g.fim,
        host: n.host,
        alvo: n.alvo,
        alvo_ip: n.alvo_ip,
        parametros: n.parametros.into_iter().collect(),
        fluxos: g.fluxos.into_iter().collect(),
    }
}

pub fn detectar(d: &Dados) -> Vec<Alerta> {
    let mut a = Vec::new();
    beaconing(d, &mut a);
    download_executavel(d, &mut a);
    dga(d, &mut a);
    tunel_dns(d, &mut a);
    credencial_em_claro(d, &mut a);
    varredura(d, &mut a);
    movimentacao_lateral(d, &mut a);
    exfiltracao(d, &mut a);
    tls_antigo(d, &mut a);
    user_agent(d, &mut a);
    porta_incomum(d, &mut a);

    a.sort_by_key(|x| (x.inicio_us, x.regra, x.host));
    for (i, x) in a.iter_mut().enumerate() {
        x.id = i as u32;
    }
    a
}

fn mediana(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.total_cmp(b));
    let n = v.len();
    if n == 0 {
        0.0
    } else if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

/// Conexões novas para o mesmo destino em intervalo quase constante.
fn beaconing(d: &Dados, saida: &mut Vec<Alerta>) {
    let mut grupos: BTreeMap<(IpAddr, IpAddr, u16, &str), Vec<&Fluxo>> = BTreeMap::new();
    for f in d.fluxos {
        if interno(&f.origem) && externo(&f.destino) && (f.protocolo == "TCP" || f.protocolo == "UDP") {
            grupos.entry((f.origem, f.destino, f.porta_destino, f.protocolo)).or_default().push(f);
        }
    }
    for ((origem, destino, porta, protocolo), mut fs) in grupos {
        if fs.len() < 6 {
            continue;
        }
        fs.sort_by_key(|f| f.inicio_us);
        let mut intervalos: Vec<f64> =
            fs.windows(2).map(|w| w[1].inicio_us.saturating_sub(w[0].inicio_us) as f64 / 1e6).collect();
        let med = mediana(&mut intervalos);
        if med < 5.0 {
            continue;
        }
        let regulares = intervalos.iter().filter(|x| (*x - med).abs() <= 0.2 * med).count();
        if (regulares as f64) < 0.8 * intervalos.len() as f64 {
            continue;
        }
        let mut desvios: Vec<f64> = intervalos.iter().map(|x| (x - med).abs()).collect();
        let variacao = mediana(&mut desvios) / med * 100.0;

        let alvo = d.nome_ou_ip(&destino);
        let mut g = Grupo::default();
        for f in &fs {
            g.somar(f.inicio_us, f.id);
        }
        saida.push(alerta(
            Novo {
                regra: "beaconing",
                severidade: if conhecido(&alvo) { "baixa" } else { "alta" },
                host: origem,
                alvo: Some(alvo),
                alvo_ip: Some(destino),
                parametros: vec![
                    ("intervalo", format!("{med:.0}")),
                    ("conexoes", fs.len().to_string()),
                    ("variacao", format!("{variacao:.0}")),
                    ("porta", format!("{protocolo}/{porta}")),
                ],
            },
            g,
        ));
    }
}

const EXTENSOES_EXECUTAVEIS: &[&str] = &[
    ".exe", ".dll", ".scr", ".msi", ".ps1", ".bat", ".cmd", ".vbs", ".hta", ".jar", ".lnk", ".iso", ".img", ".cpl",
];
const TIPOS_EXECUTAVEIS: &[&str] = &[
    "application/x-msdownload",
    "application/x-dosexec",
    "application/x-msdos-program",
    "application/vnd.microsoft.portable-executable",
    "application/x-ms-installer",
    "application/x-msi",
    "application/hta",
    "application/java-archive",
];

fn download_executavel(d: &Dados, saida: &mut Vec<Alerta>) {
    let mut grupos: BTreeMap<(IpAddr, String), (Grupo, &EventoHttp)> = BTreeMap::new();
    for h in d.http {
        if !matches!(h.status, Some(200..=299)) {
            continue;
        }
        let caminho = h.caminho.split(['?', '#']).next().unwrap_or("").to_ascii_lowercase();
        let tipo = h.tipo_conteudo.as_deref().unwrap_or("").to_ascii_lowercase();
        let por_extensao = EXTENSOES_EXECUTAVEIS.iter().any(|e| caminho.ends_with(e));
        let por_tipo = TIPOS_EXECUTAVEIS.iter().any(|t| tipo.starts_with(t));
        if !por_extensao && !por_tipo {
            continue;
        }
        let host = h.host.clone().unwrap_or_else(|| d.nome_ou_ip(&h.servidor));
        let url: String = format!("{host}{}", h.caminho).chars().take(200).collect();
        let (g, _) = grupos.entry((h.cliente, url)).or_insert_with(|| (Grupo::default(), h));
        g.somar(h.ts_us, h.fluxo);
    }
    for ((cliente, url), (g, h)) in grupos {
        let host = h.host.clone().unwrap_or_else(|| h.servidor.to_string());
        let host_sem_porta = host.split(':').next().unwrap_or(&host).to_owned();
        let ip_direto = host_sem_porta.parse::<IpAddr>().is_ok();
        let mut parametros = vec![("url", url), ("ip_direto", ip_direto.to_string())];
        if let Some(t) = &h.tipo_conteudo {
            parametros.push(("tipo", t.chars().take(80).collect()));
        }
        if let Some(t) = h.tamanho {
            parametros.push(("tamanho", t.to_string()));
        }
        saida.push(alerta(
            Novo {
                regra: "download_executavel",
                severidade: if conhecido(&host_sem_porta) { "baixa" } else { "alta" },
                host: cliente,
                alvo: Some(host_sem_porta),
                alvo_ip: Some(h.servidor),
                parametros,
            },
            g,
        ));
    }
}

/// Muitos domínios inexistentes consultados pelo mesmo host: típico de
/// malware que gera nomes por algoritmo até achar o servidor ativo.
fn dga(d: &Dados, saida: &mut Vec<Alerta>) {
    let mut por_cliente: BTreeMap<IpAddr, (BTreeSet<&str>, Grupo)> = BTreeMap::new();
    for e in d.dns {
        if e.rcode == Some(3) {
            let (nomes, g) = por_cliente.entry(e.cliente).or_default();
            nomes.insert(&e.consulta);
            g.somar(e.ts_us, e.fluxo);
        }
    }
    for (cliente, (nomes, g)) in por_cliente {
        if nomes.len() < 15 {
            continue;
        }
        let exemplos: Vec<&str> = nomes.iter().take(3).copied().collect();
        saida.push(alerta(
            Novo {
                regra: "dga",
                severidade: "media",
                host: cliente,
                alvo: None,
                alvo_ip: None,
                parametros: vec![("quantidade", nomes.len().to_string()), ("exemplos", exemplos.join(", "))],
            },
            g,
        ));
    }
}

/// Domínio registrado (aproximado): os dois últimos rótulos, ou três quando
/// o penúltimo é um sufixo de segundo nível comum (com.br, co.uk...).
pub fn dominio_base(nome: &str) -> &str {
    let rotulos: Vec<&str> = nome.trim_end_matches('.').rsplitn(4, '.').collect();
    let n = if rotulos.len() >= 3
        && rotulos[0].len() == 2
        && matches!(rotulos[1], "com" | "net" | "org" | "gov" | "edu" | "co" | "ac")
    {
        3
    } else {
        2
    };
    let tamanho: usize = rotulos.iter().take(n).map(|r| r.len() + 1).sum::<usize>().saturating_sub(1);
    &nome[nome.len().saturating_sub(tamanho)..]
}

/// Dados escondidos em subdomínios: muitos nomes únicos e longos sob o mesmo
/// domínio, muitas vezes com consultas TXT.
fn tunel_dns(d: &Dados, saida: &mut Vec<Alerta>) {
    struct Acumulado<'a> {
        unicos: BTreeSet<&'a str>,
        consultas: u64,
        tamanho: u64,
        txt: u64,
        g: Grupo,
    }
    let mut grupos: BTreeMap<(IpAddr, &str), Acumulado> = BTreeMap::new();
    for e in d.dns {
        let base = dominio_base(&e.consulta);
        if base.len() == e.consulta.len() || conhecido(base) {
            continue;
        }
        let a = grupos.entry((e.cliente, base)).or_insert_with(|| Acumulado {
            unicos: BTreeSet::new(),
            consultas: 0,
            tamanho: 0,
            txt: 0,
            g: Grupo::default(),
        });
        a.unicos.insert(&e.consulta);
        a.consultas += 1;
        a.tamanho += e.consulta.len() as u64;
        a.txt += (e.tipo == "TXT") as u64;
        a.g.somar(e.ts_us, e.fluxo);
    }
    for ((cliente, base), a) in grupos {
        let media = a.tamanho / a.consultas.max(1);
        let longo = a.unicos.len() >= 30 && media >= 40;
        let txt = a.txt >= 30 && a.unicos.len() >= 10;
        if !longo && !txt {
            continue;
        }
        saida.push(alerta(
            Novo {
                regra: "tunel_dns",
                severidade: "alta",
                host: cliente,
                alvo: Some(base.to_owned()),
                alvo_ip: None,
                parametros: vec![
                    ("consultas", a.consultas.to_string()),
                    ("unicos", a.unicos.len().to_string()),
                    ("tamanho_medio", media.to_string()),
                    ("txt", a.txt.to_string()),
                ],
            },
            a.g,
        ));
    }
}

/// Senha que atravessou a rede sem cifra. O valor nunca é guardado: só o
/// fato de que existiu e onde.
fn credencial_em_claro(d: &Dados, saida: &mut Vec<Alerta>) {
    let mut grupos: BTreeMap<(IpAddr, IpAddr, &str), Grupo> = BTreeMap::new();
    for h in d.http {
        if h.autorizacao.as_deref().is_some_and(|e| e.eq_ignore_ascii_case("basic")) {
            grupos.entry((h.cliente, h.servidor, "HTTP Basic")).or_default().somar(h.ts_us, h.fluxo);
        }
    }
    for f in d.fluxos {
        let protocolo = match (f.protocolo, f.porta_destino) {
            ("TCP", 21) => "FTP",
            ("TCP", 23) => "Telnet",
            ("TCP", 110) => "POP3",
            ("TCP", 143) => "IMAP",
            _ => continue,
        };
        // Só conta se a conexão foi aceita e houve conversa.
        if f.pacotes_volta > 2 && matches!(f.estado, "aberta" | "encerrada" | "em_andamento") {
            grupos.entry((f.origem, f.destino, protocolo)).or_default().somar(f.inicio_us, f.id);
        }
    }
    for ((cliente, servidor, protocolo), g) in grupos {
        saida.push(alerta(
            Novo {
                regra: "credencial_em_claro",
                severidade: "media",
                host: cliente,
                alvo: Some(d.nome_ou_ip(&servidor)),
                alvo_ip: Some(servidor),
                parametros: vec![("protocolo", protocolo.into())],
            },
            g,
        ));
    }
}

/// Muitas tentativas de conexão sem resposta ou recusadas: varredura de
/// portas num host, ou da mesma porta em muitos hosts.
fn varredura(d: &Dados, saida: &mut Vec<Alerta>) {
    let mut portas: BTreeMap<(IpAddr, IpAddr), (BTreeSet<u16>, Grupo)> = BTreeMap::new();
    let mut hosts: BTreeMap<(IpAddr, u16), (BTreeSet<IpAddr>, Grupo)> = BTreeMap::new();
    for f in d.fluxos {
        if f.protocolo != "TCP" || !matches!(f.estado, "sem_resposta" | "recusada") {
            continue;
        }
        let (p, g) = portas.entry((f.origem, f.destino)).or_default();
        p.insert(f.porta_destino);
        g.somar(f.inicio_us, f.id);
        let (h, g) = hosts.entry((f.origem, f.porta_destino)).or_default();
        h.insert(f.destino);
        g.somar(f.inicio_us, f.id);
    }
    for ((origem, destino), (p, g)) in portas {
        if p.len() >= 15 {
            saida.push(alerta(
                Novo {
                    regra: "varredura_portas",
                    severidade: "media",
                    host: origem,
                    alvo: Some(d.nome_ou_ip(&destino)),
                    alvo_ip: Some(destino),
                    parametros: vec![
                        ("quantidade", p.len().to_string()),
                        ("faixa", format!("{}-{}", p.first().unwrap_or(&0), p.last().unwrap_or(&0))),
                    ],
                },
                g,
            ));
        }
    }
    for ((origem, porta), (h, g)) in hosts {
        if h.len() >= 15 {
            saida.push(alerta(
                Novo {
                    regra: "varredura_hosts",
                    severidade: "media",
                    host: origem,
                    alvo: None,
                    alvo_ip: None,
                    parametros: vec![("quantidade", h.len().to_string()), ("porta", porta.to_string())],
                },
                g,
            ));
        }
    }
}

/// Um host interno usando serviços de administração remota em vários outros.
fn movimentacao_lateral(d: &Dados, saida: &mut Vec<Alerta>) {
    let mut por_origem: BTreeMap<IpAddr, (BTreeSet<IpAddr>, BTreeSet<&str>, Grupo)> = BTreeMap::new();
    for f in d.fluxos {
        let Some(app) = f.aplicacao else { continue };
        if !matches!(app, "SMB" | "RDP" | "WinRM" | "RPC" | "SSH")
            || !interno(&f.origem)
            || !interno(&f.destino)
            || matches!(f.estado, "sem_resposta" | "recusada")
        {
            continue;
        }
        let (destinos, apps, g) = por_origem.entry(f.origem).or_default();
        destinos.insert(f.destino);
        apps.insert(app);
        g.somar(f.inicio_us, f.id);
    }
    for (origem, (destinos, apps, g)) in por_origem {
        if destinos.len() < 3 {
            continue;
        }
        let alvos: Vec<String> = destinos.iter().take(5).map(|ip| d.nome_ou_ip(ip)).collect();
        saida.push(alerta(
            Novo {
                regra: "movimentacao_lateral",
                severidade: "media",
                host: origem,
                alvo: None,
                alvo_ip: None,
                parametros: vec![
                    ("quantidade", destinos.len().to_string()),
                    ("protocolos", apps.into_iter().collect::<Vec<_>>().join(", ")),
                    ("alvos", alvos.join(", ")),
                ],
            },
            g,
        ));
    }
}

/// Volume grande saindo para um destino externo, muito maior do que voltou.
fn exfiltracao(d: &Dados, saida: &mut Vec<Alerta>) {
    let mut grupos: BTreeMap<(IpAddr, IpAddr), (u64, u64, Vec<&Fluxo>)> = BTreeMap::new();
    for f in d.fluxos {
        if interno(&f.origem) && externo(&f.destino) {
            let (ida, volta, fs) = grupos.entry((f.origem, f.destino)).or_default();
            *ida += f.bytes_ida;
            *volta += f.bytes_volta;
            fs.push(f);
        }
    }
    for ((origem, destino), (ida, volta, fs)) in grupos {
        if ida < 50 * MIB || ida < 5 * volta.max(1) {
            continue;
        }
        // Evidência são os fluxos que carregaram o volume, não as conexões
        // pequenas que por acaso foram ao mesmo destino.
        let mut g = Grupo::default();
        for f in fs.iter().filter(|f| f.bytes_ida >= ida / 20) {
            g.somar(f.inicio_us, f.id);
        }
        let alvo = d.nome_ou_ip(&destino);
        saida.push(alerta(
            Novo {
                regra: "exfiltracao_volume",
                severidade: if conhecido(&alvo) { "media" } else { "alta" },
                host: origem,
                alvo: Some(alvo),
                alvo_ip: Some(destino),
                parametros: vec![("enviados", ida.to_string()), ("recebidos", volta.to_string())],
            },
            g,
        ));
    }
}

fn tls_antigo(d: &Dados, saida: &mut Vec<Alerta>) {
    let mut grupos: BTreeMap<(IpAddr, IpAddr, &str), (Grupo, Option<&str>)> = BTreeMap::new();
    for t in d.tls {
        let Some(v) = t.versao.as_deref() else { continue };
        if matches!(v, "SSL 3.0" | "TLS 1.0" | "TLS 1.1") {
            let (g, _) = grupos.entry((t.cliente, t.servidor, v)).or_insert_with(|| (Grupo::default(), t.sni.as_deref()));
            g.somar(t.ts_us, t.fluxo);
        }
    }
    for ((cliente, servidor, versao), (g, sni)) in grupos {
        saida.push(alerta(
            Novo {
                regra: "tls_antigo",
                severidade: "baixa",
                host: cliente,
                alvo: Some(sni.map_or_else(|| d.nome_ou_ip(&servidor), str::to_owned)),
                alvo_ip: Some(servidor),
                parametros: vec![("versao", versao.into())],
            },
            g,
        ));
    }
}

const FERRAMENTAS: &[&str] = &[
    "curl/", "wget/", "python-requests", "python-urllib", "powershell", "winhttp", "go-http-client",
    "libwww-perl", "nmap", "sqlmap", "nikto", "certutil", "bitsadmin", "msie 6.0", "msie 5.",
];

fn user_agent(d: &Dados, saida: &mut Vec<Alerta>) {
    let mut grupos: BTreeMap<(IpAddr, String), (Grupo, &'static str)> = BTreeMap::new();
    for h in d.http {
        let ua = h.user_agent.as_deref().unwrap_or("").trim();
        let minusculo = ua.to_ascii_lowercase();
        let marca = if ua.is_empty() {
            "vazio"
        } else if let Some(f) = FERRAMENTAS.iter().find(|f| minusculo.contains(*f)) {
            f
        } else {
            continue;
        };
        let (g, _) = grupos.entry((h.cliente, ua.chars().take(120).collect())).or_insert_with(|| (Grupo::default(), marca));
        g.somar(h.ts_us, h.fluxo);
    }
    for ((cliente, ua), (g, marca)) in grupos {
        let grave = matches!(marca, "powershell" | "certutil" | "bitsadmin");
        saida.push(alerta(
            Novo {
                regra: "user_agent_suspeito",
                severidade: if grave { "media" } else { "baixa" },
                host: cliente,
                alvo: None,
                alvo_ip: None,
                parametros: vec![("user_agent", ua), ("marca", marca.trim_end_matches('/').into())],
            },
            g,
        ));
    }
}

/// HTTP ou TLS confirmados pelo conteúdo, para fora, numa porta fora do comum.
fn porta_incomum(d: &Dados, saida: &mut Vec<Alerta>) {
    let mut grupos: BTreeMap<(IpAddr, IpAddr, u16, &str), Grupo> = BTreeMap::new();
    for f in d.fluxos {
        let (Some(app), false) = (f.aplicacao, f.aplicacao_por_porta) else { continue };
        let comum = match app {
            "HTTP" => matches!(f.porta_destino, 80 | 8080 | 8000 | 8008 | 8888 | 3128 | 591),
            "TLS" => matches!(
                f.porta_destino,
                443 | 8443 | 993 | 995 | 465 | 587 | 636 | 853 | 989 | 990 | 3269 | 5061 | 5223 | 4443 | 9443
            ),
            _ => true,
        };
        if !comum && externo(&f.destino) {
            grupos.entry((f.origem, f.destino, f.porta_destino, app)).or_default().somar(f.inicio_us, f.id);
        }
    }
    for ((origem, destino, porta, app), g) in grupos {
        saida.push(alerta(
            Novo {
                regra: "porta_incomum",
                severidade: "baixa",
                host: origem,
                alvo: Some(d.nome_ou_ip(&destino)),
                alvo_ip: Some(destino),
                parametros: vec![("protocolo", app.into()), ("porta", porta.to_string())],
            },
            g,
        ));
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    /// A interface lê a tabela de regras de um JSON: os dois precisam bater.
    #[test]
    fn regras_sincronizadas_com_a_interface() {
        let json: Vec<serde_json::Value> = serde_json::from_str(include_str!("../../web/src/regras.json")).unwrap();
        assert_eq!(json.len(), REGRAS.len());
        for (j, r) in json.iter().zip(REGRAS) {
            assert_eq!(j["regra"], r.regra);
            assert_eq!(j["tecnica"].as_str(), r.tecnica, "{}", r.regra);
            assert_eq!(j["fase"], r.fase, "{}", r.regra);
            let d3: Vec<&str> = j["d3fend"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
            assert_eq!(d3, r.d3fend, "{}", r.regra);
        }
    }

    /// Toda técnica e contramedida citada existe nos dados oficiais da MITRE.
    #[test]
    fn ids_existem_na_mitre() {
        let m: serde_json::Value = serde_json::from_str(include_str!("../../web/src/mitre.json")).unwrap();
        let tecnicas: Vec<&str> = m["tecnicas"].as_array().unwrap().iter().map(|t| t["id"].as_str().unwrap()).collect();
        for r in REGRAS {
            if let Some(t) = r.tecnica {
                assert!(tecnicas.contains(&t), "{t} não existe no ATT&CK");
            }
            for d in r.d3fend {
                assert!(m["defesas"].get(d).is_some(), "{d} não existe no D3FEND");
            }
        }
    }

    #[test]
    fn dominios_base() {
        assert_eq!(dominio_base("a.b.exfil-dns.net"), "exfil-dns.net");
        assert_eq!(dominio_base("www.banco.com.br"), "banco.com.br");
        assert_eq!(dominio_base("localhost"), "localhost");
        assert_eq!(dominio_base("x.y.co.uk"), "y.co.uk");
    }

    #[test]
    fn conhecidos_por_sufixo() {
        assert!(conhecido("download.windowsupdate.com"));
        assert!(conhecido("google.com."));
        assert!(!conhecido("notgoogle.com"));
        assert!(!conhecido("cdn-sync.top"));
    }
}
