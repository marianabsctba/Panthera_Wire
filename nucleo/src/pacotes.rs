//! Visão pacote a pacote: relê a captura e devolve os pacotes que passam no
//! filtro, com as camadas decodificadas campo a campo e os bytes. É a parte
//! "Wireshark" da ferramenta, feita só com o que o núcleo já sabe ler.
//!
//! Nomes de campos e a linha de informação seguem a convenção do Wireshark
//! (em inglês), que é a que analistas reconhecem em qualquer idioma.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::aplicacao::{dhcp, dns, http, tls};
use crate::bytes::{fatia, mac_texto, texto_limpo, u16be, u32be, u8_em};
use crate::captura::{ErroCaptura, LeitorCaptura, PacoteBruto};

#[derive(Deserialize, Default, Clone)]
pub struct Filtro {
    /// Um IP: o pacote passa se for origem ou destino. Dois IPs (um fluxo):
    /// precisa ter os dois.
    #[serde(default)]
    pub ips: Vec<IpAddr>,
    /// Uma porta, ou as duas portas de um fluxo.
    #[serde(default)]
    pub portas: Vec<u16>,
    /// TCP, UDP, ICMP, DNS, HTTP, TLS...: alguma camada com esse nome.
    #[serde(default)]
    pub protocolo: Option<String>,
    /// Texto procurado (sem diferenciar maiúsculas) na linha de informação,
    /// nos endereços e nos valores dos campos decodificados.
    #[serde(default)]
    pub texto: Option<String>,
    /// Quantos pacotes que passam no filtro pular (para paginar).
    #[serde(default)]
    pub pular: u64,
    pub limite: usize,
}

#[derive(Serialize)]
pub struct Campo {
    pub nome: String,
    pub valor: String,
}

#[derive(Serialize)]
pub struct Camada {
    pub nome: &'static str,
    pub campos: Vec<Campo>,
}

#[derive(Serialize)]
pub struct Pacote {
    /// Posição na captura, a partir de 1 (como no Wireshark).
    pub numero: u64,
    pub offset: u64,
    pub ts_us: u64,
    pub tamanho: u32,
    pub capturado: usize,
    pub origem: String,
    pub destino: String,
    pub protocolo: String,
    pub info: String,
    pub camadas: Vec<Camada>,
    /// Bytes em hexadecimal (até 4 KB).
    pub bytes: String,
}

#[derive(Serialize)]
pub struct Resultado {
    pub pacotes: Vec<Pacote>,
    /// Quantos passaram no filtro até onde a leitura foi.
    pub encontrados: u64,
    /// A leitura parou no limite: pode haver mais.
    pub tem_mais: bool,
    pub erro: Option<ErroCaptura>,
}

const MAX_BYTES: usize = 4096;
const MAX_LIMITE: usize = 5000;

pub struct ListaPacotes {
    leitor: LeitorCaptura,
    filtro: Filtro,
    numero: u64,
    encontrados: u64,
    pacotes: Vec<Pacote>,
    tem_mais: bool,
    erro: Option<ErroCaptura>,
}

impl ListaPacotes {
    pub fn new(mut filtro: Filtro) -> Self {
        filtro.limite = filtro.limite.clamp(1, MAX_LIMITE);
        Self { leitor: LeitorCaptura::new(), filtro, numero: 0, encontrados: 0, pacotes: Vec::new(), tem_mais: false, erro: None }
    }

    /// Processa um bloco. Devolve `false` quando já tem o que precisa e a
    /// leitura pode parar.
    pub fn alimentar(&mut self, dados: &[u8]) -> bool {
        if self.tem_mais {
            return false;
        }
        let ListaPacotes { leitor, filtro, numero, encontrados, pacotes, tem_mais, .. } = self;
        let r = leitor.alimentar(dados, |p| {
            *numero += 1;
            if *tem_mais {
                return;
            }
            let Some(pacote) = dissecar(*numero, &p) else { return };
            if !passa(filtro, &pacote) {
                return;
            }
            *encontrados += 1;
            if *encontrados <= filtro.pular {
                return;
            }
            if pacotes.len() >= filtro.limite {
                *tem_mais = true;
                return;
            }
            pacotes.push(pacote);
        });
        if let Err(e) = r {
            self.erro = Some(e);
            return false;
        }
        !self.tem_mais
    }

    pub fn finalizar(self) -> Resultado {
        Resultado { pacotes: self.pacotes, encontrados: self.encontrados, tem_mais: self.tem_mais, erro: self.erro }
    }
}

fn passa(f: &Filtro, p: &Pacote) -> bool {
    let ip_ok = match f.ips.as_slice() {
        [] => true,
        [ip] => p.origem == ip.to_string() || p.destino == ip.to_string(),
        [a, b, ..] => {
            let (a, b) = (a.to_string(), b.to_string());
            (p.origem == a && p.destino == b) || (p.origem == b && p.destino == a)
        }
    };
    if !ip_ok {
        return false;
    }
    if let Some(proto) = &f.protocolo {
        if !p.camadas.iter().any(|c| c.nome.eq_ignore_ascii_case(proto)) {
            return false;
        }
    }
    if let Some(texto) = f.texto.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
        let t = texto.to_lowercase();
        let tem = |s: &str| s.to_lowercase().contains(&t);
        let achou = tem(&p.info)
            || tem(&p.origem)
            || tem(&p.destino)
            || tem(&p.protocolo)
            || p.camadas.iter().any(|c| c.campos.iter().any(|x| tem(&x.valor)));
        if !achou {
            return false;
        }
    }
    if f.portas.is_empty() {
        return true;
    }
    let portas: Vec<u16> = p
        .camadas
        .iter()
        .filter(|c| c.nome == "TCP" || c.nome == "UDP")
        .flat_map(|c| c.campos.iter().take(2).filter_map(|x| x.valor.parse().ok()))
        .collect();
    f.portas.iter().all(|x| portas.contains(x))
}

fn campo(nome: &str, valor: impl ToString) -> Campo {
    Campo { nome: nome.into(), valor: valor.to_string() }
}

struct Montagem {
    camadas: Vec<Camada>,
    origem: String,
    destino: String,
    protocolo: String,
    info: String,
}

pub fn dissecar(numero: u64, p: &PacoteBruto<'_>) -> Option<Pacote> {
    let d = p.dados;
    let mut m = Montagem { camadas: Vec::new(), origem: String::new(), destino: String::new(), protocolo: String::new(), info: String::new() };

    let (tipo, l3) = match p.enlace {
        1 => {
            let destino = fatia(d, 0, 6)?;
            let origem = fatia(d, 6, 6)?;
            let mut tipo = u16be(d, 12)?;
            let mut i = 14;
            let mut campos = vec![
                campo("Destination", mac_texto(destino.try_into().ok()?)),
                campo("Source", mac_texto(origem.try_into().ok()?)),
            ];
            while matches!(tipo, 0x8100 | 0x88a8 | 0x9100) && i < 30 {
                campos.push(campo("VLAN", u16be(d, i)? & 0x0fff));
                tipo = u16be(d, i + 2)?;
                i += 4;
            }
            campos.push(campo("Type", format!("0x{tipo:04x}")));
            m.camadas.push(Camada { nome: "Ethernet", campos });
            m.origem = mac_texto(origem.try_into().ok()?);
            m.destino = mac_texto(destino.try_into().ok()?);
            m.protocolo = "Ethernet".into();
            (tipo, i)
        }
        113 => {
            m.camadas.push(Camada { nome: "Linux SLL", campos: vec![campo("Protocol", format!("0x{:04x}", u16be(d, 14)?))] });
            (u16be(d, 14)?, 16)
        }
        276 => {
            m.camadas.push(Camada { nome: "Linux SLL2", campos: vec![campo("Protocol", format!("0x{:04x}", u16be(d, 0)?))] });
            (u16be(d, 0)?, 20)
        }
        0 | 108 => {
            let b = fatia(d, 0, 4)?;
            let le = u32::from_le_bytes(b.try_into().ok()?);
            let fam = if p.enlace == 108 || le > 0xff { u32::from_be_bytes(b.try_into().ok()?) } else { le };
            m.camadas.push(Camada { nome: "Loopback", campos: vec![campo("Family", fam)] });
            (if fam == 2 { 0x0800 } else { 0x86dd }, 4)
        }
        12 | 14 | 101 | 228 | 229 => (if u8_em(d, 0)? >> 4 == 6 { 0x86dd } else { 0x0800 }, 0),
        n => {
            m.protocolo = format!("LINKTYPE {n}");
            (0, d.len())
        }
    };

    match tipo {
        0x0800 => ipv4(d, l3, &mut m),
        0x86dd => ipv6(d, l3, &mut m),
        0x0806 => arp(d, l3, &mut m),
        _ => None,
    };
    if m.info.is_empty() {
        m.info = m.protocolo.clone();
    }

    let bytes: String = d.iter().take(MAX_BYTES).map(|b| format!("{b:02x}")).collect();
    Some(Pacote {
        numero,
        offset: p.offset,
        ts_us: p.ts_us,
        tamanho: p.tamanho_original,
        capturado: d.len(),
        origem: m.origem,
        destino: m.destino,
        protocolo: m.protocolo,
        info: m.info,
        camadas: m.camadas,
        bytes,
    })
}

fn arp(d: &[u8], i: usize, m: &mut Montagem) -> Option<()> {
    let op = u16be(d, i + 6)?;
    let (sha, spa) = (fatia(d, i + 8, 6)?, Ipv4Addr::from(u32be(d, i + 14)?));
    let (tha, tpa) = (fatia(d, i + 18, 6)?, Ipv4Addr::from(u32be(d, i + 24)?));
    m.camadas.push(Camada {
        nome: "ARP",
        campos: vec![
            campo("Opcode", if op == 1 { "request (1)".into() } else if op == 2 { "reply (2)".into() } else { op.to_string() }),
            campo("Sender MAC", mac_texto(sha.try_into().ok()?)),
            campo("Sender IP", spa),
            campo("Target MAC", mac_texto(tha.try_into().ok()?)),
            campo("Target IP", tpa),
        ],
    });
    m.protocolo = "ARP".into();
    m.info = if op == 1 { format!("Who has {tpa}? Tell {spa}") } else { format!("{spa} is at {}", mac_texto(sha.try_into().ok()?)) };
    Some(())
}

fn ipv4(d: &[u8], i: usize, m: &mut Montagem) -> Option<()> {
    let v = u8_em(d, i)?;
    let cab = (v & 0x0f) as usize * 4;
    let total = u16be(d, i + 2)?;
    let frag = u16be(d, i + 6)?;
    let proto = u8_em(d, i + 9)?;
    let origem = Ipv4Addr::from(u32be(d, i + 12)?);
    let destino = Ipv4Addr::from(u32be(d, i + 16)?);
    let mut flags = Vec::new();
    if frag & 0x4000 != 0 {
        flags.push("DF");
    }
    if frag & 0x2000 != 0 {
        flags.push("MF");
    }
    m.camadas.push(Camada {
        nome: "IPv4",
        campos: vec![
            campo("Header length", format!("{cab} bytes")),
            campo("Total length", total),
            campo("Identification", format!("0x{:04x}", u16be(d, i + 4)?)),
            campo("Flags", if flags.is_empty() { "none".into() } else { flags.join(", ") }),
            campo("Fragment offset", (frag & 0x1fff) * 8),
            campo("TTL", u8_em(d, i + 8)?),
            campo("Protocol", proto),
            campo("Header checksum", format!("0x{:04x}", u16be(d, i + 10)?)),
            campo("Source", origem),
            campo("Destination", destino),
        ],
    });
    m.origem = origem.to_string();
    m.destino = destino.to_string();
    m.protocolo = "IPv4".into();
    let fim = (i + total as usize).min(d.len()).max(i + cab);
    if frag & 0x1fff != 0 {
        m.info = format!("Fragmented IP protocol (proto={proto}, off={})", (frag & 0x1fff) * 8);
        return Some(());
    }
    transporte(d.get(i + cab..fim)?, proto, m)
}

fn ipv6(d: &[u8], i: usize, m: &mut Montagem) -> Option<()> {
    let tam = u16be(d, i + 4)?;
    let mut proximo = u8_em(d, i + 6)?;
    let origem = Ipv6Addr::from(<[u8; 16]>::try_from(fatia(d, i + 8, 16)?).ok()?);
    let destino = Ipv6Addr::from(<[u8; 16]>::try_from(fatia(d, i + 24, 16)?).ok()?);
    m.camadas.push(Camada {
        nome: "IPv6",
        campos: vec![
            campo("Payload length", tam),
            campo("Next header", proximo),
            campo("Hop limit", u8_em(d, i + 7)?),
            campo("Source", origem),
            campo("Destination", destino),
        ],
    });
    m.origem = origem.to_string();
    m.destino = destino.to_string();
    m.protocolo = "IPv6".into();
    let mut p = i + 40;
    for _ in 0..8 {
        match proximo {
            0 | 43 | 60 => {
                let n = u8_em(d, p)?;
                p += (u8_em(d, p + 1)? as usize + 1) * 8;
                proximo = n;
            }
            44 => {
                let n = u8_em(d, p)?;
                if u16be(d, p + 2)? >> 3 != 0 {
                    m.info = "IPv6 fragment".into();
                    return Some(());
                }
                p += 8;
                proximo = n;
            }
            _ => break,
        }
    }
    let fim = (i + 40 + tam as usize).min(d.len());
    transporte(d.get(p..fim.max(p))?, proximo, m)
}

const FLAGS_TCP: [(u8, &str); 8] =
    [(0x80, "CWR"), (0x40, "ECE"), (0x20, "URG"), (0x10, "ACK"), (0x08, "PSH"), (0x04, "RST"), (0x02, "SYN"), (0x01, "FIN")];

fn transporte(c: &[u8], proto: u8, m: &mut Montagem) -> Option<()> {
    match proto {
        6 => {
            let (po, pd) = (u16be(c, 0)?, u16be(c, 2)?);
            let (seq, ack) = (u32be(c, 4)?, u32be(c, 8)?);
            let cab = (u8_em(c, 12)? >> 4) as usize * 4;
            let flags = u8_em(c, 13)?;
            let nomes: Vec<&str> = FLAGS_TCP.iter().filter(|(b, _)| flags & b != 0).map(|(_, n)| *n).rev().collect();
            let carga = c.get(cab.max(20)..).unwrap_or(&[]);
            m.camadas.push(Camada {
                nome: "TCP",
                campos: vec![
                    campo("Source port", po),
                    campo("Destination port", pd),
                    campo("Sequence number", seq),
                    campo("Acknowledgment number", ack),
                    campo("Header length", format!("{cab} bytes")),
                    campo("Flags", nomes.join(", ")),
                    campo("Window", u16be(c, 14)?),
                    campo("Checksum", format!("0x{:04x}", u16be(c, 16)?)),
                    campo("Payload length", carga.len()),
                ],
            });
            m.protocolo = "TCP".into();
            m.info = format!("{po} → {pd} [{}] Seq={seq} Ack={ack} Win={} Len={}", nomes.join(", "), u16be(c, 14)?, carga.len());
            if !carga.is_empty() {
                aplicacao_tcp(carga, po, pd, m);
            }
        }
        17 => {
            let (po, pd, tam) = (u16be(c, 0)?, u16be(c, 2)?, u16be(c, 4)?);
            let fim = (tam as usize).clamp(8, c.len().max(8)).min(c.len());
            let carga = c.get(8..fim).unwrap_or(&[]);
            m.camadas.push(Camada {
                nome: "UDP",
                campos: vec![
                    campo("Source port", po),
                    campo("Destination port", pd),
                    campo("Length", tam),
                    campo("Checksum", format!("0x{:04x}", u16be(c, 6)?)),
                ],
            });
            m.protocolo = "UDP".into();
            m.info = format!("{po} → {pd} Len={}", carga.len());
            aplicacao_udp(carga, po, pd, m);
        }
        1 | 58 => {
            let (tipo, codigo) = (u8_em(c, 0)?, u8_em(c, 1)?);
            let nome = if proto == 1 { "ICMP" } else { "ICMPv6" };
            let descricao = match (proto, tipo) {
                (1, 8) | (58, 128) => "Echo (ping) request",
                (1, 0) | (58, 129) => "Echo (ping) reply",
                (1, 3) | (58, 1) => "Destination unreachable",
                (1, 11) | (58, 3) => "Time exceeded",
                (58, 135) => "Neighbor Solicitation",
                (58, 136) => "Neighbor Advertisement",
                _ => "",
            };
            m.camadas.push(Camada { nome, campos: vec![campo("Type", tipo), campo("Code", codigo)] });
            m.protocolo = nome.into();
            m.info = if descricao.is_empty() { format!("Type {tipo}, code {codigo}") } else { descricao.into() };
        }
        n => {
            m.info = format!("IP protocol {n}");
        }
    }
    Some(())
}

fn aplicacao_udp(c: &[u8], po: u16, pd: u16, m: &mut Montagem) {
    let porta = |x: u16| po == x || pd == x;
    if porta(53) || porta(5353) || porta(5355) {
        if let Some(msg) = dns::ler(c) {
            camada_dns(msg, m);
        }
    } else if porta(67) && porta(68) {
        if let Some(msg) = dhcp::ler(c) {
            let tipo = msg.tipo.map_or("?", dhcp::nome_tipo);
            let mut campos = vec![campo("Message type", tipo), campo("Client MAC", mac_texto(&msg.mac))];
            if let Some(h) = &msg.nome_host {
                campos.push(campo("Host name", h));
            }
            if let Some(ip) = msg.ip {
                campos.push(campo("Requested IP", ip));
            }
            m.camadas.push(Camada { nome: "DHCP", campos });
            m.protocolo = "DHCP".into();
            m.info = format!("DHCP {tipo}");
        }
    }
}

fn camada_dns(msg: dns::MensagemDns, m: &mut Montagem) {
    let tipo = dns::nome_tipo(msg.tipo);
    let consulta = msg.consulta.clone().unwrap_or_default();
    let mut campos = vec![
        campo("Transaction ID", format!("0x{:04x}", msg.id)),
        campo("Response", msg.resposta),
        campo("Query", format!("{consulta} ({tipo})")),
    ];
    if msg.resposta {
        campos.push(campo("Reply code", msg.rcode));
        for r in &msg.respostas {
            campos.push(campo("Answer", format!("{} {}", dns::nome_tipo(r.tipo), r.valor)));
        }
    }
    m.camadas.push(Camada { nome: "DNS", campos });
    m.protocolo = "DNS".into();
    m.info = if msg.resposta {
        let r: Vec<&str> = msg.respostas.iter().take(3).map(|r| r.valor.as_str()).collect();
        let erro = if msg.rcode == 3 { " No such name" } else { "" };
        format!("Standard query response 0x{:04x} {tipo} {consulta}{erro} {}", msg.id, r.join(" "))
    } else {
        format!("Standard query 0x{:04x} {tipo} {consulta}", msg.id)
    };
}

fn aplicacao_tcp(c: &[u8], po: u16, pd: u16, m: &mut Montagem) {
    if po == 53 || pd == 53 {
        if let Some(msg) = c.get(2..).and_then(dns::ler) {
            camada_dns(msg, m);
        }
        return;
    }
    if tls::parece_tls(c) {
        let (msgs, _) = tls::mensagens(c);
        let mut campos = vec![
            campo("Content type", "Handshake (22)"),
            campo("Version", tls::nome_versao(u16be(c, 1).unwrap_or(0))),
            campo("Length", u16be(c, 3).unwrap_or(0)),
        ];
        let mut info = Vec::new();
        for h in msgs {
            match h {
                tls::Handshake::Cliente(h) => {
                    info.push(format!("Client Hello{}", h.sni.as_deref().map(|s| format!(" (SNI={s})")).unwrap_or_default()));
                    campos.push(campo("Handshake", "Client Hello"));
                    if let Some(s) = &h.sni {
                        campos.push(campo("Server name", s));
                    }
                    if !h.alpn.is_empty() {
                        campos.push(campo("ALPN", h.alpn.join(", ")));
                    }
                    campos.push(campo("Supported version", tls::nome_versao(h.versao)));
                    campos.push(campo("JA4", h.ja4()));
                    campos.push(campo("JA3", h.ja3()));
                }
                tls::Handshake::Servidor(h) => {
                    info.push("Server Hello".into());
                    campos.push(campo("Handshake", "Server Hello"));
                    campos.push(campo("Selected version", tls::nome_versao(h.versao)));
                    campos.push(campo("Cipher suite", format!("0x{:04x}", h.cifra)));
                    campos.push(campo("JA3S", h.ja3s()));
                }
                tls::Handshake::Certificado(_) => {
                    info.push("Certificate".into());
                    campos.push(campo("Handshake", "Certificate"));
                }
            }
        }
        m.camadas.push(Camada { nome: "TLS", campos });
        m.protocolo = "TLS".into();
        m.info = if info.is_empty() { "TLS handshake (continuation)".into() } else { info.join(", ") };
        return;
    }
    if matches!(c, [0x17, 0x03, ..]) {
        m.camadas.push(Camada { nome: "TLS", campos: vec![campo("Content type", "Application Data (23)"), campo("Length", u16be(c, 3).unwrap_or(0))] });
        m.protocolo = "TLS".into();
        m.info = "Application Data".into();
        return;
    }
    if http::parece_http(c) {
        let fim = c.windows(4).position(|j| j == b"\r\n\r\n").unwrap_or(c.len().min(4096));
        let mut linhas = c[..fim].split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
        let primeira = texto_limpo(linhas.next().unwrap_or(&[]), 512);
        let mut campos = vec![campo("Line", &primeira)];
        for l in linhas.take(40) {
            let Some(p) = l.iter().position(|&b| b == b':') else { continue };
            let nome = texto_limpo(&l[..p], 64);
            let mut valor = texto_limpo(&l[p + 1..], 512).trim().to_owned();
            // O valor de credenciais não aparece decodificado (está nos bytes).
            if nome.eq_ignore_ascii_case("authorization") || nome.eq_ignore_ascii_case("cookie") {
                valor = format!("{} ••••", valor.split_whitespace().next().unwrap_or(""));
            }
            campos.push(campo(&nome, valor));
        }
        m.camadas.push(Camada { nome: "HTTP", campos });
        m.protocolo = "HTTP".into();
        m.info = primeira;
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn filtro_por_fluxo_e_paginacao() {
        let arquivo = include_bytes!("../../amostras/exemplo.pcap");
        let filtro = Filtro {
            ips: vec!["10.0.0.5".parse().unwrap(), "203.0.113.50".parse().unwrap()],
            portas: vec![50002, 80],
            limite: 5,
            ..Default::default()
        };
        let mut l = ListaPacotes::new(filtro.clone());
        l.alimentar(arquivo);
        let r = l.finalizar();
        assert_eq!(r.pacotes.len(), 5);
        assert!(r.tem_mais);
        assert!(r.pacotes[0].info.contains("[SYN]"), "{}", r.pacotes[0].info);
        assert!(r.pacotes.iter().any(|p| p.info.starts_with("GET /patch/KB5031.exe")));
        assert!(r.pacotes.iter().all(|p| p.camadas.iter().any(|c| c.nome == "TCP")));

        let mut l = ListaPacotes::new(Filtro { pular: 5, ..filtro });
        l.alimentar(arquivo);
        let r = l.finalizar();
        assert_eq!(r.pacotes.len(), 2);
        assert!(!r.tem_mais);
    }

    #[test]
    fn busca_por_texto_e_protocolo() {
        let arquivo = include_bytes!("../../amostras/exemplo.pcap");
        let buscar = |texto: &str, protocolo: Option<&str>| {
            let mut l = ListaPacotes::new(Filtro {
                texto: Some(texto.into()),
                protocolo: protocolo.map(str::to_owned),
                limite: 100,
                ..Default::default()
            });
            l.alimentar(arquivo);
            l.finalizar().pacotes
        };
        // SNI dentro da camada TLS e nome nas respostas DNS.
        let tls = buscar("CDN-SYNC", Some("tls"));
        assert!(!tls.is_empty() && tls.iter().all(|p| p.protocolo == "TLS"));
        assert!(buscar("cdn-sync", Some("DNS")).iter().all(|p| p.protocolo == "DNS"));
        assert!(buscar("no such name", None).iter().any(|p| p.info.contains("qx7kz2v9lmw3.info")));
        assert!(buscar("isto não existe em lugar nenhum", None).is_empty());
    }

    #[test]
    fn camadas_dns_e_credencial_mascarada() {
        let arquivo = include_bytes!("../../amostras/exemplo.pcap");
        let mut l = ListaPacotes::new(Filtro { portas: vec![53], limite: 2, ..Default::default() });
        l.alimentar(arquivo);
        let r = l.finalizar();
        assert!(r.pacotes[0].info.starts_with("Standard query 0x1001 A update-cdn.xyz"), "{}", r.pacotes[0].info);
        assert!(r.pacotes[1].info.contains("203.0.113.50"));

        let mut l = ListaPacotes::new(Filtro { ips: vec!["10.0.0.40".parse().unwrap()], limite: 10, ..Default::default() });
        l.alimentar(arquivo);
        let http = l.finalizar().pacotes.into_iter().find(|p| p.protocolo == "HTTP").unwrap();
        let auth = http.camadas.iter().flat_map(|c| &c.campos).find(|c| c.nome == "Authorization").unwrap();
        assert_eq!(auth.valor, "Basic ••••");
    }
}
