//! Decodificação das camadas de enlace, rede e transporte.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::bytes::{fatia, mac, u16be, u32be, u8_em};

pub struct Decodificado<'a> {
    pub mac_origem: Option<[u8; 6]>,
    pub rede: Rede<'a>,
}

pub enum Rede<'a> {
    Ip(Ip<'a>),
    Arp(Arp),
    Outra,
}

pub struct Ip<'a> {
    pub origem: IpAddr,
    pub destino: IpAddr,
    pub transporte: Transporte<'a>,
}

#[derive(Clone, Copy)]
pub enum Transporte<'a> {
    Tcp { origem: u16, destino: u16, flags: u8, carga: &'a [u8] },
    Udp { origem: u16, destino: u16, carga: &'a [u8] },
    Icmp { v6: bool },
    /// Fragmento IP que não é o primeiro: não carrega cabeçalho de transporte.
    Fragmento { protocolo: u8 },
    Outro { protocolo: u8 },
}

impl Transporte<'_> {
    pub fn numero(&self) -> u8 {
        match self {
            Transporte::Tcp { .. } => 6,
            Transporte::Udp { .. } => 17,
            Transporte::Icmp { v6: false, .. } => 1,
            Transporte::Icmp { v6: true, .. } => 58,
            Transporte::Fragmento { protocolo } | Transporte::Outro { protocolo } => *protocolo,
        }
    }
}

pub struct Arp {
    pub mac_remetente: [u8; 6],
    pub ip_remetente: Ipv4Addr,
}

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

/// Nome legível dos tipos de enlace que sabemos decodificar.
pub fn nome_enlace(enlace: u16) -> String {
    match enlace {
        0 => "BSD loopback".into(),
        1 => "Ethernet".into(),
        12 | 14 | 101 => "IP".into(),
        108 => "OpenBSD loopback".into(),
        113 => "Linux cooked (SLL)".into(),
        228 => "IPv4".into(),
        229 => "IPv6".into(),
        276 => "Linux cooked v2 (SLL2)".into(),
        n => format!("LINKTYPE {n}"),
    }
}

pub fn decodificar(enlace: u16, d: &[u8]) -> Option<Decodificado<'_>> {
    match enlace {
        1 => ethernet(d),
        113 => sem_mac(u16be(d, 14)?, d.get(16..)?),
        276 => sem_mac(u16be(d, 0)?, d.get(20..)?),
        0 => {
            // Família no byte order da máquina que capturou: aceita os dois.
            let bruto = fatia(d, 0, 4)?;
            let le = u32::from_le_bytes(bruto.try_into().ok()?);
            let familia = if le <= 0xff { le } else { u32::from_be_bytes(bruto.try_into().ok()?) };
            ip_por_familia(familia, d.get(4..)?)
        }
        108 => ip_por_familia(u32be(d, 0)?, d.get(4..)?),
        12 | 14 | 101 => ip_cru(d),
        228 => sem_mac(0x0800, d),
        229 => sem_mac(0x86dd, d),
        _ => None,
    }
}

fn ethernet(d: &[u8]) -> Option<Decodificado<'_>> {
    let origem = mac(d, 6)?;
    let mut tipo = u16be(d, 12)?;
    let mut i = 14;
    let mut etiquetas = 0;
    // 802.1Q, 802.1ad (QinQ) e o QinQ antigo
    while matches!(tipo, 0x8100 | 0x88a8 | 0x9100) && etiquetas < 4 {
        tipo = u16be(d, i + 2)?;
        i += 4;
        etiquetas += 1;
    }
    Some(Decodificado { mac_origem: Some(origem), rede: rede(tipo, d.get(i..)?) })
}

fn sem_mac(tipo: u16, carga: &[u8]) -> Option<Decodificado<'_>> {
    Some(Decodificado { mac_origem: None, rede: rede(tipo, carga) })
}

fn ip_por_familia(familia: u32, carga: &[u8]) -> Option<Decodificado<'_>> {
    match familia {
        2 => sem_mac(0x0800, carga),
        24 | 28 | 30 => sem_mac(0x86dd, carga),
        _ => None,
    }
}

fn ip_cru(d: &[u8]) -> Option<Decodificado<'_>> {
    match u8_em(d, 0)? >> 4 {
        4 => sem_mac(0x0800, d),
        6 => sem_mac(0x86dd, d),
        _ => None,
    }
}

fn rede(tipo: u16, c: &[u8]) -> Rede<'_> {
    let r = match tipo {
        0x0800 => ipv4(c).map(Rede::Ip),
        0x86dd => ipv6(c).map(Rede::Ip),
        0x0806 => arp(c).map(Rede::Arp),
        _ => None,
    };
    r.unwrap_or(Rede::Outra)
}

fn ipv4(c: &[u8]) -> Option<Ip<'_>> {
    let v = u8_em(c, 0)?;
    if v >> 4 != 4 {
        return None;
    }
    let cabecalho = (v & 0x0f) as usize * 4;
    if cabecalho < 20 {
        return None;
    }
    // Limita ao tamanho declarado: Ethernet completa quadros curtos com zeros.
    let total = u16be(c, 2)? as usize;
    let fim = if total >= cabecalho && total <= c.len() { total } else { c.len() };
    let deslocamento = u16be(c, 6)? & 0x1fff;
    let protocolo = u8_em(c, 9)?;
    let origem = IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(fatia(c, 12, 4)?).ok()?));
    let destino = IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(fatia(c, 16, 4)?).ok()?));
    let carga = c.get(cabecalho..fim)?;
    let transporte =
        if deslocamento != 0 { Transporte::Fragmento { protocolo } } else { transporte(protocolo, carga) };
    Some(Ip { origem, destino, transporte })
}

fn ipv6(c: &[u8]) -> Option<Ip<'_>> {
    if u8_em(c, 0)? >> 4 != 6 {
        return None;
    }
    let tamanho = u16be(c, 4)? as usize;
    let fim = if tamanho == 0 { c.len() } else { (40 + tamanho).min(c.len()) };
    let origem = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(fatia(c, 8, 16)?).ok()?));
    let destino = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(fatia(c, 24, 16)?).ok()?));

    let mut proximo = u8_em(c, 6)?;
    let mut i = 40;
    for _ in 0..8 {
        match proximo {
            // hop-by-hop, roteamento, opções de destino
            0 | 43 | 60 => {
                let n = u8_em(c, i)?;
                i += (u8_em(c, i + 1)? as usize + 1) * 8;
                proximo = n;
            }
            44 => {
                let n = u8_em(c, i)?;
                if u16be(c, i + 2)? >> 3 != 0 {
                    return Some(Ip { origem, destino, transporte: Transporte::Fragmento { protocolo: n } });
                }
                i += 8;
                proximo = n;
            }
            // Authentication Header
            51 => {
                let n = u8_em(c, i)?;
                i += (u8_em(c, i + 1)? as usize + 2) * 4;
                proximo = n;
            }
            _ => break,
        }
    }
    let transporte = match c.get(i..fim) {
        Some(carga) => transporte(proximo, carga),
        None => Transporte::Outro { protocolo: proximo },
    };
    Some(Ip { origem, destino, transporte })
}

fn transporte(protocolo: u8, c: &[u8]) -> Transporte<'_> {
    let t = match protocolo {
        6 => (|| {
            let cabecalho = (u8_em(c, 12)? >> 4) as usize * 4;
            Some(Transporte::Tcp {
                origem: u16be(c, 0)?,
                destino: u16be(c, 2)?,
                flags: u8_em(c, 13)?,
                carga: c.get(cabecalho.max(20)..).unwrap_or(&[]),
            })
        })(),
        17 => (|| {
            let tamanho = u16be(c, 4)? as usize;
            let fim = if (8..=c.len()).contains(&tamanho) { tamanho } else { c.len() };
            Some(Transporte::Udp { origem: u16be(c, 0)?, destino: u16be(c, 2)?, carga: c.get(8..fim)? })
        })(),
        1 | 58 => match (u8_em(c, 0), u8_em(c, 1)) {
            (Some(_), Some(_)) => Some(Transporte::Icmp { v6: protocolo == 58 }),
            _ => None,
        },
        _ => None,
    };
    t.unwrap_or(Transporte::Outro { protocolo })
}

fn arp(c: &[u8]) -> Option<Arp> {
    // Só Ethernet + IPv4, que é o que existe na prática.
    if u16be(c, 2)? != 0x0800 || u8_em(c, 4)? != 6 || u8_em(c, 5)? != 4 {
        return None;
    }
    Some(Arp {
        mac_remetente: mac(c, 8)?,
        ip_remetente: Ipv4Addr::from(<[u8; 4]>::try_from(fatia(c, 14, 4)?).ok()?),
    })
}

/// Escopo de um endereço, para separar a rede observada do resto do mundo.
///
/// `reservado` são as faixas de documentação e testes (TEST-NET, 198.18/15,
/// 2001:db8::/32). Não existem na internet, então aparecem em laboratórios e
/// capturas sintéticas, e as regras as tratam como podendo estar dos dois lados.
pub fn escopo(ip: &IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            if v.is_multicast() || v.is_broadcast() || o[3] == 255 && v.is_private() {
                "multicast"
            } else if v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || (o[0] == 100 && (64..128).contains(&o[1]))
            {
                "interno"
            } else if matches!(o, [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]) || (o[0] == 198 && (o[1] & 0xfe) == 18) {
                "reservado"
            } else {
                "externo"
            }
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            if v.is_multicast() {
                "multicast"
            } else if v.is_loopback() || v.is_unspecified() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80 {
                "interno"
            } else if s[0] == 0x2001 && s[1] == 0x0db8 {
                "reservado"
            } else {
                "externo"
            }
        }
    }
}

/// Pode ser a rede observada (o lado de dentro).
pub fn lado_de_dentro(ip: &IpAddr) -> bool {
    matches!(escopo(ip), "interno" | "reservado")
}

/// Pode ser um destino lá fora.
pub fn lado_de_fora(ip: &IpAddr) -> bool {
    matches!(escopo(ip), "externo" | "reservado")
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn ethernet_vlan_ipv4_udp() {
        let mut q = vec![0u8; 12];
        q.extend_from_slice(&[0x81, 0x00, 0x00, 0x0a, 0x08, 0x00]);
        q.extend_from_slice(&[0x45, 0, 0, 32, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 8, 8, 8, 8]);
        q.extend_from_slice(&[0x30, 0x39, 0, 53, 0, 12, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd]);
        q.extend_from_slice(&[0; 6]); // enchimento do quadro
        let d = decodificar(1, &q).unwrap();
        let Rede::Ip(ip) = d.rede else { panic!() };
        assert_eq!(ip.destino.to_string(), "8.8.8.8");
        let Transporte::Udp { destino, carga, .. } = ip.transporte else { panic!() };
        assert_eq!(destino, 53);
        assert_eq!(carga, &[0xaa, 0xbb, 0xcc, 0xdd]);
    }

    #[test]
    fn lixo_nao_derruba() {
        for tamanho in 0..80 {
            let lixo: Vec<u8> = (0..tamanho).map(|i| (i * 37 + 11) as u8).collect();
            for enlace in [0, 1, 101, 113, 228, 229, 276] {
                let _ = decodificar(enlace, &lixo);
            }
        }
    }

    #[test]
    fn escopos() {
        assert_eq!(escopo(&"192.168.0.10".parse().unwrap()), "interno");
        assert_eq!(escopo(&"100.70.1.1".parse().unwrap()), "interno");
        assert_eq!(escopo(&"8.8.8.8".parse().unwrap()), "externo");
        assert_eq!(escopo(&"198.51.100.20".parse().unwrap()), "reservado");
        assert_eq!(escopo(&"198.19.0.1".parse().unwrap()), "reservado");
        assert_eq!(escopo(&"2001:db8::1".parse().unwrap()), "reservado");
        assert_eq!(escopo(&"224.0.0.251".parse().unwrap()), "multicast");
        assert_eq!(escopo(&"fe80::1".parse().unwrap()), "interno");
        assert_eq!(escopo(&"2001:4860::8888".parse().unwrap()), "externo");
    }
}
