use std::net::Ipv4Addr;

use crate::bytes::{fatia, mac, texto_limpo, u32be, u8_em};

pub struct MensagemDhcp {
    pub tipo: Option<u8>,
    pub mac: [u8; 6],
    pub nome_host: Option<String>,
    pub ip: Option<Ipv4Addr>,
}

pub fn ler(c: &[u8]) -> Option<MensagemDhcp> {
    if u8_em(c, 1)? != 1 || u8_em(c, 2)? != 6 || u32be(c, 236)? != 0x6382_5363 {
        return None;
    }
    let mac = mac(c, 28)?;
    let ip_cliente = Ipv4Addr::from(<[u8; 4]>::try_from(fatia(c, 16, 4)?).ok()?);

    let mut tipo = None;
    let mut nome_host = None;
    let mut ip_pedido = None;
    let mut i = 240;
    while let Some(codigo) = u8_em(c, i) {
        match codigo {
            0 => {
                i += 1;
                continue;
            }
            255 => break,
            _ => {}
        }
        let Some(tam) = u8_em(c, i + 1) else { break };
        let Some(v) = fatia(c, i + 2, tam as usize) else { break };
        match codigo {
            53 => tipo = v.first().copied(),
            12 => nome_host = Some(texto_limpo(v, 64)),
            50 if v.len() == 4 => ip_pedido = Some(Ipv4Addr::new(v[0], v[1], v[2], v[3])),
            _ => {}
        }
        i += 2 + tam as usize;
    }
    let ip = ip_pedido.or(Some(ip_cliente).filter(|ip| !ip.is_unspecified()));
    Some(MensagemDhcp { tipo, mac, nome_host, ip })
}

pub fn nome_tipo(t: u8) -> &'static str {
    match t {
        1 => "DISCOVER",
        2 => "OFFER",
        3 => "REQUEST",
        4 => "DECLINE",
        5 => "ACK",
        6 => "NAK",
        7 => "RELEASE",
        8 => "INFORM",
        _ => "?",
    }
}
