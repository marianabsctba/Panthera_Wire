use std::net::{Ipv4Addr, Ipv6Addr};

use crate::bytes::{fatia, texto_limpo, u16be, u8_em};

pub struct MensagemDns {
    pub id: u16,
    pub resposta: bool,
    pub rcode: u8,
    pub consulta: Option<String>,
    pub tipo: u16,
    pub respostas: Vec<RespostaDns>,
}

pub struct RespostaDns {
    pub tipo: u16,
    pub valor: String,
}

const MAX_RESPOSTAS: usize = 32;

pub fn ler(m: &[u8]) -> Option<MensagemDns> {
    let id = u16be(m, 0)?;
    let flags = u16be(m, 2)?;
    let perguntas = u16be(m, 4)?;
    let respostas_total = u16be(m, 6)?;
    // Filtro de sanidade: tráfego qualquer na porta 53 não vira DNS.
    if perguntas == 0 || perguntas > 8 || respostas_total > 512 || (flags >> 11) & 0x0f > 6 {
        return None;
    }

    let mut i = 12;
    let mut consulta = None;
    let mut tipo = 0;
    for k in 0..perguntas {
        let (nome, prox) = nome(m, i)?;
        let t = u16be(m, prox)?;
        i = prox + 4;
        if k == 0 {
            consulta = Some(nome);
            tipo = t;
        }
    }

    let mut respostas = Vec::new();
    for _ in 0..respostas_total {
        let Some((_, p)) = nome(m, i) else { break };
        let (Some(t), Some(tam)) = (u16be(m, p), u16be(m, p + 8)) else { break };
        let Some(dado) = fatia(m, p + 10, tam as usize) else { break };
        i = p + 10 + tam as usize;
        let valor = match t {
            1 if dado.len() == 4 => Some(Ipv4Addr::from(<[u8; 4]>::try_from(dado).ok()?).to_string()),
            28 if dado.len() == 16 => Some(Ipv6Addr::from(<[u8; 16]>::try_from(dado).ok()?).to_string()),
            2 | 5 | 12 => nome(m, p + 10).map(|n| n.0),
            15 => nome(m, p + 12).map(|n| n.0),
            16 => Some(txt(dado)),
            _ => None,
        };
        if let Some(valor) = valor {
            if respostas.len() < MAX_RESPOSTAS {
                respostas.push(RespostaDns { tipo: t, valor });
            }
        }
    }

    Some(MensagemDns { id, resposta: flags & 0x8000 != 0, rcode: (flags & 0x0f) as u8, consulta, tipo, respostas })
}

/// Lê um nome com ponteiros de compressão. Devolve o nome e a posição logo
/// depois dele na mensagem original.
fn nome(m: &[u8], mut i: usize) -> Option<(String, usize)> {
    let mut nome = String::new();
    let mut depois = None;
    let mut saltos = 0;
    loop {
        let tam = u8_em(m, i)?;
        match tam & 0xc0 {
            0xc0 => {
                if depois.is_none() {
                    depois = Some(i + 2);
                }
                saltos += 1;
                if saltos > 16 {
                    return None;
                }
                i = (u16be(m, i)? & 0x3fff) as usize;
            }
            0x00 if tam == 0 => {
                if depois.is_none() {
                    depois = Some(i + 1);
                }
                break;
            }
            0x00 => {
                let rotulo = fatia(m, i + 1, tam as usize)?;
                if !nome.is_empty() {
                    nome.push('.');
                }
                nome.push_str(&texto_limpo(rotulo, 63));
                if nome.len() > 255 {
                    return None;
                }
                i += 1 + tam as usize;
            }
            _ => return None,
        }
    }
    Some((if nome.is_empty() { ".".into() } else { nome }, depois?))
}

fn txt(dado: &[u8]) -> String {
    let mut s = String::new();
    let mut i = 0;
    while let Some(tam) = u8_em(dado, i) {
        let Some(parte) = fatia(dado, i + 1, tam as usize) else { break };
        s.push_str(&texto_limpo(parte, 255));
        i += 1 + tam as usize;
        if s.len() >= 255 {
            break;
        }
    }
    s.chars().take(255).collect()
}

pub fn nome_tipo(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        n => format!("TYPE{n}"),
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn resposta_com_compressao() {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        m.extend_from_slice(b"\x03www\x07exemplo\x03com\x00\x00\x01\x00\x01");
        // CNAME apontando para cdn.exemplo.com (com ponteiro para "exemplo.com")
        m.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6]);
        m.extend_from_slice(&[3, b'c', b'd', b'n', 0xc0, 16]);
        m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        let d = ler(&m).unwrap();
        assert!(d.resposta);
        assert_eq!(d.consulta.as_deref(), Some("www.exemplo.com"));
        assert_eq!(d.respostas[0].valor, "cdn.exemplo.com");
        assert_eq!(d.respostas[1].valor, "93.184.216.34");
    }

    #[test]
    fn ponteiro_em_laco_nao_trava() {
        let mut m = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(&[0xc0, 12]);
        assert!(ler(&m).is_none());
    }
}
