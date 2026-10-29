use crate::bytes::{fatia, texto_limpo, u16be, u8_em};

pub enum MensagemTls {
    ClientHello { versao: u16, sni: Option<String>, alpn: Vec<String> },
    ServerHello { versao: u16, cifra: u16 },
}

pub fn parece_tls(c: &[u8]) -> bool {
    matches!(c, [0x16, 0x03, 0x00..=0x04, ..])
}

pub fn ler(c: &[u8]) -> Option<MensagemTls> {
    if !parece_tls(c) {
        return None;
    }
    let tamanho = u16be(c, 3)? as usize;
    // O registro pode vir cortado no segmento: aproveita o que chegou.
    let hs = c.get(5..(5 + tamanho).min(c.len()))?;
    let corpo = hs.get(4..)?;
    match u8_em(hs, 0)? {
        1 => client_hello(corpo),
        2 => server_hello(corpo),
        _ => None,
    }
}

fn pular_inicio(b: &[u8]) -> Option<usize> {
    // versão (2) + random (32) + session id
    let sessao = u8_em(b, 34)? as usize;
    Some(35 + sessao)
}

fn extensoes(b: &[u8], mut i: usize, mut cada: impl FnMut(u16, &[u8])) {
    let Some(total) = u16be(b, i) else { return };
    i += 2;
    let fim = (i + total as usize).min(b.len());
    while i + 4 <= fim {
        let (Some(tipo), Some(tam)) = (u16be(b, i), u16be(b, i + 2)) else { return };
        let dado = &b[i + 4..(i + 4 + tam as usize).min(fim)];
        cada(tipo, dado);
        i += 4 + tam as usize;
    }
}

fn grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a
}

fn client_hello(b: &[u8]) -> Option<MensagemTls> {
    let mut versao = u16be(b, 0)?;
    let mut i = pular_inicio(b)?;
    i += 2 + u16be(b, i)? as usize; // cifras
    i += 1 + u8_em(b, i)? as usize; // compressão

    let mut sni = None;
    let mut alpn = Vec::new();
    extensoes(b, i, |tipo, d| match tipo {
        0 => {
            // lista (2) + tipo do nome (1) + tamanho (2) + nome
            if let (Some(0), Some(tam)) = (u8_em(d, 2), u16be(d, 3)) {
                sni = fatia(d, 5, tam as usize).map(|n| texto_limpo(n, 255));
            }
        }
        16 => {
            let mut j = 2;
            while let Some(tam) = u8_em(d, j) {
                let Some(p) = fatia(d, j + 1, tam as usize) else { break };
                if alpn.len() < 8 {
                    alpn.push(texto_limpo(p, 32));
                }
                j += 1 + tam as usize;
            }
        }
        43 => {
            let mut j = 1;
            while let Some(v) = u16be(d, j) {
                if !grease(v) {
                    versao = versao.max(v);
                }
                j += 2;
            }
        }
        _ => {}
    });
    Some(MensagemTls::ClientHello { versao, sni, alpn })
}

fn server_hello(b: &[u8]) -> Option<MensagemTls> {
    let mut versao = u16be(b, 0)?;
    let i = pular_inicio(b)?;
    let cifra = u16be(b, i)?;
    extensoes(b, i + 3, |tipo, d| {
        if tipo == 43 {
            if let Some(v) = u16be(d, 0) {
                versao = v;
            }
        }
    });
    Some(MensagemTls::ServerHello { versao, cifra })
}

pub fn nome_versao(v: u16) -> String {
    match v {
        0x0300 => "SSL 3.0".into(),
        0x0301 => "TLS 1.0".into(),
        0x0302 => "TLS 1.1".into(),
        0x0303 => "TLS 1.2".into(),
        0x0304 => "TLS 1.3".into(),
        n => format!("0x{n:04x}"),
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    pub fn client_hello_exemplo(sni: &str) -> Vec<u8> {
        let mut ext = Vec::new();
        let n = sni.as_bytes();
        ext.extend_from_slice(&[0, 0]);
        ext.extend_from_slice(&((n.len() + 5) as u16).to_be_bytes());
        ext.extend_from_slice(&((n.len() + 3) as u16).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(n.len() as u16).to_be_bytes());
        ext.extend_from_slice(n);
        ext.extend_from_slice(&[0, 16, 0, 5, 0, 3, 2, b'h', b'2']);
        ext.extend_from_slice(&[0, 43, 0, 5, 4, 0x3a, 0x3a, 3, 4]);

        let mut corpo = vec![3, 3];
        corpo.extend_from_slice(&[7; 32]);
        corpo.push(0);
        corpo.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
        corpo.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        corpo.extend_from_slice(&ext);

        let mut hs = vec![1, 0];
        hs.extend_from_slice(&(corpo.len() as u16).to_be_bytes());
        hs.extend_from_slice(&corpo);
        let mut r = vec![0x16, 3, 1];
        r.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        r.extend_from_slice(&hs);
        r
    }

    #[test]
    fn sni_alpn_e_versao() {
        let Some(MensagemTls::ClientHello { versao, sni, alpn }) = ler(&client_hello_exemplo("update-cdn.xyz")) else {
            panic!()
        };
        assert_eq!(sni.as_deref(), Some("update-cdn.xyz"));
        assert_eq!(alpn, vec!["h2"]);
        assert_eq!(nome_versao(versao), "TLS 1.3");
    }

    #[test]
    fn hello_cortado_nao_derruba() {
        let c = client_hello_exemplo("a.b");
        for fim in 0..c.len() {
            let _ = ler(&c[..fim]);
        }
    }
}
