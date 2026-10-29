//! TLS: lê o handshake a partir do começo remontado de cada direção do fluxo.
//! Do cliente sai o ClientHello (SNI, ALPN, versões, JA3 e JA4); do servidor,
//! o ServerHello (versão, cifra, JA3S) e, no TLS 1.2, o certificado.

use md5::{Digest as _, Md5};
use sha2::Sha256;

use crate::bytes::{fatia, texto_limpo, u16be, u8_em};

pub struct HelloCliente {
    pub versao: u16,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    legado: u16,
    cifras: Vec<u16>,
    tipos: Vec<u16>,
    curvas: Vec<u16>,
    formatos: Vec<u8>,
    assinaturas: Vec<u16>,
}

pub struct HelloServidor {
    pub versao: u16,
    pub cifra: u16,
    legado: u16,
    tipos: Vec<u16>,
}

impl HelloServidor {
    /// JA3S: MD5 de versão, cifra escolhida e extensões do ServerHello.
    pub fn ja3s(&self) -> String {
        md5_hex(&format!("{},{},{}", self.legado, self.cifra, juntar(&self.tipos, "-")))
    }
}

pub enum Handshake {
    Cliente(HelloCliente),
    Servidor(HelloServidor),
    /// DER do primeiro certificado da cadeia (o do servidor).
    Certificado(Vec<u8>),
}

pub fn parece_tls(c: &[u8]) -> bool {
    matches!(c, [0x16, 0x03, 0x00..=0x04, ..])
}

/// Lê as mensagens de handshake completas que já estão no buffer. Mensagens
/// podem atravessar registros: os conteúdos dos registros de handshake são
/// concatenados antes. Para no primeiro registro que não é de handshake, e
/// avisa (segundo valor) que o handshake em claro acabou.
pub fn mensagens(buf: &[u8]) -> (Vec<Handshake>, bool) {
    let mut hs = Vec::new();
    let mut i = 0;
    let mut acabou = false;
    while let (Some(tipo), Some(tam)) = (u8_em(buf, i), u16be(buf, i + 3)) {
        if tipo != 0x16 && tipo != 0x14 {
            acabou = true;
            break;
        }
        let Some(corpo) = fatia(buf, i + 5, tam as usize) else { break };
        // ChangeCipherSpec (0x14) só é pulado.
        if tipo == 0x16 {
            hs.extend_from_slice(corpo);
        }
        i += 5 + tam as usize;
    }

    let mut saida = Vec::new();
    let mut j = 0;
    while let (Some(tipo), Some(tam)) = (u8_em(&hs, j), fatia(&hs, j + 1, 3)) {
        let tam = (tam[0] as usize) << 16 | (tam[1] as usize) << 8 | tam[2] as usize;
        let Some(corpo) = fatia(&hs, j + 4, tam) else { break };
        let m = match tipo {
            1 => client_hello(corpo).map(Handshake::Cliente),
            2 => server_hello(corpo).map(Handshake::Servidor),
            11 => certificado(corpo).map(Handshake::Certificado),
            _ => None,
        };
        saida.extend(m);
        j += 4 + tam;
    }
    (saida, acabou)
}

fn grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
}

fn lista_u16(b: &[u8]) -> Vec<u16> {
    b.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).filter(|v| !grease(*v)).collect()
}

fn juntar(v: &[u16], sep: &str) -> String {
    v.iter().map(u16::to_string).collect::<Vec<_>>().join(sep)
}

fn hex4(v: &[u16]) -> String {
    v.iter().map(|x| format!("{x:04x}")).collect::<Vec<_>>().join(",")
}

fn hash12(s: &str) -> String {
    if s.is_empty() {
        return "000000000000".into();
    }
    let d = Sha256::digest(s.as_bytes());
    d.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

fn md5_hex(s: &str) -> String {
    Md5::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// Percorre as extensões a partir de `i` (onde está o tamanho total).
fn extensoes(b: &[u8], i: usize, mut cada: impl FnMut(u16, &[u8])) {
    let Some(total) = u16be(b, i) else { return };
    let fim = (i + 2 + total as usize).min(b.len());
    let mut k = i + 2;
    while k + 4 <= fim {
        let (Some(tipo), Some(tam)) = (u16be(b, k), u16be(b, k + 2)) else { return };
        let dado = &b[k + 4..(k + 4 + tam as usize).min(fim)];
        cada(tipo, dado);
        k += 4 + tam as usize;
    }
}

fn client_hello(b: &[u8]) -> Option<HelloCliente> {
    let legado = u16be(b, 0)?;
    let mut i = 35 + u8_em(b, 34)? as usize; // versão, random, session id
    let n_cifras = u16be(b, i)? as usize;
    let cifras = lista_u16(fatia(b, i + 2, n_cifras)?);
    i += 2 + n_cifras;
    i += 1 + u8_em(b, i)? as usize; // compressão

    let mut tipos = Vec::new();
    let (mut curvas, mut formatos, mut assinaturas, mut versoes) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut sni = None;
    let mut alpn = Vec::new();
    extensoes(b, i, |tipo, d| {
        if !grease(tipo) {
            tipos.push(tipo);
        }
        match tipo {
            0 => {
                if let (Some(0), Some(tam)) = (u8_em(d, 2), u16be(d, 3)) {
                    sni = fatia(d, 5, tam as usize).map(|n| texto_limpo(n, 255));
                }
            }
            10 => curvas = d.get(2..).map(lista_u16).unwrap_or_default(),
            11 => formatos = d.get(1..).map(<[u8]>::to_vec).unwrap_or_default(),
            13 => assinaturas = d.get(2..).map(|s| s.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect()).unwrap_or_default(),
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
            43 => versoes = d.get(1..).map(lista_u16).unwrap_or_default(),
            _ => {}
        }
    });

    let versao = versoes.iter().copied().max().unwrap_or(legado);
    Some(HelloCliente { versao, sni, alpn, legado, cifras, tipos, curvas, formatos, assinaturas })
}

// Os fingerprints são calculados só quando o evento é guardado: os hashes
// custam, e capturas grandes têm muito mais handshakes que eventos guardados.
impl HelloCliente {
    /// JA3: MD5 de versão, cifras, extensões, curvas e formatos (sem GREASE).
    pub fn ja3(&self) -> String {
        md5_hex(&format!(
            "{},{},{},{},{}",
            self.legado,
            juntar(&self.cifras, "-"),
            juntar(&self.tipos, "-"),
            juntar(&self.curvas, "-"),
            self.formatos.iter().map(u8::to_string).collect::<Vec<_>>().join("-")
        ))
    }

    /// JA4 (FoxIO): t + versão + d/i + nº de cifras + nº de extensões + ALPN,
    /// hash das cifras ordenadas, hash das extensões ordenadas sem SNI e ALPN
    /// seguidas dos algoritmos de assinatura na ordem original.
    pub fn ja4(&self) -> String {
        let v = match self.versao {
            0x0304 => "13",
            0x0303 => "12",
            0x0302 => "11",
            0x0301 => "10",
            0x0300 => "s3",
            _ => "00",
        };
        let alpn = match self.alpn.first().map(|a| a.as_bytes()) {
            Some([a, .., z]) if a.is_ascii_alphanumeric() && z.is_ascii_alphanumeric() => {
                format!("{}{}", *a as char, *z as char)
            }
            Some([a]) if a.is_ascii_alphanumeric() => format!("{}{}", *a as char, *a as char),
            Some(_) => "99".into(),
            None => "00".into(),
        };
        let mut cifras = self.cifras.clone();
        cifras.sort_unstable();
        let mut ext: Vec<u16> = self.tipos.iter().copied().filter(|t| *t != 0 && *t != 16).collect();
        ext.sort_unstable();
        let mut ext_txt = hex4(&ext);
        if !self.assinaturas.is_empty() {
            ext_txt.push('_');
            ext_txt.push_str(&hex4(&self.assinaturas));
        }
        format!(
            "t{}{}{:02}{:02}{}_{}_{}",
            v,
            if self.sni.is_some() { "d" } else { "i" },
            self.cifras.len().min(99),
            self.tipos.len().min(99),
            alpn,
            hash12(&hex4(&cifras)),
            hash12(&ext_txt)
        )
    }
}

fn server_hello(b: &[u8]) -> Option<HelloServidor> {
    let legado = u16be(b, 0)?;
    let i = 35 + u8_em(b, 34)? as usize;
    let cifra = u16be(b, i)?;
    let mut versao = legado;
    let mut tipos = Vec::new();
    extensoes(b, i + 3, |tipo, d| {
        tipos.push(tipo);
        if tipo == 43 {
            if let Some(v) = u16be(d, 0) {
                versao = v;
            }
        }
    });
    Some(HelloServidor { versao, cifra, legado, tipos })
}

fn certificado(b: &[u8]) -> Option<Vec<u8>> {
    // TLS 1.2: tamanho da cadeia (3 bytes) e cada certificado com 3 bytes de tamanho.
    let tam = fatia(b, 3, 3)?;
    let tam = (tam[0] as usize) << 16 | (tam[1] as usize) << 8 | tam[2] as usize;
    fatia(b, 6, tam).map(<[u8]>::to_vec)
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

    fn ext(tipo: u16, dado: &[u8]) -> Vec<u8> {
        let mut v = tipo.to_be_bytes().to_vec();
        v.extend_from_slice(&(dado.len() as u16).to_be_bytes());
        v.extend_from_slice(dado);
        v
    }

    fn registro(tipo_hs: u8, corpo: &[u8]) -> Vec<u8> {
        let mut hs = vec![tipo_hs, 0];
        hs.extend_from_slice(&(corpo.len() as u16).to_be_bytes());
        hs.extend_from_slice(corpo);
        let mut r = vec![0x16, 3, 1];
        r.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        r.extend_from_slice(&hs);
        r
    }

    /// ClientHello com as cifras e extensões do exemplo oficial do JA4.
    fn hello_exemplo() -> Vec<u8> {
        let cifras: [u16; 16] =
            [0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035];
        let mut e = Vec::new();
        e.extend(ext(0x0a0a, &[]));
        e.extend(ext(0x0000, &[0, 9, 0, 0, 6, b'a', b'.', b'b', b'.', b'c', b'd']));
        for t in [0x0017u16, 0xff01, 0x0023, 0x0012, 0x0005, 0x001b, 0x0015, 0x4469] {
            e.extend(ext(t, &[]));
        }
        e.extend(ext(0x000a, &[0, 6, 0, 0x1d, 0, 0x17, 0, 0x18]));
        e.extend(ext(0x000b, &[1, 0]));
        let sig: [u16; 8] = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];
        let mut s = ((sig.len() * 2) as u16).to_be_bytes().to_vec();
        sig.iter().for_each(|x| s.extend_from_slice(&x.to_be_bytes()));
        e.extend(ext(0x000d, &s));
        e.extend(ext(0x0010, &[0, 3, 2, b'h', b'2']));
        e.extend(ext(0x002b, &[4, 3, 4, 3, 3]));
        e.extend(ext(0x002d, &[1, 1]));
        e.extend(ext(0x0033, &[0, 0]));

        let mut c = vec![3, 3];
        c.extend_from_slice(&[7; 32]);
        c.push(0);
        c.extend_from_slice(&((cifras.len() * 2) as u16).to_be_bytes());
        cifras.iter().for_each(|x| c.extend_from_slice(&x.to_be_bytes()));
        c.extend_from_slice(&[1, 0]);
        c.extend_from_slice(&(e.len() as u16).to_be_bytes());
        c.extend_from_slice(&e);
        registro(1, &c)
    }

    #[test]
    fn ja4_do_exemplo_oficial() {
        let (m, _) = mensagens(&hello_exemplo());
        let Some(Handshake::Cliente(h)) = m.first() else { panic!() };
        // GREASE fora; 15 cifras, 16 extensões, SNI presente, ALPN h2.
        assert_eq!(h.ja4(), "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(h.sni.as_deref(), Some("a.b.cd"));
        assert_eq!(nome_versao(h.versao), "TLS 1.3");
        assert_eq!(h.ja3().len(), 32);
    }

    #[test]
    fn hello_dividido_em_dois_registros() {
        let r = hello_exemplo();
        // Mesmo handshake, cortado em dois registros TLS.
        let hs = &r[5..];
        let (a, b) = hs.split_at(40);
        let mut v = vec![0x16, 3, 1];
        v.extend_from_slice(&(a.len() as u16).to_be_bytes());
        v.extend_from_slice(a);
        v.extend_from_slice(&[0x16, 3, 1]);
        v.extend_from_slice(&(b.len() as u16).to_be_bytes());
        v.extend_from_slice(b);
        assert!(matches!(mensagens(&v).0.first(), Some(Handshake::Cliente(_))));
    }

    #[test]
    fn hello_cortado_nao_derruba() {
        let c = hello_exemplo();
        for fim in 0..c.len() {
            let _ = mensagens(&c[..fim]);
        }
    }
}
