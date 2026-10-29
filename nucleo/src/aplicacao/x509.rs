//! Leitura mínima de certificado X.509 (DER): só o que serve para análise de
//! rede. Nomes do sujeito e do emissor, validade, nomes alternativos e se é
//! autoassinado. Sem validar assinatura nem cadeia.

use crate::bytes::{texto_limpo, u8_em};
pub use crate::relatorio::Certificado;

/// (tag, início do conteúdo, fim do conteúdo, fim do elemento)
fn elemento(b: &[u8], i: usize) -> Option<(u8, usize, usize)> {
    let tag = u8_em(b, i)?;
    let primeiro = u8_em(b, i + 1)? as usize;
    let (tam, ini) = if primeiro < 0x80 {
        (primeiro, i + 2)
    } else {
        let n = primeiro & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut t = 0usize;
        for k in 0..n {
            t = t << 8 | u8_em(b, i + 2 + k)? as usize;
        }
        (t, i + 2 + n)
    };
    let fim = ini.checked_add(tam)?;
    (fim <= b.len()).then_some((tag, ini, fim))
}

/// Filhos de um elemento construído.
fn filhos(b: &[u8], ini: usize, fim: usize) -> Vec<(u8, usize, usize)> {
    let mut v = Vec::new();
    let mut i = ini;
    while i < fim && v.len() < 64 {
        let Some((tag, a, z)) = elemento(b, i) else { break };
        v.push((tag, a, z));
        i = z;
    }
    v
}

const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_O: &[u8] = &[0x55, 0x04, 0x0a];
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];

fn atributo(b: &[u8], nome: (usize, usize), oid: &[u8]) -> Option<String> {
    for (_, a, z) in filhos(b, nome.0, nome.1) {
        for (_, sa, sz) in filhos(b, a, z) {
            let partes = filhos(b, sa, sz);
            if let [(0x06, oa, oz), (_, va, vz), ..] = partes[..] {
                if &b[oa..oz] == oid {
                    return Some(texto_limpo(&b[va..vz], 255));
                }
            }
        }
    }
    None
}

fn tempo(b: &[u8], tag: u8, a: usize, z: usize) -> Option<u64> {
    let s = std::str::from_utf8(&b[a..z]).ok()?;
    let (ano, resto) = match tag {
        0x17 => {
            let aa: i64 = s.get(0..2)?.parse().ok()?;
            (if aa < 50 { 2000 + aa } else { 1900 + aa }, s.get(2..)?)
        }
        0x18 => (s.get(0..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    let n = |i: usize| -> Option<i64> { resto.get(i..i + 2)?.parse().ok() };
    let (mes, dia, h, m, seg) = (n(0)?, n(2)?, n(4)?, n(6)?, n(8).unwrap_or(0));
    let dias = dias_desde_1970(ano, mes, dia);
    let total = dias * 86_400 + h * 3600 + m * 60 + seg;
    u64::try_from(total).ok().map(|t| t * 1_000_000)
}

/// Algoritmo de Howard Hinnant (days_from_civil).
fn dias_desde_1970(ano: i64, mes: i64, dia: i64) -> i64 {
    let y = if mes <= 2 { ano - 1 } else { ano };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (mes + 9) % 12;
    let doy = (153 * mp + 2) / 5 + dia - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub fn ler(der: &[u8]) -> Option<Certificado> {
    let (0x30, ca, cz) = elemento(der, 0)? else { return None };
    let (0x30, ta, tz) = elemento(der, ca)? else { return None };
    let mut campos = filhos(der, ta, tz);
    // [0] versão é opcional
    if campos.first().is_some_and(|c| c.0 == 0xa0) {
        campos.remove(0);
    }
    let _ = cz;
    // número de série, algoritmo, emissor, validade, sujeito, chave pública, extensões...
    let emissor = campos.get(2).filter(|c| c.0 == 0x30)?;
    let validade = campos.get(3).filter(|c| c.0 == 0x30)?;
    let sujeito = campos.get(4).filter(|c| c.0 == 0x30)?;

    let datas = filhos(der, validade.1, validade.2);
    let nao_antes = datas.first().and_then(|d| tempo(der, d.0, d.1, d.2));
    let nao_depois = datas.get(1).and_then(|d| tempo(der, d.0, d.1, d.2));

    let mut nomes = Vec::new();
    if let Some(ext) = campos.iter().find(|c| c.0 == 0xa3) {
        for (_, sa, sz) in filhos(der, ext.1, ext.2) {
            for (_, ea, ez) in filhos(der, sa, sz) {
                let partes = filhos(der, ea, ez);
                let Some(&(0x06, oa, oz)) = partes.first() else { continue };
                if &der[oa..oz] != OID_SAN {
                    continue;
                }
                let Some(&(0x04, va, vz)) = partes.last() else { continue };
                let Some((0x30, la, lz)) = elemento(der, va).filter(|e| e.2 <= vz) else { continue };
                for (tag, na, nz) in filhos(der, la, lz) {
                    if tag == 0x82 && nomes.len() < 256 {
                        nomes.push(texto_limpo(&der[na..nz], 255).to_ascii_lowercase());
                    }
                }
            }
        }
    }

    Some(Certificado {
        sujeito: atributo(der, (sujeito.1, sujeito.2), OID_CN),
        emissor: atributo(der, (emissor.1, emissor.2), OID_CN),
        emissor_organizacao: atributo(der, (emissor.1, emissor.2), OID_O),
        nao_antes_us: nao_antes,
        nao_depois_us: nao_depois,
        autoassinado: der[emissor.1..emissor.2] == der[sujeito.1..sujeito.2],
        nomes,
    })
}

/// O nome pedido (SNI) bate com algum nome do certificado (com curinga).
/// Sem nomes alternativos, vale o CN do sujeito.
pub fn confere(cert: &Certificado, nome: &str) -> bool {
    let nome = nome.to_ascii_lowercase();
    let bate = |padrao: &str| {
        let p = padrao.to_ascii_lowercase();
        match p.strip_prefix("*.") {
            Some(base) => nome.split_once('.').is_some_and(|(_, resto)| resto == base),
            None => p == nome,
        }
    };
    cert.nomes.iter().any(|n| bate(n)) || cert.sujeito.as_deref().is_some_and(bate)
}

#[cfg(test)]
mod testes {
    use super::*;

    fn tlv(tag: u8, conteudo: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        if conteudo.len() < 0x80 {
            v.push(conteudo.len() as u8);
        } else {
            v.push(0x82);
            v.extend_from_slice(&(conteudo.len() as u16).to_be_bytes());
        }
        v.extend_from_slice(conteudo);
        v
    }

    fn nome(cn: &str) -> Vec<u8> {
        let atr = tlv(0x30, &[tlv(0x06, OID_CN), tlv(0x0c, cn.as_bytes())].concat());
        tlv(0x30, &tlv(0x31, &atr))
    }

    pub fn certificado_exemplo(emissor: &str, sujeito: &str, san: &[&str], antes: &str, depois: &str) -> Vec<u8> {
        let validade = tlv(0x30, &[tlv(0x17, antes.as_bytes()), tlv(0x17, depois.as_bytes())].concat());
        let nomes: Vec<u8> = san.iter().flat_map(|n| tlv(0x82, n.as_bytes())).collect();
        let ext_san = tlv(0x30, &[tlv(0x06, OID_SAN), tlv(0x04, &tlv(0x30, &nomes))].concat());
        let extensoes = tlv(0xa3, &tlv(0x30, &ext_san));
        let tbs = tlv(
            0x30,
            &[
                tlv(0xa0, &tlv(0x02, &[2])),
                tlv(0x02, &[1]),
                tlv(0x30, &tlv(0x06, &[0x2a])),
                nome(emissor),
                validade,
                nome(sujeito),
                tlv(0x30, &[]),
                extensoes,
            ]
            .concat(),
        );
        tlv(0x30, &[tbs, tlv(0x30, &tlv(0x06, &[0x2a])), tlv(0x03, &[0])].concat())
    }

    #[test]
    fn le_nomes_validade_e_autoassinado() {
        let der = certificado_exemplo("cdn-sync.top", "cdn-sync.top", &["cdn-sync.top"], "250101000000Z", "250201000000Z");
        let c = ler(&der).unwrap();
        assert_eq!(c.sujeito.as_deref(), Some("cdn-sync.top"));
        assert!(c.autoassinado);
        assert_eq!(c.nomes, vec!["cdn-sync.top"]);
        assert_eq!(c.nao_antes_us, Some(1_735_689_600_000_000));
        assert!(confere(&c, "CDN-SYNC.top"));
        assert!(!confere(&c, "outro.top"));

        let der = certificado_exemplo("R11", "www.exemplo.com", &["*.exemplo.com"], "250101000000Z", "260101000000Z");
        let c = ler(&der).unwrap();
        assert!(!c.autoassinado);
        assert!(confere(&c, "api.exemplo.com"));
        assert!(!confere(&c, "a.b.exemplo.com"));
    }

    #[test]
    fn der_cortado_nao_derruba() {
        let der = certificado_exemplo("a", "b", &["c"], "250101000000Z", "260101000000Z");
        for fim in 0..der.len() {
            let _ = ler(&der[..fim]);
        }
    }
}
