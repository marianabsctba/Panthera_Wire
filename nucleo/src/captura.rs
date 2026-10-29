//! Leitura de pcap e pcapng em streaming.
//!
//! Os bytes chegam em blocos de qualquer tamanho. O leitor guarda só o pedaço
//! de registro que ficou incompleto no fim de um bloco e entrega cada pacote
//! com o offset dele no arquivo original.

use serde::Serialize;

use crate::bytes::{fatia, u16_ordem, u32_ordem};

/// Um pacote como está na captura, antes da decodificação.
pub struct PacoteBruto<'a> {
    pub offset: u64,
    pub ts_us: u64,
    pub enlace: u16,
    pub dados: &'a [u8],
    pub tamanho_original: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErroCaptura {
    pub codigo: &'static str,
    pub offset: u64,
}

#[derive(Clone, Copy)]
enum Resolucao {
    /// 10^-n segundos
    Decimal(u8),
    /// 2^-n segundos
    Binaria(u8),
}

#[derive(Clone, Copy)]
struct Interface {
    enlace: u16,
    resolucao: Resolucao,
}

enum Formato {
    Desconhecido,
    Pcap { be: bool, nano: bool, enlace: u16 },
    Pcapng { be: bool, interfaces: Vec<Interface> },
}

/// Maior registro aceito. Acima disso o arquivo está corrompido ou é hostil.
const MAX_REGISTRO: usize = 64 * 1024 * 1024;
const MAX_INTERFACES: usize = 1024;

const PCAPNG_SHB: u32 = 0x0A0D_0D0A;

pub struct LeitorCaptura {
    buf: Vec<u8>,
    base: u64,
    formato: Formato,
    enlaces: Vec<u16>,
    erro: Option<ErroCaptura>,
}

impl LeitorCaptura {
    pub fn new() -> Self {
        Self { buf: Vec::new(), base: 0, formato: Formato::Desconhecido, enlaces: Vec::new(), erro: None }
    }

    pub fn formato(&self) -> &'static str {
        match self.formato {
            Formato::Desconhecido => "desconhecido",
            Formato::Pcap { .. } => "pcap",
            Formato::Pcapng { .. } => "pcapng",
        }
    }

    pub fn enlaces(&self) -> &[u16] {
        &self.enlaces
    }

    pub fn erro(&self) -> Option<&ErroCaptura> {
        self.erro.as_ref()
    }

    /// Bytes de um registro incompleto que sobraram no fim do último bloco.
    pub fn pendente(&self) -> (u64, usize) {
        (self.base, self.buf.len())
    }

    pub fn alimentar(&mut self, dados: &[u8], mut ao_pacote: impl FnMut(PacoteBruto<'_>)) -> Result<(), ErroCaptura> {
        if let Some(e) = &self.erro {
            return Err(e.clone());
        }
        self.buf.extend_from_slice(dados);

        let Self { buf, base, formato, enlaces, .. } = self;
        let mut pos = 0usize;
        let resultado = loop {
            match ler_registro(formato, &buf[pos..], *base + pos as u64, enlaces, &mut ao_pacote) {
                Ok(Some(n)) => pos += n,
                Ok(None) => break Ok(()),
                Err(e) => break Err(e),
            }
        };
        buf.drain(..pos);
        *base += pos as u64;

        if let Err(e) = &resultado {
            self.erro = Some(e.clone());
        }
        resultado
    }
}

/// Lê um registro do início de `b`. Devolve quantos bytes consumiu, ou `None`
/// se ainda faltam bytes para completar o registro.
fn ler_registro(
    formato: &mut Formato,
    b: &[u8],
    offset: u64,
    enlaces: &mut Vec<u16>,
    ao_pacote: &mut impl FnMut(PacoteBruto<'_>),
) -> Result<Option<usize>, ErroCaptura> {
    let erro = |codigo| ErroCaptura { codigo, offset };

    match formato {
        Formato::Desconhecido => {
            let Some(magico) = fatia(b, 0, 4) else { return Ok(None) };
            let (be, nano) = match magico {
                [0xd4, 0xc3, 0xb2, 0xa1] => (false, false),
                [0xa1, 0xb2, 0xc3, 0xd4] => (true, false),
                [0x4d, 0x3c, 0xb2, 0xa1] => (false, true),
                [0xa1, 0xb2, 0x3c, 0x4d] => (true, true),
                [0x0a, 0x0d, 0x0d, 0x0a] => {
                    // O próprio bloco de seção define a ordem dos bytes.
                    *formato = Formato::Pcapng { be: false, interfaces: Vec::new() };
                    return Ok(Some(0));
                }
                _ => return Err(erro("formato_desconhecido")),
            };
            if b.len() < 24 {
                return Ok(None);
            }
            let enlace = (u32_ordem(b, 20, be).ok_or(erro("cabecalho_invalido"))? & 0xffff) as u16;
            registrar_enlace(enlaces, enlace);
            *formato = Formato::Pcap { be, nano, enlace };
            Ok(Some(24))
        }

        Formato::Pcap { be, nano, enlace } => {
            let (be, nano, enlace) = (*be, *nano, *enlace);
            if b.len() < 16 {
                return Ok(None);
            }
            let ler = |i| u32_ordem(b, i, be).ok_or(erro("registro_invalido"));
            let (seg, frac, capturado, original) = (ler(0)?, ler(4)?, ler(8)? as usize, ler(12)?);
            if capturado > MAX_REGISTRO {
                return Err(erro("registro_invalido"));
            }
            let Some(dados) = fatia(b, 16, capturado) else { return Ok(None) };
            let frac_us = if nano { frac as u64 / 1000 } else { frac as u64 };
            ao_pacote(PacoteBruto {
                offset,
                ts_us: seg as u64 * 1_000_000 + frac_us,
                enlace,
                dados,
                tamanho_original: original.max(capturado as u32),
            });
            Ok(Some(16 + capturado))
        }

        Formato::Pcapng { be, interfaces } => {
            let Some(tipo_bruto) = fatia(b, 0, 4) else { return Ok(None) };
            if tipo_bruto == [0x0a, 0x0d, 0x0d, 0x0a] {
                // Nova seção: ordem dos bytes e interfaces começam do zero.
                let Some(bom) = fatia(b, 8, 4) else { return Ok(None) };
                *be = match bom {
                    [0x1a, 0x2b, 0x3c, 0x4d] => true,
                    [0x4d, 0x3c, 0x2b, 0x1a] => false,
                    _ => return Err(erro("pcapng_invalido")),
                };
                interfaces.clear();
            }
            let be = *be;
            let (Some(tipo), Some(tamanho)) = (u32_ordem(b, 0, be), u32_ordem(b, 4, be)) else { return Ok(None) };
            let tamanho = tamanho as usize;
            if tamanho < 12 || tamanho % 4 != 0 || tamanho > MAX_REGISTRO {
                return Err(erro("bloco_invalido"));
            }
            if b.len() < tamanho {
                return Ok(None);
            }
            let corpo = &b[8..tamanho - 4];
            let ler32 = |i| u32_ordem(corpo, i, be).ok_or(erro("bloco_invalido"));

            match tipo {
                PCAPNG_SHB => {}
                // Interface Description Block
                1 => {
                    let enlace = u16_ordem(corpo, 0, be).ok_or(erro("bloco_invalido"))?;
                    let mut resolucao = Resolucao::Decimal(6);
                    let mut i = 8;
                    while let (Some(codigo), Some(tam)) = (u16_ordem(corpo, i, be), u16_ordem(corpo, i + 2, be)) {
                        if codigo == 0 {
                            break;
                        }
                        // if_tsresol
                        if codigo == 9 && tam >= 1 {
                            if let Some(&v) = corpo.get(i + 4) {
                                resolucao = if v & 0x80 != 0 { Resolucao::Binaria(v & 0x7f) } else { Resolucao::Decimal(v) };
                            }
                        }
                        i += 4 + (tam as usize).div_ceil(4) * 4;
                    }
                    if interfaces.len() < MAX_INTERFACES {
                        interfaces.push(Interface { enlace, resolucao });
                    }
                    registrar_enlace(enlaces, enlace);
                }
                // Enhanced Packet Block
                6 => {
                    let itf = *interfaces.get(ler32(0)? as usize).ok_or(erro("interface_inexistente"))?;
                    let ts = (ler32(4)? as u64) << 32 | ler32(8)? as u64;
                    let capturado = ler32(12)? as usize;
                    let original = ler32(16)?;
                    let dados = fatia(corpo, 20, capturado).ok_or(erro("bloco_invalido"))?;
                    ao_pacote(PacoteBruto {
                        offset,
                        ts_us: para_us(ts, itf.resolucao),
                        enlace: itf.enlace,
                        dados,
                        tamanho_original: original.max(capturado as u32),
                    });
                }
                // Simple Packet Block: sem horário, sempre da interface 0
                3 => {
                    let itf = *interfaces.first().ok_or(erro("interface_inexistente"))?;
                    let original = ler32(0)?;
                    let dados = &corpo[4.min(corpo.len())..];
                    let dados = &dados[..dados.len().min(original as usize)];
                    ao_pacote(PacoteBruto { offset, ts_us: 0, enlace: itf.enlace, dados, tamanho_original: original });
                }
                // Packet Block (obsoleto)
                2 => {
                    let indice = u16_ordem(corpo, 0, be).ok_or(erro("bloco_invalido"))? as usize;
                    let itf = *interfaces.get(indice).ok_or(erro("interface_inexistente"))?;
                    let ts = (ler32(4)? as u64) << 32 | ler32(8)? as u64;
                    let capturado = ler32(12)? as usize;
                    let original = ler32(16)?;
                    let dados = fatia(corpo, 20, capturado).ok_or(erro("bloco_invalido"))?;
                    ao_pacote(PacoteBruto {
                        offset,
                        ts_us: para_us(ts, itf.resolucao),
                        enlace: itf.enlace,
                        dados,
                        tamanho_original: original.max(capturado as u32),
                    });
                }
                // Estatísticas, resolução de nomes, segredos e blocos desconhecidos.
                _ => {}
            }
            Ok(Some(tamanho))
        }
    }
}

fn registrar_enlace(enlaces: &mut Vec<u16>, enlace: u16) {
    if !enlaces.contains(&enlace) && enlaces.len() < 64 {
        enlaces.push(enlace);
    }
}

fn para_us(ts: u64, resolucao: Resolucao) -> u64 {
    match resolucao {
        Resolucao::Decimal(n) if n >= 6 => 10u64.checked_pow(n as u32 - 6).map_or(0, |d| ts / d),
        Resolucao::Decimal(n) => ts.saturating_mul(10u64.pow(6 - n as u32)),
        Resolucao::Binaria(n) => ((ts as u128 * 1_000_000) >> n.min(127)) as u64,
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    fn pcap_com(pacotes: &[&[u8]]) -> Vec<u8> {
        let mut v = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
        v.extend_from_slice(&[0; 8]);
        v.extend_from_slice(&65535u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        for (i, p) in pacotes.iter().enumerate() {
            v.extend_from_slice(&(1_700_000_000u32 + i as u32).to_le_bytes());
            v.extend_from_slice(&500u32.to_le_bytes());
            v.extend_from_slice(&(p.len() as u32).to_le_bytes());
            v.extend_from_slice(&(p.len() as u32).to_le_bytes());
            v.extend_from_slice(p);
        }
        v
    }

    #[test]
    fn pcap_em_blocos_de_um_byte() {
        let arquivo = pcap_com(&[&[1, 2, 3], &[4, 5, 6, 7]]);
        let mut leitor = LeitorCaptura::new();
        let mut vistos = Vec::new();
        for b in arquivo.chunks(1) {
            leitor.alimentar(b, |p| vistos.push((p.offset, p.ts_us, p.dados.to_vec()))).unwrap();
        }
        assert_eq!(leitor.formato(), "pcap");
        assert_eq!(vistos.len(), 2);
        assert_eq!(vistos[0], (24, 1_700_000_000_000_500, vec![1, 2, 3]));
        assert_eq!(vistos[1].0, 24 + 16 + 3);
        assert_eq!(leitor.pendente().1, 0);
    }

    #[test]
    fn arquivo_que_nao_e_captura() {
        let mut leitor = LeitorCaptura::new();
        let r = leitor.alimentar(b"PK\x03\x04 isto e um zip", |_| {});
        assert_eq!(r.unwrap_err().codigo, "formato_desconhecido");
    }

    #[test]
    fn registro_gigante_e_recusado() {
        let mut arquivo = pcap_com(&[]);
        arquivo.extend_from_slice(&[0; 8]);
        arquivo.extend_from_slice(&u32::MAX.to_le_bytes());
        arquivo.extend_from_slice(&[0; 4]);
        let r = LeitorCaptura::new().alimentar(&arquivo, |_| {});
        assert_eq!(r.unwrap_err().codigo, "registro_invalido");
    }

    #[test]
    fn resolucoes_de_tempo() {
        assert_eq!(para_us(1_500_000_000, Resolucao::Decimal(9)), 1_500_000);
        assert_eq!(para_us(15, Resolucao::Decimal(1)), 1_500_000);
        assert_eq!(para_us(1 << 20, Resolucao::Binaria(20)), 1_000_000);
    }
}
