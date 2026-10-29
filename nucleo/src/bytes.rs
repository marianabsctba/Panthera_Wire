//! Leitura de inteiros com verificação de limites. Nenhum acesso por índice
//! direto sobre dados da captura passa por fora daqui.

pub(crate) fn fatia(b: &[u8], inicio: usize, tamanho: usize) -> Option<&[u8]> {
    b.get(inicio..inicio.checked_add(tamanho)?)
}

pub(crate) fn u8_em(b: &[u8], i: usize) -> Option<u8> {
    b.get(i).copied()
}

pub(crate) fn u16be(b: &[u8], i: usize) -> Option<u16> {
    let s = fatia(b, i, 2)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

pub(crate) fn u32be(b: &[u8], i: usize) -> Option<u32> {
    let s = fatia(b, i, 4)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

pub(crate) fn u16_ordem(b: &[u8], i: usize, be: bool) -> Option<u16> {
    let s = fatia(b, i, 2)?;
    let v = [s[0], s[1]];
    Some(if be { u16::from_be_bytes(v) } else { u16::from_le_bytes(v) })
}

pub(crate) fn u32_ordem(b: &[u8], i: usize, be: bool) -> Option<u32> {
    let s = fatia(b, i, 4)?;
    let v = [s[0], s[1], s[2], s[3]];
    Some(if be { u32::from_be_bytes(v) } else { u32::from_le_bytes(v) })
}

pub(crate) fn mac(b: &[u8], i: usize) -> Option<[u8; 6]> {
    fatia(b, i, 6)?.try_into().ok()
}

pub(crate) fn mac_texto(m: &[u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
}

/// Texto imprimível e com tamanho máximo, para tudo que vem da captura e vai
/// para a interface.
pub(crate) fn texto_limpo(b: &[u8], maximo: usize) -> String {
    String::from_utf8_lossy(b)
        .chars()
        .filter(|c| !c.is_control())
        .take(maximo)
        .collect()
}
