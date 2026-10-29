// Compartilhado pelos alvos: monta um pcap com um único pacote a partir dos
// bytes do fuzzer. O primeiro byte escolhe o tipo de enlace, para os
// decodificadores de Ethernet, SLL, SLL2, loopback e IP cru serem exercitados.

const ENLACES: [u32; 8] = [1, 113, 276, 0, 108, 101, 228, 229];

pub fn pcap_de_um_pacote(dados: &[u8]) -> Vec<u8> {
    let (enlace, quadro) = match dados.split_first() {
        Some((e, resto)) => (ENLACES[*e as usize % ENLACES.len()], resto),
        None => (1, &[][..]),
    };
    let mut v = Vec::with_capacity(40 + quadro.len());
    v.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0]);
    v.extend_from_slice(&[0; 8]);
    v.extend_from_slice(&65535u32.to_le_bytes());
    v.extend_from_slice(&enlace.to_le_bytes());
    v.extend_from_slice(&1_700_000_000u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&(quadro.len() as u32).to_le_bytes());
    v.extend_from_slice(&(quadro.len() as u32).to_le_bytes());
    v.extend_from_slice(quadro);
    v
}
