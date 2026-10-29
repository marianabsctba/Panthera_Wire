//! Anonimizador: lê a captura em blocos e escreve uma nova, em pcapng, sem
//! alterar a original.
//!
//! - Endereços IP trocados de forma consistente e preservando prefixo (a
//!   mesma rede continua a mesma rede), mantendo a faixa privada.
//! - MACs trocados de forma consistente, com o fabricante (OUI) opcional.
//! - Conteúdo: por padrão, só cabeçalhos. Na opção `protocolos`, ficam DNS,
//!   DHCP e o handshake TLS (sem certificado), com nomes internos mascarados
//!   no mesmo tamanho e endereços dentro deles também trocados.
//! - Pacotes que não sabemos reescrever com segurança são removidos.
//!
//! A troca usa uma chave de 128 bits (SipHash-2-4). Sem a chave, a
//! correspondência não se desfaz; com a mesma chave, capturas diferentes
//! recebem a mesma troca.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::bytes::{mac_texto, u16be, u32be, u8_em};
use crate::captura::{ErroCaptura, LeitorCaptura, PacoteBruto};
use crate::decodificacao::escopo;

#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Enderecos {
    /// Só os da rede observada (privados, link-local, CGNAT).
    Internos,
    Todos,
    Nenhum,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Conteudo {
    /// Corta tudo depois do cabeçalho de transporte.
    Cabecalhos,
    /// Mantém DNS, DHCP e handshake TLS, mascarados.
    Protocolos,
}

#[derive(Deserialize, Clone)]
pub struct Opcoes {
    /// 32 caracteres hexadecimais (128 bits).
    pub chave: String,
    pub enderecos: Enderecos,
    pub conteudo: Conteudo,
    #[serde(default)]
    pub manter_fabricante: bool,
    #[serde(default)]
    pub deslocar_horarios: bool,
    /// Nomes que a análise já sabe que são da rede (hostnames, DHCP...).
    #[serde(default)]
    pub nomes_internos: Vec<String>,
    /// Domínios informados pela pessoa (ex.: empresa.com.br).
    #[serde(default)]
    pub dominios_internos: Vec<String>,
}

#[derive(Serialize, Default)]
pub struct RelatorioAnonimizacao {
    pub pacotes: u64,
    pub pacotes_removidos: u64,
    pub pacotes_cortados: u64,
    pub bytes_removidos: u64,
    pub enderecos_trocados: usize,
    pub macs_trocados: usize,
    pub nomes_mascarados: usize,
    /// O que continua podendo identificar alguém, em códigos.
    pub riscos: Vec<&'static str>,
    pub erro: Option<ErroCaptura>,
}

/// Sufixos que, por convenção, só existem dentro de uma rede.
const SUFIXOS_INTERNOS: &[&str] = &[
    "local", "lan", "home", "corp", "internal", "intranet", "localdomain", "home.arpa", "ad", "private", "domain",
];

/// 2000-01-01 00:00:00 UTC, em microssegundos: início das capturas deslocadas.
const INICIO_DESLOCADO_US: i64 = 946_684_800_000_000;

pub struct Anonimizador {
    leitor: LeitorCaptura,
    e: Estado,
}

struct Estado {
    chave: [u64; 2],
    op: Opcoes,
    nomes_internos: HashSet<String>,
    ips: HashMap<IpAddr, IpAddr>,
    macs: HashMap<[u8; 6], [u8; 6]>,
    nomes: BTreeMap<String, String>,
    interfaces: Vec<u16>,
    saida: Vec<u8>,
    deslocamento: Option<i64>,
    r: RelatorioAnonimizacao,
}

impl Anonimizador {
    pub fn new(op: Opcoes) -> Result<Self, &'static str> {
        let chave = ler_chave(&op.chave).ok_or("chave_invalida")?;
        let nomes_internos = op.nomes_internos.iter().map(|n| normalizar(n)).collect();
        let mut e = Estado {
            chave,
            op,
            nomes_internos,
            ips: HashMap::new(),
            macs: HashMap::new(),
            nomes: BTreeMap::new(),
            interfaces: Vec::new(),
            saida: Vec::new(),
            deslocamento: None,
            r: RelatorioAnonimizacao::default(),
        };
        e.escrever_shb();
        Ok(Self { leitor: LeitorCaptura::new(), e })
    }

    /// Processa um bloco da captura original e devolve os bytes novos da
    /// captura anonimizada (pode ser vazio).
    pub fn alimentar(&mut self, dados: &[u8]) -> Result<Vec<u8>, ErroCaptura> {
        let Anonimizador { leitor, e } = self;
        let r = leitor.alimentar(dados, |p| e.pacote(p));
        if let Err(erro) = &r {
            e.r.erro = Some(erro.clone());
        }
        r.map(|_| std::mem::take(&mut self.e.saida))
    }

    /// Encerra e devolve o resto da saída e o relatório.
    pub fn finalizar(mut self) -> (Vec<u8>, RelatorioAnonimizacao) {
        let e = &mut self.e;
        e.r.enderecos_trocados = e.ips.iter().filter(|(a, b)| a != b).count();
        e.r.macs_trocados = e.macs.iter().filter(|(a, b)| a != b).count();
        e.r.nomes_mascarados = e.nomes.len();
        let mut riscos = vec!["tamanhos_e_tempos"];
        if !e.op.deslocar_horarios {
            riscos.push("horarios_reais");
        }
        if e.op.enderecos == Enderecos::Internos {
            riscos.push("ips_externos");
        }
        if e.op.enderecos == Enderecos::Nenhum {
            riscos.push("ips_originais");
        }
        if e.op.manter_fabricante {
            riscos.push("fabricante");
        }
        if e.op.conteudo == Conteudo::Protocolos {
            riscos.push("nomes_publicos");
        }
        e.r.riscos = riscos;
        (std::mem::take(&mut e.saida), std::mem::take(&mut e.r))
    }

    /// Tabela de correspondência (original → anonimizado), em CSV. É
    /// sensível: quem tem a tabela desfaz a anonimização.
    pub fn tabela(&self) -> String {
        let mut s = String::from("tipo,original,anonimizado\n");
        let mut ips: Vec<_> = self.e.ips.iter().filter(|(a, b)| a != b).collect();
        ips.sort();
        for (a, b) in ips {
            s.push_str(&format!("ip,{a},{b}\n"));
        }
        let mut macs: Vec<_> = self.e.macs.iter().filter(|(a, b)| a != b).collect();
        macs.sort();
        for (a, b) in macs {
            s.push_str(&format!("mac,{},{}\n", mac_texto(a), mac_texto(b)));
        }
        for (a, b) in &self.e.nomes {
            s.push_str(&format!("nome,{a},{b}\n"));
        }
        s
    }
}

fn ler_chave(hex: &str) -> Option<[u64; 2]> {
    let hex = hex.trim();
    if hex.len() != 32 || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some([u64::from_str_radix(&hex[..16], 16).ok()?, u64::from_str_radix(&hex[16..], 16).ok()?])
}

fn normalizar(nome: &str) -> String {
    nome.trim().trim_end_matches('.').to_ascii_lowercase()
}

// ---------- SipHash-2-4 ----------

fn rodada(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13) ^ v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16) ^ v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21) ^ v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17) ^ v[2];
    v[2] = v[2].rotate_left(32);
}

fn sip(k: &[u64; 2], dados: &[u8]) -> u64 {
    let mut v = [
        k[0] ^ 0x736f_6d65_7073_6575,
        k[1] ^ 0x646f_7261_6e64_6f6d,
        k[0] ^ 0x6c79_6765_6e65_7261,
        k[1] ^ 0x7465_6462_7974_6573,
    ];
    let mut blocos = dados.chunks_exact(8);
    for b in &mut blocos {
        let m = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
        v[3] ^= m;
        rodada(&mut v);
        rodada(&mut v);
        v[0] ^= m;
    }
    let mut ultimo = (dados.len() as u64 & 0xff) << 56;
    for (i, &c) in blocos.remainder().iter().enumerate() {
        ultimo |= (c as u64) << (8 * i);
    }
    v[3] ^= ultimo;
    rodada(&mut v);
    rodada(&mut v);
    v[0] ^= ultimo;
    v[2] ^= 0xff;
    for _ in 0..4 {
        rodada(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

// ---------- escrita pcapng ----------

fn bloco(saida: &mut Vec<u8>, tipo: u32, corpo: &[u8]) {
    let enchimento = (4 - corpo.len() % 4) % 4;
    let tamanho = (12 + corpo.len() + enchimento) as u32;
    saida.extend_from_slice(&tipo.to_le_bytes());
    saida.extend_from_slice(&tamanho.to_le_bytes());
    saida.extend_from_slice(corpo);
    saida.extend(std::iter::repeat_n(0u8, enchimento));
    saida.extend_from_slice(&tamanho.to_le_bytes());
}

impl Estado {
    fn escrever_shb(&mut self) {
        let mut corpo = Vec::with_capacity(16);
        corpo.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
        corpo.extend_from_slice(&1u16.to_le_bytes());
        corpo.extend_from_slice(&0u16.to_le_bytes());
        corpo.extend_from_slice(&(-1i64).to_le_bytes());
        bloco(&mut self.saida, 0x0A0D_0D0A, &corpo);
    }

    fn interface(&mut self, enlace: u16) -> u32 {
        if let Some(i) = self.interfaces.iter().position(|&e| e == enlace) {
            return i as u32;
        }
        let mut corpo = Vec::with_capacity(8);
        corpo.extend_from_slice(&enlace.to_le_bytes());
        corpo.extend_from_slice(&0u16.to_le_bytes());
        corpo.extend_from_slice(&0u32.to_le_bytes());
        bloco(&mut self.saida, 1, &corpo);
        self.interfaces.push(enlace);
        (self.interfaces.len() - 1) as u32
    }

    fn pacote(&mut self, p: PacoteBruto<'_>) {
        self.r.pacotes += 1;
        let Some(dados) = self.reescrever(p.enlace, p.dados) else {
            self.r.pacotes_removidos += 1;
            self.r.bytes_removidos += p.dados.len() as u64;
            return;
        };
        if dados.len() < p.dados.len() {
            self.r.pacotes_cortados += 1;
            self.r.bytes_removidos += (p.dados.len() - dados.len()) as u64;
        }

        let mut ts = p.ts_us as i64;
        if self.op.deslocar_horarios {
            let d = *self.deslocamento.get_or_insert(INICIO_DESLOCADO_US - ts);
            ts = (ts + d).max(0);
        }
        let itf = self.interface(p.enlace);
        let mut corpo = Vec::with_capacity(20 + dados.len());
        corpo.extend_from_slice(&itf.to_le_bytes());
        corpo.extend_from_slice(&(((ts as u64) >> 32) as u32).to_le_bytes());
        corpo.extend_from_slice(&((ts as u64) as u32).to_le_bytes());
        corpo.extend_from_slice(&(dados.len() as u32).to_le_bytes());
        corpo.extend_from_slice(&p.tamanho_original.max(dados.len() as u32).to_le_bytes());
        corpo.extend_from_slice(&dados);
        bloco(&mut self.saida, 6, &corpo);
    }

    // ---------- trocas ----------

    fn mac(&mut self, m: [u8; 6]) -> [u8; 6] {
        // Broadcast, multicast e zerado ficam como estão.
        if m[0] & 1 == 1 || m == [0; 6] {
            return m;
        }
        let (chave, manter) = (self.chave, self.op.manter_fabricante);
        *self.macs.entry(m).or_insert_with(|| {
            let h = sip(&chave, &[&[1u8][..], &m[..]].concat()).to_le_bytes();
            if manter {
                [m[0], m[1], m[2], h[0], h[1], h[2]]
            } else {
                // Unicast e administrado localmente: não colide com fabricante real.
                [(h[0] & 0xfc) | 0x02, h[1], h[2], h[3], h[4], h[5]]
            }
        })
    }

    fn trocar_mac_em(&mut self, b: &mut [u8], i: usize) {
        if let Some(s) = b.get_mut(i..i + 6) {
            let novo = self.mac(<[u8; 6]>::try_from(&*s).unwrap_or([0; 6]));
            s.copy_from_slice(&novo);
        }
    }

    fn ip(&mut self, ip: IpAddr) -> IpAddr {
        let esc = escopo(&ip);
        let trocar = match self.op.enderecos {
            Enderecos::Nenhum => false,
            Enderecos::Internos => esc == "interno",
            Enderecos::Todos => matches!(esc, "interno" | "externo" | "reservado"),
        };
        if !trocar || ip.is_loopback() || ip.is_unspecified() {
            return ip;
        }
        let chave = self.chave;
        *self.ips.entry(ip).or_insert_with(|| match ip {
            IpAddr::V4(v) => {
                let n = u32::from(v);
                let o = v.octets();
                // Bits que ficam: a faixa privada continua privada.
                let fixos = match o {
                    [10, ..] => 8,
                    [172, b, ..] if (16..32).contains(&b) => 12,
                    [192, 168, ..] | [169, 254, ..] => 16,
                    [100, b, ..] if (64..128).contains(&b) => 10,
                    _ => 0,
                };
                let mut r = n;
                for i in fixos..32u32 {
                    let prefixo = if i == 0 { 0 } else { n >> (32 - i) };
                    let mut d = [4u8, i as u8, 0, 0, 0, 0];
                    d[2..].copy_from_slice(&prefixo.to_be_bytes());
                    r ^= ((sip(&chave, &d) & 1) as u32) << (31 - i);
                }
                IpAddr::V4(Ipv4Addr::from(r))
            }
            IpAddr::V6(v) => {
                let n = u128::from(v);
                let s = v.segments();
                let fixos = if s[0] & 0xffc0 == 0xfe80 {
                    64
                } else if s[0] & 0xfe00 == 0xfc00 {
                    8
                } else {
                    0
                };
                let mut r = n;
                for i in fixos..128u32 {
                    let prefixo = if i == 0 { 0 } else { n >> (128 - i) };
                    let mut d = [0u8; 18];
                    d[0] = 6;
                    d[1] = i as u8;
                    d[2..].copy_from_slice(&prefixo.to_be_bytes());
                    r ^= ((sip(&chave, &d) & 1) as u128) << (127 - i);
                }
                IpAddr::V6(Ipv6Addr::from(r))
            }
        })
    }

    fn trocar_v4_em(&mut self, b: &mut [u8], i: usize) {
        if let Some(s) = b.get_mut(i..i + 4) {
            let atual = Ipv4Addr::new(s[0], s[1], s[2], s[3]);
            if let IpAddr::V4(novo) = self.ip(IpAddr::V4(atual)) {
                s.copy_from_slice(&novo.octets());
            }
        }
    }

    fn trocar_v6_em(&mut self, b: &mut [u8], i: usize) {
        if let Some(s) = b.get_mut(i..i + 16) {
            let atual = Ipv6Addr::from(<[u8; 16]>::try_from(&*s).unwrap_or([0; 16]));
            if let IpAddr::V6(novo) = self.ip(IpAddr::V6(atual)) {
                s.copy_from_slice(&novo.octets());
            }
        }
    }

    fn pseudonimo(&self, rotulo: &[u8]) -> Vec<u8> {
        const LETRAS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
        const ALFABETO: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let base = rotulo.to_ascii_lowercase();
        let mut saida = Vec::with_capacity(rotulo.len());
        let mut h = 0u64;
        for i in 0..rotulo.len() {
            if i % 10 == 0 {
                h = sip(&self.chave, &[&[2u8, (i / 10) as u8][..], &base[..]].concat());
            }
            let alfabeto = if i == 0 { LETRAS } else { ALFABETO };
            saida.push(alfabeto[(h % alfabeto.len() as u64) as usize]);
            h /= alfabeto.len() as u64;
        }
        saida
    }

    fn interno(&self, nome: &str) -> bool {
        let n = normalizar(nome);
        if n.is_empty() || n == "." {
            return false;
        }
        let sufixo = |s: &str| n == s || n.ends_with(&format!(".{s}"));
        !n.contains('.')
            || self.nomes_internos.contains(&n)
            || SUFIXOS_INTERNOS.iter().any(|s| sufixo(s))
            || self.op.dominios_internos.iter().map(|d| normalizar(d)).any(|d| !d.is_empty() && sufixo(&d))
            || reverso_interno(&n)
    }

    /// Quantos rótulos do fim do nome ficam visíveis.
    fn rotulos_mantidos(nome: &str) -> usize {
        if nome.ends_with(".arpa") {
            2
        } else {
            1
        }
    }

    fn registrar_nome(&mut self, nome: &str) {
        let n = normalizar(nome);
        if self.nomes.contains_key(&n) {
            return;
        }
        let rotulos: Vec<&str> = n.split('.').collect();
        let manter = Self::rotulos_mantidos(&n).min(rotulos.len().saturating_sub(1));
        let novo: Vec<String> = rotulos
            .iter()
            .enumerate()
            .map(|(i, r)| {
                if i + manter < rotulos.len() {
                    String::from_utf8_lossy(&self.pseudonimo(r.as_bytes())).into_owned()
                } else {
                    (*r).to_owned()
                }
            })
            .collect();
        self.nomes.insert(n, novo.join("."));
    }

    /// Mascara, no lugar, os rótulos de um nome (mesmo tamanho).
    fn mascarar_rotulos(&mut self, b: &mut [u8], rotulos: &[(usize, usize)], total: usize, nome: &str) {
        let manter = Self::rotulos_mantidos(nome).min(total.saturating_sub(1));
        for (j, &(ini, tam)) in rotulos.iter().enumerate() {
            if j + manter < total {
                if let Some(s) = b.get_mut(ini..ini + tam) {
                    let novo = self.pseudonimo(s);
                    s.copy_from_slice(&novo);
                }
            }
        }
        self.registrar_nome(nome);
    }

    // ---------- reescrita do pacote ----------

    fn reescrever(&mut self, enlace: u16, original: &[u8]) -> Option<Vec<u8>> {
        let mut b = original.to_vec();
        let (tipo, l3) = match enlace {
            1 => {
                self.trocar_mac_em(&mut b, 0);
                self.trocar_mac_em(&mut b, 6);
                let mut tipo = u16be(&b, 12)?;
                let mut i = 14;
                let mut etiquetas = 0;
                while matches!(tipo, 0x8100 | 0x88a8 | 0x9100) && etiquetas < 4 {
                    tipo = u16be(&b, i + 2)?;
                    i += 4;
                    etiquetas += 1;
                }
                (tipo, i)
            }
            113 => {
                if u16be(&b, 4)? == 6 {
                    self.trocar_mac_em(&mut b, 6);
                }
                (u16be(&b, 14)?, 16)
            }
            276 => {
                if u8_em(&b, 11)? == 6 {
                    self.trocar_mac_em(&mut b, 12);
                }
                (u16be(&b, 0)?, 20)
            }
            0 | 108 => {
                let bruto = b.get(0..4)?;
                let le = u32::from_le_bytes(bruto.try_into().ok()?);
                let familia = if enlace == 108 || le > 0xff { u32::from_be_bytes(bruto.try_into().ok()?) } else { le };
                match familia {
                    2 => (0x0800, 4),
                    24 | 28 | 30 => (0x86dd, 4),
                    _ => return None,
                }
            }
            12 | 14 | 101 => match u8_em(&b, 0)? >> 4 {
                4 => (0x0800, 0),
                6 => (0x86dd, 0),
                _ => return None,
            },
            228 => (0x0800, 0),
            229 => (0x86dd, 0),
            _ => return None,
        };
        match tipo {
            0x0800 => self.ipv4(&mut b, l3)?,
            0x86dd => self.ipv6(&mut b, l3)?,
            0x0806 => self.arp(&mut b, l3)?,
            // Protocolo de rede que não sabemos reescrever: fica de fora.
            _ => return None,
        }
        Some(b)
    }

    fn arp(&mut self, b: &mut Vec<u8>, i: usize) -> Option<()> {
        if u16be(b, i + 2)? != 0x0800 || u8_em(b, i + 4)? != 6 || u8_em(b, i + 5)? != 4 {
            return None;
        }
        self.trocar_mac_em(b, i + 8);
        self.trocar_v4_em(b, i + 14);
        self.trocar_mac_em(b, i + 18);
        self.trocar_v4_em(b, i + 24);
        b.truncate(i + 28);
        Some(())
    }

    fn ipv4(&mut self, b: &mut Vec<u8>, i: usize) -> Option<()> {
        let v = u8_em(b, i)?;
        let cab = (v & 0x0f) as usize * 4;
        if v >> 4 != 4 || cab < 20 || b.len() < i + cab {
            return None;
        }
        self.trocar_v4_em(b, i + 12);
        self.trocar_v4_em(b, i + 16);
        // Opções IP (record route, timestamp) podem carregar endereços: viram NOP.
        for byte in &mut b[i + 20..i + cab] {
            *byte = 1;
        }
        b[i + 10] = 0;
        b[i + 11] = 0;
        let soma = soma_verificacao(&b[i..i + cab]);
        b[i + 10..i + 12].copy_from_slice(&soma.to_be_bytes());

        let fragmento = u16be(b, i + 6)? & 0x1fff != 0;
        let protocolo = u8_em(b, i + 9)?;
        // Limita ao tamanho declarado (Ethernet completa quadros curtos).
        let total = u16be(b, i + 2)? as usize;
        if total >= cab && i + total < b.len() {
            b.truncate(i + total);
        }
        if fragmento {
            b.truncate(i + cab);
            return Some(());
        }
        self.transporte(b, i + cab, protocolo)
    }

    fn ipv6(&mut self, b: &mut Vec<u8>, i: usize) -> Option<()> {
        if u8_em(b, i)? >> 4 != 6 || b.len() < i + 40 {
            return None;
        }
        self.trocar_v6_em(b, i + 8);
        self.trocar_v6_em(b, i + 24);
        let mut proximo = u8_em(b, i + 6)?;
        let mut p = i + 40;
        for _ in 0..8 {
            match proximo {
                0 | 60 => {
                    let n = u8_em(b, p)?;
                    p += (u8_em(b, p + 1)? as usize + 1) * 8;
                    proximo = n;
                }
                // Cabeçalho de roteamento carrega endereços: pacote fora.
                43 => return None,
                44 => {
                    let n = u8_em(b, p)?;
                    if u16be(b, p + 2)? >> 3 != 0 {
                        b.truncate(p.min(b.len()));
                        return Some(());
                    }
                    p += 8;
                    proximo = n;
                }
                51 => {
                    let n = u8_em(b, p)?;
                    p += (u8_em(b, p + 1)? as usize + 2) * 4;
                    proximo = n;
                }
                _ => break,
            }
        }
        if p > b.len() {
            return None;
        }
        self.transporte(b, p, proximo)
    }

    fn transporte(&mut self, b: &mut Vec<u8>, p: usize, protocolo: u8) -> Option<()> {
        let protocolos = self.op.conteudo == Conteudo::Protocolos;
        match protocolo {
            6 => {
                let cab = (u8_em(b, p + 12)? >> 4) as usize * 4;
                let (po, pd) = (u16be(b, p)?, u16be(b, p + 2)?);
                if b.len() < p + cab.max(20) {
                    b.truncate(p);
                    return Some(());
                }
                // A soma de verificação deixaria de bater: fica zerada.
                b[p + 16] = 0;
                b[p + 17] = 0;
                let q = p + cab.max(20);
                if protocolos && q < b.len() {
                    if po == 53 || pd == 53 {
                        if q + 2 <= b.len() && self.dns(b, q + 2).is_some() {
                            return Some(());
                        }
                    } else if b[q] == 0x16 && self.tls(b, q).is_some() {
                        return Some(());
                    }
                }
                b.truncate(q);
            }
            17 => {
                if b.len() < p + 8 {
                    b.truncate(p);
                    return Some(());
                }
                let (po, pd) = (u16be(b, p)?, u16be(b, p + 2)?);
                b[p + 6] = 0;
                b[p + 7] = 0;
                let q = p + 8;
                let porta = |x: u16| po == x || pd == x;
                if protocolos {
                    if porta(53) || porta(5353) || porta(5355) {
                        if self.dns(b, q).is_some() {
                            return Some(());
                        }
                    } else if porta(67) && porta(68) && self.dhcp(b, q).is_some() {
                        return Some(());
                    }
                }
                b.truncate(q);
            }
            // ICMP de erro carrega o cabeçalho IP original: fica só o início.
            1 | 58 => b.truncate((p + 8).min(b.len())),
            _ => b.truncate(p),
        }
        Some(())
    }

    // ---------- DNS, DHCP e TLS ----------

    /// Mascara nomes internos e troca endereços dentro de uma mensagem DNS.
    /// `None` quando não dá para ler com segurança: o chamador corta o conteúdo.
    fn dns(&mut self, b: &mut Vec<u8>, q: usize) -> Option<()> {
        let original = b.get(q..)?.to_vec();
        let m = &original[..];
        let contagem = |i| u16be(m, i).map(|v| v as usize);
        let (qd, an, ns, ar) = (contagem(4)?, contagem(6)?, contagem(8)?, contagem(10)?);
        if qd > 16 || an + ns + ar > 512 {
            return None;
        }
        let mut nomes: Vec<(Vec<(usize, usize)>, usize, String)> = Vec::new();
        let mut enderecos: Vec<(usize, usize)> = Vec::new();
        let mut i = 12;
        for _ in 0..qd {
            let (rotulos, total, nome, prox) = ler_nome(m, i)?;
            nomes.push((rotulos, total, nome));
            i = prox + 4;
        }
        for _ in 0..an + ns + ar {
            let (rotulos, total, nome, p) = ler_nome(m, i)?;
            nomes.push((rotulos, total, nome));
            let tipo = u16be(m, p)?;
            let tam = u16be(m, p + 8)? as usize;
            let r = p + 10;
            if r + tam > m.len() {
                return None;
            }
            // Nomes dentro do dado do registro (CNAME, PTR, NS, MX, SRV, SOA).
            let posicoes: Vec<usize> = match tipo {
                1 if tam == 4 => {
                    enderecos.push((r, 4));
                    vec![]
                }
                28 if tam == 16 => {
                    enderecos.push((r, 16));
                    vec![]
                }
                2 | 5 | 12 => vec![r],
                15 => vec![r + 2],
                33 => vec![r + 6],
                6 => vec![r, ler_nome(m, r)?.3],
                _ => vec![],
            };
            for pos in posicoes {
                let (rotulos, total, nome, _) = ler_nome(m, pos)?;
                nomes.push((rotulos, total, nome));
            }
            i = r + tam;
        }

        // Um nome que resolve para endereço interno também é interno.
        let resolve_para_dentro = enderecos.iter().any(|&(pos, tam)| {
            let ip = if tam == 4 {
                IpAddr::V4(Ipv4Addr::new(m[pos], m[pos + 1], m[pos + 2], m[pos + 3]))
            } else {
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&m[pos..pos + 16]).unwrap_or([0; 16])))
            };
            escopo(&ip) == "interno"
        });
        let alvo = &mut b[q..];
        for (rotulos, total, nome) in &nomes {
            if self.interno(nome) || (resolve_para_dentro && nome != ".") {
                self.mascarar_rotulos(alvo, rotulos, *total, nome);
            }
        }
        for (pos, tam) in enderecos {
            if tam == 4 {
                self.trocar_v4_em(alvo, pos);
            } else {
                self.trocar_v6_em(alvo, pos);
            }
        }
        Some(())
    }

    fn dhcp(&mut self, b: &mut Vec<u8>, q: usize) -> Option<()> {
        if u32be(b, q + 236)? != 0x6382_5363 {
            return None;
        }
        for campo in [12, 16, 20, 24] {
            self.trocar_v4_em(b, q + campo);
        }
        if u8_em(b, q + 2)? == 6 {
            self.trocar_mac_em(b, q + 28);
        }
        // sname e file podem ter nomes de servidor e caminhos.
        b.get_mut(q + 44..q + 236)?.fill(0);
        let mut i = q + 240;
        while let Some(codigo) = u8_em(b, i) {
            match codigo {
                0 => {
                    i += 1;
                    continue;
                }
                255 => break,
                _ => {}
            }
            let tam = u8_em(b, i + 1)? as usize;
            let v = i + 2;
            if v + tam > b.len() {
                return None;
            }
            match codigo {
                // nome do host e domínio: mascarados no mesmo tamanho
                12 | 15 => {
                    let nome = String::from_utf8_lossy(&b[v..v + tam]).into_owned();
                    let pedacos = rotulos_texto(&b[v..v + tam], v);
                    let total = pedacos.len();
                    // Num hostname puro nada fica visível.
                    let manter_nada = codigo == 12;
                    for (j, (ini, t)) in pedacos.iter().enumerate() {
                        if manter_nada || j + 1 < total {
                            let novo = self.pseudonimo(&b[*ini..ini + t]);
                            b[*ini..ini + t].copy_from_slice(&novo);
                        }
                    }
                    self.registrar_nome(&nome);
                }
                // FQDN do cliente: 3 bytes de flags e o nome
                81 if tam > 3 => {
                    let nome = String::from_utf8_lossy(&b[v + 3..v + tam]).into_owned();
                    for (ini, t) in rotulos_texto(&b[v + 3..v + tam], v + 3) {
                        let novo = self.pseudonimo(&b[ini..ini + t]);
                        b[ini..ini + t].copy_from_slice(&novo);
                    }
                    self.registrar_nome(&nome);
                }
                // identificador do cliente: costuma ser o MAC
                61 => {
                    if tam == 7 && b[v] == 1 {
                        self.trocar_mac_em(b, v + 1);
                    } else {
                        b[v..v + tam].fill(0);
                    }
                }
                // listas de IPv4: pedido, servidor, roteador, DNS, broadcast
                50 | 54 | 3 | 6 | 28 if tam % 4 == 0 => {
                    for k in (0..tam).step_by(4) {
                        self.trocar_v4_em(b, v + k);
                    }
                }
                // específico do fabricante: pode ter qualquer coisa
                43 => b[v..v + tam].fill(0),
                _ => {}
            }
            i = v + tam;
        }
        Some(())
    }

    /// Mantém só a mensagem ClientHello ou ServerHello do primeiro registro
    /// (o certificado, que tem nomes, fica de fora) e mascara o SNI interno.
    fn tls(&mut self, b: &mut Vec<u8>, q: usize) -> Option<()> {
        if u8_em(b, q + 1)? != 3 {
            return None;
        }
        let tipo = u8_em(b, q + 5)?;
        if tipo != 1 && tipo != 2 {
            return None;
        }
        let tam_hs = (u32be(b, q + 5)? & 0x00ff_ffff) as usize;
        let fim = (q + 9 + tam_hs).min(b.len());
        // Registro passa a conter só esta mensagem.
        let novo_tam = (fim - q - 5) as u16;
        b[q + 3..q + 5].copy_from_slice(&novo_tam.to_be_bytes());
        b.truncate(fim);

        if tipo == 1 {
            if let Some((ini, tam)) = sni(b, q + 9) {
                let nome = String::from_utf8_lossy(&b[ini..ini + tam]).into_owned();
                if self.interno(&nome) {
                    let pedacos = rotulos_texto(&b[ini..ini + tam], ini);
                    let total = pedacos.len();
                    let manter = Self::rotulos_mantidos(&nome).min(total.saturating_sub(1));
                    for (j, (i, t)) in pedacos.iter().enumerate() {
                        if j + manter < total {
                            let novo = self.pseudonimo(&b[*i..i + t]);
                            b[*i..i + t].copy_from_slice(&novo);
                        }
                    }
                    self.registrar_nome(&nome);
                }
            }
        }
        Some(())
    }
}

/// Posições (início, tamanho) dos rótulos de um nome em texto (a.b.c).
fn rotulos_texto(texto: &[u8], base: usize) -> Vec<(usize, usize)> {
    let mut saida = Vec::new();
    let mut ini = 0;
    for (i, &c) in texto.iter().enumerate() {
        if c == b'.' {
            if i > ini {
                saida.push((base + ini, i - ini));
            }
            ini = i + 1;
        }
    }
    if texto.len() > ini {
        saida.push((base + ini, texto.len() - ini));
    }
    saida
}

/// Lê um nome DNS. Devolve os rótulos que estão neste ponto da mensagem (antes
/// do primeiro ponteiro), o total de rótulos do nome completo, o nome e a
/// posição logo depois dele.
fn ler_nome(m: &[u8], mut i: usize) -> Option<(Vec<(usize, usize)>, usize, String, usize)> {
    let mut proprios = Vec::new();
    let mut partes: Vec<String> = Vec::new();
    let mut depois = None;
    let mut saltos = 0;
    loop {
        let tam = u8_em(m, i)? as usize;
        if tam & 0xc0 == 0xc0 {
            depois.get_or_insert(i + 2);
            saltos += 1;
            if saltos > 16 {
                return None;
            }
            i = (u16be(m, i)? & 0x3fff) as usize;
            continue;
        }
        if tam & 0xc0 != 0 {
            return None;
        }
        if tam == 0 {
            depois.get_or_insert(i + 1);
            break;
        }
        let rotulo = m.get(i + 1..i + 1 + tam)?;
        if depois.is_none() {
            proprios.push((i + 1, tam));
        }
        partes.push(String::from_utf8_lossy(rotulo).to_ascii_lowercase());
        if partes.len() > 127 {
            return None;
        }
        i += 1 + tam;
    }
    let total = partes.len();
    let nome = if partes.is_empty() { ".".to_owned() } else { partes.join(".") };
    Some((proprios, total, nome, depois?))
}

/// Posição do nome no SNI de um ClientHello (corpo começando na versão).
fn sni(b: &[u8], corpo: usize) -> Option<(usize, usize)> {
    let mut i = corpo + 34;
    i += 1 + u8_em(b, i)? as usize;
    i += 2 + u16be(b, i)? as usize;
    i += 1 + u8_em(b, i)? as usize;
    let fim = (i + 2 + u16be(b, i)? as usize).min(b.len());
    i += 2;
    while i + 4 <= fim {
        let tipo = u16be(b, i)?;
        let tam = u16be(b, i + 2)? as usize;
        if tipo == 0 {
            let n = u16be(b, i + 7)? as usize;
            let ini = i + 9;
            return (ini + n <= b.len()).then_some((ini, n));
        }
        i += 4 + tam;
    }
    None
}

fn reverso_interno(n: &str) -> bool {
    let Some(resto) = n.strip_suffix(".in-addr.arpa") else { return false };
    let partes: Vec<u8> = resto.split('.').rev().filter_map(|p| p.parse().ok()).collect();
    if partes.len() != 4 {
        return false;
    }
    escopo(&IpAddr::V4(Ipv4Addr::new(partes[0], partes[1], partes[2], partes[3]))) == "interno"
}

fn soma_verificacao(cabecalho: &[u8]) -> u16 {
    let mut soma: u32 = 0;
    for par in cabecalho.chunks(2) {
        soma += u32::from(u16::from_be_bytes([par[0], *par.get(1).unwrap_or(&0)]));
    }
    while soma > 0xffff {
        soma = (soma & 0xffff) + (soma >> 16);
    }
    !(soma as u16)
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn siphash_vetores_oficiais() {
        let k = [u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7]), u64::from_le_bytes([8, 9, 10, 11, 12, 13, 14, 15])];
        assert_eq!(sip(&k, &[]), 0x726f_db47_dd0e_0e31);
        let m: Vec<u8> = (0..15).collect();
        assert_eq!(sip(&k, &m), 0xa129_ca61_49be_45e5);
    }

    fn estado(enderecos: Enderecos) -> Anonimizador {
        Anonimizador::new(Opcoes {
            chave: "000102030405060708090a0b0c0d0e0f".into(),
            enderecos,
            conteudo: Conteudo::Protocolos,
            manter_fabricante: false,
            deslocar_horarios: false,
            nomes_internos: vec!["desktop-fin01".into()],
            dominios_internos: vec!["empresa.com.br".into()],
        })
        .unwrap()
    }

    #[test]
    fn prefixo_preservado_e_faixa_privada_mantida() {
        let mut a = estado(Enderecos::Internos);
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let x = a.e.ip(ip("10.0.0.5"));
        let y = a.e.ip(ip("10.0.0.8"));
        let z = a.e.ip(ip("10.9.0.1"));
        assert_ne!(x, ip("10.0.0.5"));
        assert!(x.to_string().starts_with("10."));
        // Mesma /24 continua na mesma /24; rede diferente sai diferente.
        let pref = |i: IpAddr| i.to_string().rsplit_once('.').unwrap().0.to_owned();
        assert_eq!(pref(x), pref(y));
        assert_ne!(pref(x), pref(z));
        // Consistente e externo mantido.
        assert_eq!(a.e.ip(ip("10.0.0.5")), x);
        assert_eq!(a.e.ip(ip("8.8.8.8")), ip("8.8.8.8"));
        assert_eq!(a.e.ip(ip("224.0.0.251")), ip("224.0.0.251"));
    }

    #[test]
    fn nomes_internos() {
        let a = estado(Enderecos::Internos);
        for n in ["desktop-fin01", "intranet.local", "srv.empresa.com.br", "fileserver", "5.0.0.10.in-addr.arpa"] {
            assert!(a.e.interno(n), "{n}");
        }
        for n in ["www.google.com", "cdn-sync.top", "8.8.8.8.in-addr.arpa"] {
            assert!(!a.e.interno(n), "{n}");
        }
        let p = a.e.pseudonimo(b"intranet");
        assert_eq!(p.len(), 8);
        assert_ne!(p, b"intranet");
        assert_eq!(p, a.e.pseudonimo(b"INTRANET"));
    }

    #[test]
    fn chave_precisa_ter_128_bits() {
        let mut op = estado(Enderecos::Internos).e.op.clone();
        op.chave = "abc".into();
        assert!(Anonimizador::new(op).is_err());
    }
}
