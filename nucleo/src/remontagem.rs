//! Remontagem do começo de uma direção de um fluxo TCP, pela ordem do número
//! de sequência. Só até um limite pequeno: serve para ler handshakes e
//! cabeçalhos que atravessam vários segmentos, não para guardar a conversa.

pub struct Direcao {
    base: u32,
    dados: Vec<u8>,
    /// Segmentos que chegaram antes do buraco que os precede.
    pendentes: Vec<(usize, Vec<u8>)>,
    limite: usize,
}

const MAX_PENDENTES: usize = 32;

impl Direcao {
    pub fn new(seq: u32, limite: usize) -> Self {
        Self { base: seq, dados: Vec::new(), pendentes: Vec::new(), limite }
    }

    pub fn dados(&self) -> &[u8] {
        &self.dados
    }

    pub fn cheia(&self) -> bool {
        self.dados.len() >= self.limite
    }

    /// Acrescenta um segmento. Devolve se o trecho contínuo cresceu.
    pub fn segmento(&mut self, seq: u32, carga: &[u8]) -> bool {
        let deslocamento = seq.wrapping_sub(self.base) as usize;
        // Retransmissão de algo anterior ao começo: nada a fazer.
        if deslocamento > 1 << 30 || carga.is_empty() {
            return false;
        }
        let cresceu = self.encaixar(deslocamento, carga);
        if !cresceu && deslocamento > self.dados.len() && deslocamento < self.limite && self.pendentes.len() < MAX_PENDENTES {
            let fim = carga.len().min(self.limite - deslocamento);
            self.pendentes.push((deslocamento, carga[..fim].to_vec()));
        }
        if cresceu {
            // Os pendentes que agora encostam no fim entram também.
            loop {
                let Some(i) = self.pendentes.iter().position(|(d, _)| *d <= self.dados.len()) else { break };
                let (d, c) = self.pendentes.swap_remove(i);
                self.encaixar(d, &c);
            }
        }
        cresceu
    }

    fn encaixar(&mut self, deslocamento: usize, carga: &[u8]) -> bool {
        if deslocamento > self.dados.len() || self.cheia() {
            return false;
        }
        let ja_tem = self.dados.len() - deslocamento;
        if ja_tem >= carga.len() {
            return false;
        }
        let novo = &carga[ja_tem..];
        let cabe = novo.len().min(self.limite - self.dados.len());
        self.dados.extend_from_slice(&novo[..cabe]);
        true
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn fora_de_ordem_duplicado_e_limite() {
        let mut d = Direcao::new(1000, 10);
        assert!(d.segmento(1000, b"abc"));
        assert!(!d.segmento(1006, b"gh")); // chegou antes do buraco
        assert!(!d.segmento(1000, b"ab")); // retransmissão
        assert!(d.segmento(1002, b"cdef")); // sobrepõe e fecha o buraco
        assert_eq!(d.dados(), b"abcdefgh");
        assert!(d.segmento(1008, b"ijklmn"));
        assert_eq!(d.dados(), b"abcdefghij");
        assert!(d.cheia());
    }

    #[test]
    fn numero_de_sequencia_que_da_a_volta() {
        let mut d = Direcao::new(u32::MAX - 1, 100);
        assert!(d.segmento(u32::MAX - 1, b"ab"));
        assert!(d.segmento(0, b"cd"));
        assert_eq!(d.dados(), b"abcd");
    }
}
