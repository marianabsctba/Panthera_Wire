//! Núcleo do Panthera Wire.
//!
//! Lê capturas pcap e pcapng em blocos de qualquer tamanho, sem nunca guardar
//! o arquivo inteiro, e monta o relatório: fluxos, hosts e eventos de
//! aplicação (DNS, HTTP, TLS, DHCP). Toda entrada é tratada como hostil: não
//! há `unsafe`, todo acesso a bytes é verificado e todo acúmulo tem limite.

#![forbid(unsafe_code)]

mod analise;
pub mod anonimizador;
mod aplicacao;
mod bytes;
mod captura;
mod decodificacao;
mod deteccao;
mod historia;
mod remontagem;
pub mod relatorio;

pub use analise::{Analise, Progresso};
pub use captura::ErroCaptura;
pub use relatorio::Relatorio;
