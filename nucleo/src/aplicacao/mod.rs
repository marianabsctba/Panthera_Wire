//! Leitores da camada de aplicação. Cada um recebe a carga de um pacote e
//! devolve só o que interessa para a análise, ou `None` se não reconhecer.

pub mod dhcp;
pub mod dns;
pub mod http;
pub mod tls;
pub mod x509;
