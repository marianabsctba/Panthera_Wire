//! Formato do relatório entregue à interface. Horários em microssegundos
//! desde 1970 (cabem com folga num número do JavaScript). Textos que a
//! interface traduz saem como códigos, nunca como frases.

use std::collections::BTreeSet;
use std::net::IpAddr;

use serde::Serialize;

#[derive(Serialize)]
pub struct Relatorio {
    pub captura: ResumoCaptura,
    pub protocolos: Vec<Contagem>,
    pub aplicacoes: Vec<Contagem>,
    pub hosts: Vec<Host>,
    pub total_hosts: u64,
    pub fluxos: Vec<Fluxo>,
    pub total_fluxos: u64,
    pub dns: Vec<EventoDns>,
    pub total_dns: u64,
    pub http: Vec<EventoHttp>,
    pub total_http: u64,
    pub tls: Vec<EventoTls>,
    pub total_tls: u64,
    pub dhcp: Vec<EventoDhcp>,
    pub total_dhcp: u64,
}

#[derive(Serialize)]
pub struct ResumoCaptura {
    pub formato: &'static str,
    pub enlaces: Vec<String>,
    pub inicio_us: u64,
    pub fim_us: u64,
    pub pacotes: u64,
    pub bytes: u64,
    pub nao_decodificados: u64,
    pub avisos: Vec<Aviso>,
}

#[derive(Serialize)]
pub struct Aviso {
    pub codigo: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
}

#[derive(Serialize)]
pub struct Contagem {
    pub nome: String,
    pub pacotes: u64,
    pub bytes: u64,
    pub fluxos: u64,
}

#[derive(Serialize)]
pub struct Host {
    pub ip: IpAddr,
    pub escopo: &'static str,
    pub mac: Option<String>,
    pub nomes: BTreeSet<String>,
    pub pacotes_enviados: u64,
    pub pacotes_recebidos: u64,
    pub bytes_enviados: u64,
    pub bytes_recebidos: u64,
    pub fluxos_iniciados: u64,
    pub fluxos_recebidos: u64,
    pub primeiro_us: u64,
    pub ultimo_us: u64,
}

#[derive(Serialize)]
pub struct Fluxo {
    pub id: u32,
    pub protocolo: &'static str,
    pub origem: IpAddr,
    pub porta_origem: u16,
    pub destino: IpAddr,
    pub porta_destino: u16,
    pub inicio_us: u64,
    pub fim_us: u64,
    pub pacotes_ida: u64,
    pub pacotes_volta: u64,
    pub bytes_ida: u64,
    pub bytes_volta: u64,
    pub aplicacao: Option<&'static str>,
    /// A aplicação foi deduzida pela porta, não confirmada pelo conteúdo.
    pub aplicacao_por_porta: bool,
    pub estado: &'static str,
    /// Onde está o primeiro pacote do fluxo no arquivo original.
    pub offset: u64,
}

#[derive(Serialize)]
pub struct EventoDns {
    pub ts_us: u64,
    pub fluxo: u32,
    pub cliente: IpAddr,
    pub servidor: IpAddr,
    pub consulta: String,
    pub tipo: String,
    pub rcode: Option<u8>,
    pub respostas: Vec<String>,
    pub resposta_us: Option<u64>,
}

#[derive(Serialize)]
pub struct EventoHttp {
    pub ts_us: u64,
    pub fluxo: u32,
    pub cliente: IpAddr,
    pub servidor: IpAddr,
    pub porta: u16,
    pub metodo: String,
    pub host: Option<String>,
    pub caminho: String,
    pub user_agent: Option<String>,
    pub autorizacao: Option<String>,
    pub status: Option<u16>,
    pub tipo_conteudo: Option<String>,
    pub tamanho: Option<u64>,
    pub servidor_http: Option<String>,
}

#[derive(Serialize)]
pub struct EventoTls {
    pub ts_us: u64,
    pub fluxo: u32,
    pub cliente: IpAddr,
    pub servidor: IpAddr,
    pub porta: u16,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub versao_oferecida: String,
    pub versao: Option<String>,
    pub cifra: Option<String>,
}

#[derive(Serialize)]
pub struct EventoDhcp {
    pub ts_us: u64,
    pub mac: String,
    pub tipo: &'static str,
    pub nome_host: Option<String>,
    pub ip: Option<IpAddr>,
}
