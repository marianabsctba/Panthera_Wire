//! Formato do relatório entregue à interface. Horários em microssegundos
//! desde 1970 (cabem com folga num número do JavaScript). Textos que a
//! interface traduz saem como códigos, nunca como frases.

use std::collections::{BTreeMap, BTreeSet};
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
    pub alertas: Vec<Alerta>,
    pub historia: Historia,
}

/// Algo que merece atenção, com a evidência. O texto é montado pela
/// interface a partir de `regra` e `parametros`, no idioma escolhido.
#[derive(Serialize)]
pub struct Alerta {
    pub id: u32,
    pub regra: &'static str,
    /// baixa, media, alta
    pub severidade: &'static str,
    /// Fase do ataque em que o fato se encaixa (ver `historia`).
    pub fase: &'static str,
    /// Técnica MITRE ATT&CK, quando houver uma que se aplique.
    pub tecnica: Option<&'static str>,
    pub inicio_us: u64,
    pub fim_us: u64,
    /// Host principal envolvido (quem iniciou).
    pub host: IpAddr,
    /// Destino, domínio ou o que for o alvo, já em texto.
    pub alvo: Option<String>,
    pub alvo_ip: Option<IpAddr>,
    pub parametros: BTreeMap<&'static str, String>,
    /// Fluxos que sustentam o alerta (no máximo 200).
    pub fluxos: Vec<u32>,
}

#[derive(Serialize)]
pub struct Historia {
    pub paciente_zero: Option<IpAddr>,
    /// Outros hosts internos envolvidos: com alertas próprios ou que falaram
    /// com os mesmos destinos suspeitos do paciente zero.
    pub hosts_afetados: Vec<IpAddr>,
    pub cadeias: Vec<Cadeia>,
    /// O que a captura não permite afirmar, em códigos.
    pub nao_mostra: Vec<&'static str>,
}

#[derive(Serialize)]
pub struct Cadeia {
    pub host: IpAddr,
    /// baixa, media, alta
    pub confianca: &'static str,
    /// Por que essa confiança: entrega_e_controle, tres_fases, duas_graves,
    /// duas_fases ou uma_grave.
    pub motivo: &'static str,
    /// Fases que contaram (severidade baixa não conta).
    pub fases: Vec<&'static str>,
    pub inicio_us: u64,
    pub fim_us: u64,
    pub passos: Vec<Passo>,
}

#[derive(Serialize)]
pub struct Passo {
    pub alerta: u32,
    pub ts_us: u64,
    pub fase: &'static str,
    /// Por que este passo se liga ao anterior: mesmo_destino, pouco_depois, depois.
    pub ligacao: Option<&'static str>,
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
    /// Campo de senha no formulário ou na URL (o valor nunca é guardado).
    pub senha_em_claro: bool,
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
    /// Fingerprints do ClientHello (JA3 em MD5, JA4 da FoxIO) e do ServerHello.
    pub ja3: Option<String>,
    pub ja4: Option<String>,
    pub ja3s: Option<String>,
    /// Certificado do servidor (só aparece no TLS 1.2; no 1.3 vai cifrado).
    pub certificado: Option<Certificado>,
}

#[derive(Serialize, Clone)]
pub struct Certificado {
    pub sujeito: Option<String>,
    pub emissor: Option<String>,
    pub emissor_organizacao: Option<String>,
    pub nao_antes_us: Option<u64>,
    pub nao_depois_us: Option<u64>,
    pub autoassinado: bool,
    /// Nomes DNS do Subject Alternative Name.
    pub nomes: Vec<String>,
}

#[derive(Serialize)]
pub struct EventoDhcp {
    pub ts_us: u64,
    pub mac: String,
    pub tipo: &'static str,
    pub nome_host: Option<String>,
    pub ip: Option<IpAddr>,
}
