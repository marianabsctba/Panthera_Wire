//! Analisadores: olham fluxos e eventos da captura inteira (antes de qualquer
//! corte para a interface) e geram alertas com a evidência.
//!
//! Cada regra é deliberadamente simples e explicável: o alerta diz o que foi
//! visto e com quais números, para a pessoa poder discordar.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

use crate::aplicacao::x509;
use crate::decodificacao::{escopo, lado_de_dentro, lado_de_fora};
use crate::diagnostico as lim;
use crate::relatorio::{Alerta, EventoDns, EventoHttp, EventoTls, Fluxo};

pub struct Dados<'a> {
    pub fluxos: &'a [Fluxo],
    pub dns: &'a [EventoDns],
    pub http: &'a [EventoHttp],
    pub tls: &'a [EventoTls],
    pub nomes: &'a HashMap<IpAddr, BTreeSet<String>>,
}

/// O que cada regra detecta (ATT&CK), em que fase da história entra e qual
/// contramedida D3FEND ela própria implementa. A interface lê a mesma tabela
/// de `web/src/regras.json`; um teste garante que as duas não se separem.
pub struct Regra {
    pub regra: &'static str,
    pub tecnica: Option<&'static str>,
    pub fase: &'static str,
    /// Lido pela interface (regras.json), conferido no teste abaixo.
    #[allow(dead_code)]
    pub d3fend: &'static [&'static str],
}

pub const REGRAS: &[Regra] = &[
    Regra { regra: "beaconing", tecnica: Some("T1071"), fase: "comando_e_controle", d3fend: &["D3-PMAD"] },
    Regra { regra: "download_executavel", tecnica: Some("T1105"), fase: "entrega", d3fend: &["D3-APCA"] },
    Regra { regra: "ataque_web", tecnica: Some("T1190"), fase: "acesso_inicial", d3fend: &["D3-APCA"] },
    Regra { regra: "dga", tecnica: Some("T1568.002"), fase: "comando_e_controle", d3fend: &["D3-DNSTA"] },
    Regra { regra: "tunel_dns", tecnica: Some("T1071.004"), fase: "exfiltracao", d3fend: &["D3-DNSTA"] },
    Regra { regra: "credencial_em_claro", tecnica: Some("T1552"), fase: "credenciais", d3fend: &["D3-APCA"] },
    Regra { regra: "varredura_portas", tecnica: Some("T1046"), fase: "descoberta", d3fend: &["D3-CAA"] },
    Regra { regra: "varredura_hosts", tecnica: Some("T1046"), fase: "descoberta", d3fend: &["D3-CAA"] },
    Regra {
        regra: "movimentacao_lateral",
        tecnica: Some("T1021"),
        fase: "movimentacao_lateral",
        d3fend: &["D3-ANAA", "D3-RTSD"],
    },
    Regra { regra: "exfiltracao_volume", tecnica: Some("T1041"), fase: "exfiltracao", d3fend: &["D3-PHDURA"] },
    Regra { regra: "tls_antigo", tecnica: None, fase: "higiene", d3fend: &["D3-PMAD"] },
    Regra { regra: "user_agent_suspeito", tecnica: Some("T1071.001"), fase: "comando_e_controle", d3fend: &["D3-PMAD"] },
    Regra { regra: "porta_incomum", tecnica: Some("T1571"), fase: "comando_e_controle", d3fend: &["D3-PMAD"] },
    Regra { regra: "forca_bruta", tecnica: Some("T1110.001"), fase: "credenciais", d3fend: &["D3-ANET"] },
    Regra { regra: "sondagem_udp", tecnica: Some("T1046"), fase: "descoberta", d3fend: &["D3-CAA", "D3-ISVA"] },
    Regra { regra: "certificado_suspeito", tecnica: Some("T1573.002"), fase: "comando_e_controle", d3fend: &["D3-PCA"] },
    Regra { regra: "protocolo_disfarcado", tecnica: Some("T1571"), fase: "comando_e_controle", d3fend: &["D3-PMAD"] },
    Regra { regra: "c2_rotativo", tecnica: Some("T1008"), fase: "comando_e_controle", d3fend: &["D3-CSPP"] },
];

fn regra(nome: &str) -> &'static Regra {
    REGRAS.iter().find(|r| r.regra == nome).expect("toda regra usada precisa estar em REGRAS")
}

const MAX_EVIDENCIAS: usize = 200;
const MIB: u64 = 1024 * 1024;

/// Domínios de infraestrutura muito comum. Estar aqui só rebaixa a
/// severidade: o alerta continua aparecendo.
const CONHECIDOS: &[&str] = &[
    "microsoft.com", "windowsupdate.com", "windows.com", "windows.net", "msftncsi.com", "msftconnecttest.com",
    "live.com", "office.com", "office365.com", "office.net", "bing.com", "skype.com", "apple.com", "icloud.com",
    "mzstatic.com", "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "gvt1.com",
    "youtube.com", "ytimg.com", "mozilla.org", "mozilla.net", "firefox.com", "ubuntu.com", "canonical.com",
    "debian.org", "digicert.com", "letsencrypt.org", "sectigo.com", "globalsign.com", "adobe.com", "zoom.us",
    "whatsapp.net", "facebook.com", "fbcdn.net", "instagram.com", "dns.google", "cloudflare-dns.com",
];

pub fn conhecido(nome: &str) -> bool {
    let nome = nome.trim_end_matches('.').to_ascii_lowercase();
    CONHECIDOS.iter().any(|s| nome == *s || nome.ends_with(&format!(".{s}")))
}

fn interno(ip: &IpAddr) -> bool {
    escopo(ip) == "interno"
}

/// De um host da rede observada para um destino lá fora. Com faixas
/// reservadas (laboratório), as duas pontas podem ser reservadas.
pub(crate) fn para_fora(origem: &IpAddr, destino: &IpAddr) -> bool {
    origem != destino && lado_de_dentro(origem) && lado_de_fora(destino) && !(interno(origem) && interno(destino))
}

impl Dados<'_> {
    fn nome(&self, ip: &IpAddr) -> Option<&str> {
        self.nomes.get(ip).and_then(|n| n.iter().next()).map(String::as_str)
    }

    pub(crate) fn nome_ou_ip(&self, ip: &IpAddr) -> String {
        self.nome(ip).map_or_else(|| ip.to_string(), str::to_owned)
    }
}

/// Agrupa evidências de um alerta enquanto as regras percorrem os dados.
struct Grupo {
    inicio: u64,
    fim: u64,
    fluxos: BTreeSet<u32>,
}

impl Default for Grupo {
    fn default() -> Self {
        Self { inicio: u64::MAX, fim: 0, fluxos: BTreeSet::new() }
    }
}

impl Grupo {
    fn somar(&mut self, ts: u64, fluxo: u32) {
        self.inicio = self.inicio.min(ts);
        self.fim = self.fim.max(ts);
        if self.fluxos.len() < MAX_EVIDENCIAS {
            self.fluxos.insert(fluxo);
        }
    }
}

struct Novo {
    regra: &'static str,
    severidade: &'static str,
    host: IpAddr,
    alvo: Option<String>,
    alvo_ip: Option<IpAddr>,
    parametros: Vec<(&'static str, String)>,
}

fn alerta(n: Novo, g: Grupo) -> Alerta {
    let info = regra(n.regra);
    Alerta {
        id: 0,
        regra: n.regra,
        severidade: n.severidade,
        fase: info.fase,
        tecnica: info.tecnica,
        inicio_us: if g.inicio == u64::MAX { 0 } else { g.inicio },
        fim_us: g.fim,
        host: n.host,
        alvo: n.alvo,
        alvo_ip: n.alvo_ip,
        parametros: n.parametros.into_iter().collect(),
        fluxos: g.fluxos.into_iter().collect(),
    }
}

pub fn detectar(d: &Dados) -> Vec<Alerta> {
    let mut a = Vec::new();
    beaconing(d, &mut a);
    download_executavel(d, &mut a);
    ataque_web(d, &mut a);
    forca_bruta(d, &mut a);
    sondagem_udp(d, &mut a);
    certificado_suspeito(d, &mut a);
    protocolo_disfarcado(d, &mut a);
    c2_rotativo(d, &mut a);
    dga(d, &mut a);
    tunel_dns(d, &mut a);
    credencial_em_claro(d, &mut a);
    varredura(d, &mut a);
    movimentacao_lateral(d, &mut a);
    exfiltracao(d, &mut a);
    tls_antigo(d, &mut a);
    user_agent(d, &mut a);
    porta_incomum(d, &mut a);

    a.sort_by_key(|x| (x.inicio_us, x.regra, x.host));
    for (i, x) in a.iter_mut().enumerate() {
        x.id = i as u32;
    }
    a
}

pub(crate) fn mediana(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.total_cmp(b));
    let n = v.len();
    if n == 0 {
        0.0
    } else if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

/// Conexões novas para o mesmo destino em intervalo quase constante.
fn beaconing(d: &Dados, saida: &mut Vec<Alerta>) {
    let mut grupos: BTreeMap<(IpAddr, IpAddr, u16, &str), Vec<&Fluxo>> = BTreeMap::new();
    for f in d.fluxos {
        if para_fora(&f.origem, &f.destino) && (f.protocolo == "TCP" || f.protocolo == "UDP") {
            grupos.entry((f.origem, f.destino, f.porta_destino, f.protocolo)).or_default().push(f);
        }
    }
    for ((origem, destino, porta, protocolo), mut fs) in grupos {
        if (fs.len() as f64) < lim::BEACON_CONEXOES {
            continue;
        }
        fs.sort_by_key(|f| f.inicio_us);
        let mut intervalos: Vec<f64> =
            fs.windows(2).map(|w| w[1].inicio_us.saturating_sub(w[0].inicio_us) as f64 / 1e6).collect();
        let med = mediana(&mut intervalos);
        if med < lim::BEACON_INTERVALO_S {
            continue;
        }
        let regulares = intervalos.iter().filter(|x| (*x - med).abs() <= 0.2 * med).count();
        if (regulares as f64) < lim::BEACON_REGULARES_PCT / 100.0 * intervalos.len() as f64 {
            continue;
        }
        let mut desvios: Vec<f64> = intervalos.iter().map(|x| (x - med).abs()).collect();
        let variacao = mediana(&mut desvios) / med * 100.0;

        let alvo = d.nome_ou_ip(&destino);
        let mut g = Grupo::default();
        for f in &fs {
            g.somar(f.inicio_us, f.id);
        }
        saida.push(alerta(
            Novo {
                regra: "beaconing",
                severidade: if conhecido(&alvo) { "baixa" } else { "alta" },
                host: origem,
                alvo: Some(alvo),
                alvo_ip: Some(destino),
                parametros: vec![
                    ("intervalo", format!("{med:.0}")),
                    ("conexoes", fs.len().to_string()),
                    ("variacao", format!("{variacao:.0}")),
                    ("porta", format!("{protocolo}/{porta}")),
                ],
            },
            g,
        ));
    }
}

/// Caminhos de distribuição de atualização da Microsoft, que muitas vezes vêm
/// de IPs de CDN sem nome conhecido.
const CAMINHOS_DE_ATUALIZACAO: &[&str] =
    &["/msdownload/update/", "/windowsupdate/", "/filestreamingservice/files/", "/d/msdownload/", "/c/msdownload/"];

fn atualizacao_conhecida(url: &str) -> bool {
    let u = url.to_ascii_lowercase();
    CAMINHOS_DE_ATUALIZACAO.iter().any(|c| u.contains(c))
}

const EXTENSOES_EXECUTAVEIS: &[&str] = &[
    ".exe", ".dll", ".scr", ".msi", ".ps1", ".bat", ".cmd", ".vbs", ".hta", ".jar", ".lnk", ".iso", ".img", ".cpl",
];
const TIPOS_EXECUTAVEIS: &[&str] = &[
    "application/x-msdownload",
    "application/x-dosexec",
    "application/x-msdos-program",
    "application/vnd.microsoft.portable-executable",
    "application/x-ms-installer",
    "application/x-msi",
    "application/hta",
    "application/java-archive",
];

fn download_executavel(d: &Dados, saida: &mut Vec<Alerta>) {
    let mut grupos: BTreeMap<(IpAddr, String), (Grupo, &EventoHttp)> = BTreeMap::new();
    for h in d.http {
        if !matches!(h.status, Some(200..=299)) {
            continue;
        }
        let caminho = h.caminho.split(['?', '#']).next().unwrap_or("").to_ascii_lowercase();
        let tipo = h.tipo_conteudo.as_deref().unwrap_or("").to_ascii_lowercase();
        let por_extensao = EXTENSOES_EXECUTAVEIS.iter().any(|e| caminho.ends_with(e));
        let por_tipo = TIPOS_EXECUTAVEIS.iter().any(|t| tipo.starts_with(t));
        if !por_extensao && !por_tipo {
            continue;
        }
        let host = h.host.clone().unwrap_or_else(|| d.nome_ou_ip(&h.servidor));
        let url: String = format!("{host}{}", h.caminho).chars().take(200).collect();
        let (g, _) = grupos.entry((h.cliente, url)).or_insert_with(|| (Grupo::default(), h));
        g.somar(h.ts_us, h.fluxo);
    }
    for ((cliente, url), (g, h)) in grupos {
        let host = h.host.clone().unwrap_or_else(|| h.servidor.to_string());
        let host_sem_porta = host.split(':').next().unwrap_or(&host).to_owned();
        let ip_direto = host_sem_porta.parse::<IpAddr>().is_ok();
        let atualizacao = atualizacao_conhecida(&url);
        let mut parametros = vec![("url", url), ("ip_direto", ip_direto.to_string())];
        if let Some(t) = &h.tipo_conteudo {
            parametros.push(("tipo", t.chars().take(80).collect()));
        }
        if let Some(t) = h.tamanho {
            parametros.push(("tamanho", t.to_string()));
        }
        saida.push(alerta(
            Novo {
                regra: "download_executavel",
                severidade: if conhecido(&host_sem_porta) || atualizacao { "baixa" } else { "alta" },
                host: cliente,
                alvo: Some(host_sem_porta),
                alvo_ip: Some(h.servidor),
                parametros,
            },
            g,
        ));
    }
}

/// Padrões clássicos de exploração de aplicação web na URL da requisição.
/// Cada um é procurado na URL em minúsculas e também já decodificada.
const PADROES_WEB: &[(&str, &[&str])] = &[
    ("traversal", &["../", "..\\", "/etc/passwd", "/etc/shadow", "win.ini", "boot.ini"]),
    (
        "sqli",
        &[
            "union select", "' or '1'='1", "' or 1=1", "\" or 1=1", " or 1=1", " and 1=1", "1=1--", "sleep(", "benchmark(",
            "information_schema", "' or ''='",
        ],
    ),
    ("xss", &["<script", "javascript:", "onerror=", "onload=", "<svg"]),
    ("comando", &[";cat ", "|cat ", "$(", "`", ";id", "|id", "cmd.exe", "/bin/sh", "/bin/bash", "powershell"]),
    ("log4shell", &["${jndi:"]),
];

/// Decodifica %XX (duas vezes, para pegar a codificação dupla) e + como espaço.
fn decodificar_url(s: &str) -> String {
    let mut atual = s.to_owned();
    for _ in 0..2 {
        let b = atual.as_bytes();
        let mut saida = Vec::with_capacity(b.len());
        let mut i = 0;
        let hex = |c: u8| (c as char).to_digit(16).map(|v| v as u8);
        while i < b.len() {
            if b[i] == b'%' {
                if let (Some(a), Some(c)) = (b.get(i + 1).copied().and_then(hex), b.get(i + 2).copied().and_then(hex)) {
                    saida.push(a << 4 | c);
                    i += 3;
                    continue;
                }
            }
            saida.push(if b[i] == b'+' { b' ' } else { b[i] });
            i += 1;
        }
        atual = String::from_utf8_lossy(&saida).into_owned();
    }
    atual
}

fn ataque_web(d: &Dados, saida: &mut Vec<Alerta>) {
    let mut grupos: BTreeMap<(IpAddr, IpAddr, &'static str), (Grupo, String, bool, Option<String>)> = BTreeMap::new();
    for h in d.http {
        let url = decodificar_url(&h.caminho).to_ascii_lowercase();
        let Some((tipo, _)) = PADROES_WEB.iter().find(|(_, ps)| ps.iter().any(|p| url.contains(p))) else { continue };
        // A primeira URL de cada tipo fica como exemplo.
        let (g, _, sucesso, _) = grupos.entry((h.cliente, h.servidor, tipo)).or_insert_with(|| {
            (Grupo::default(), h.caminho.chars().take(160).collect(), false, host_http(h))
        });
        g.somar(h.ts_us, h.fluxo);
        *sucesso |= matches!(h.status, Some(200..=299));
    }
    for ((cliente, servidor, tipo), (g, exemplo, sucesso, host)) in grupos {
        let tentativas = g.fluxos.len();
        saida.push(alerta(
            Novo {
                regra: "ataque_web",
                // Com resposta 2xx, a exploração pode ter funcionado.
                severidade: if sucesso { "alta" } else { "media" },
                host: cliente,
                alvo: Some(host.unwrap_or_else(|| d.nome_ou_ip(&servidor))),
                alvo_ip: Some(servidor),
                parametros: vec![
                    ("tipo", tipo.into()),
                    ("exemplo", exemplo),
                    ("tentativas", tentativas.to_string()),
                    ("sucesso", sucesso.to_string()),
                ],
            },
            g,
        ));
    }
}

/// Nome pedido no cabeçalho Host, sem a porta. Diz mais do que o nome
/// aprendido para o IP, que pode ter vários.
fn host_http(h: &EventoHttp) -> Option<String> {
    let host = h.host.as_deref()?;
    let sem_porta = if host.starts_with('[') { host } else { host.split(':').next().unwrap_or(host) };
    Some(sem_porta.to_owned()).filter(|s| !s.is_empty())
}

/// Muitas tentativas de autenticação recusadas (HTTP 401 ou 403) do mesmo
/// cliente no mesmo servidor. Se depois vier um sucesso no mesmo caminho, a
/// senha pode ter sido descoberta.
fn forca_bruta(d: &Dados, saida: &mut Vec<Alerta>) {
    struct Tentativas {
        falhas: u64,
        caminhos: BTreeSet<String>,
        ultima_falha: u64,
        sucesso_depois: bool,
        g: Grupo,
        host: Option<String>,
    }
    let mut grupos: BTreeMap<(IpAddr, IpAddr), Tentativas> = BTreeMap::new();
    for h in d.http {
        let caminho = h.caminho.split('?').next().unwrap_or("").to_owned();
        let t = grupos.entry((h.cliente, h.servidor)).or_insert_with(|| Tentativas {
            falhas: 0,
            caminhos: BTreeSet::new(),
            ultima_falha: 0,
            sucesso_depois: false,
            g: Grupo::default(),
            host: host_http(h),
        });
        match h.status {
            Some(401 | 403) => {
                t.falhas += 1;
                t.ultima_falha = t.ultima_falha.max(h.ts_us);
                t.g.somar(h.ts_us, h.fluxo);
                if t.caminhos.len() < 4 {
                    t.caminhos.insert(caminho);
                }
            }
            Some(200..=399) if t.falhas >= 10 && t.caminhos.contains(&caminho) => {
                t.sucesso_depois = true;
                t.g.somar(h.ts_us, h.fluxo);
            }
            _ => {}
        }
    }
    for ((cliente, servidor), t) in grupos {
        if (t.falhas as f64) < lim::BRUTA_FALHAS {
            continue;
        }
        saida.push(alerta(
            Novo {
                regra: "forca_bruta",
                severidade: if t.sucesso_depois { "alta" } else { "media" },
                host: cliente,
                alvo: Some(t.host.unwrap_or_else(|| d.nome_ou_ip(&servidor))),
                alvo_ip: Some(servidor),
                parametros: vec![
                    ("falhas", t.falhas.to_string()),
                    ("caminhos", t.caminhos.into_iter().collect::<Vec<_>>().join(", ")),
                    ("sucesso", t.sucesso_depois.to_string()),
                ],
            },
            t.g,
        ));
    }
}

/// Muitas mensagens UDP sem nenhuma resposta do mesmo host para o mesmo
/// destino: sondagem de serviços como SNMP, NTP ou DNS.
fn sondagem_udp(d: &Dados, saida: &mut Vec<Alerta>) {
    let mut grupos: BTreeMap<(IpAddr, IpAddr), (u64, BTreeSet<u16>, Grupo)> = BTreeMap::new();
    for f in d.fluxos {
        // DNS sem resposta já é avaliado pelas regras de DNS.
        if f.protocolo == "UDP" && f.estado == "sem_resposta" && f.porta_destino != 53 && escopo(&f.destino) != "multicast" {
            let (n, portas, g) = grupos.entry((f.origem, f.destino)).or_default();
            *n += f.pacotes_ida;
            portas.insert(f.porta_destino);
            g.somar(f.inicio_us, f.id);
        }
    }
    for ((origem, destino), (pacotes, portas, g)) in grupos {
        if (g.fluxos.len() as f64) < lim::SONDAGEM_UDP {
            continue;
        }
        let nomes: Vec<String> = portas.iter().take(6).map(|p| servico_udp(*p)).collect();
        saida.push(alerta(
            Novo {
                regra: "sondagem_udp",
                severidade: "media",
                host: origem,
                alvo: Some(d.nome_ou_ip(&destino)),
                alvo_ip: Some(destino),
                parametros: vec![("pacotes", pacotes.to_string()), ("servicos", nomes.join(", "))],
            },
            g,
        ));
    }
}

/// Certificado do servidor, numa conexão para fora, que não deveria ser
/// aceito: autoassinado, vencido, ainda não válido ou emitido para outro nome.
/// Servidores de comando montados às pressas costumam ter um desses.
fn certificado_suspeito(d: &Dados, saida: &mut Vec<Alerta>) {
    let mut grupos: BTreeMap<(IpAddr, IpAddr, String), (Grupo, BTreeSet<&'static str>, &EventoTls)> = BTreeMap::new();
    for t in d.tls {
        let Some(c) = &t.certificado else { continue };
        if !para_fora(&t.cliente, &t.servidor) {
            continue;
        }
        let mut motivos = BTreeSet::new();
        if c.autoassinado {
            motivos.insert("autoassinado");
        }
        if c.nao_depois_us.is_some_and(|f| f < t.ts_us) {
            motivos.insert("vencido");
        }
        if c.nao_antes_us.is_some_and(|i| i > t.ts_us) {
            motivos.insert("ainda_nao_valido");
        }
        if let Some(sni) = &t.sni {
            if (c.sujeito.is_some() || !c.nomes.is_empty()) && !x509::confere(c, sni) {
                motivos.insert("nome_diferente");
            }
        }
        if motivos.is_empty() {
            continue;
        }
        let alvo = t.sni.clone().unwrap_or_else(|| d.nome_ou_ip(&t.servidor));
        let (g, m, _) = grupos.entry((t.cliente, t.servidor, alvo)).or_insert_with(|| (Grupo::default(), BTreeSet::new(), t));
        g.somar(t.ts_us, t.fluxo);
        m.extend(motivos);
    }
    for ((cliente, servidor, alvo), (g, motivos, t)) in grupos {
        let c = t.certificado.as_ref();
        saida.push(alerta(
            Novo {
                regra: "certificado_suspeito",
                severidade: if motivos.contains("autoassinado") || motivos.contains("nome_diferente") { "media" } else { "baixa" },
                host: cliente,
                alvo: Some(alvo),
                alvo_ip: Some(servidor),
                parametros: vec![
                    ("motivos", motivos.into_iter().collect::<Vec<_>>().join(",")),
                    ("sujeito", c.and_then(|c| c.sujeito.clone()).unwrap_or_default()),
                    ("emissor", c.and_then(|c| c.emissor.clone()).unwrap_or_default()),
                ],
            },
            g,
        ));
    }
}

/// Dados trafegando numa porta de protocolo conhecido (DNS, HTTP, TLS) que
/// não são aquele protocolo: shell remoto ou túnel usando a porta para passar
/// por filtros. A aplicação foi deduzida só pela porta e o conteúdo não bateu.
fn protocolo_disfarcado(d: &Dados, saida: &mut Vec<Alerta>) {
    let mut grupos: BTreeMap<(IpAddr, IpAddr, u16, &'static str), Grupo> = BTreeMap::new();
    for f in d.fluxos {
        let Some(app) = f.aplicacao else { continue };
        if f.aplicacao_por_porta && f.conteudo_desconhecido && matches!(app, "DNS" | "HTTP" | "TLS") && f.pacotes_volta > 0 {
            grupos.entry((f.origem, f.destino, f.porta_destino, app)).or_default().somar(f.inicio_us, f.id);
        }
    }
    for ((origem, destino, porta, app), g) in grupos {
        saida.push(alerta(
            Novo {
                regra: "protocolo_disfarcado",
                // DNS quase nunca tem motivo para carregar outra coisa.
                severidade: if app == "DNS" { "alta" } else { "media" },
                host: origem,
                alvo: Some(d.nome_ou_ip(&destino)),
                alvo_ip: Some(destino),
                parametros: vec![("protocolo", app.into()), ("porta", porta.to_string()), ("conexoes", g.fluxos.len().to_string())],
            },
            g,
        ));
    }
}

fn servico_udp(porta: u16) -> String {
    match porta {
        69 => "TFTP".into(),
        123 => "NTP".into(),
        137 => "NetBIOS".into(),
        161 | 162 => "SNMP".into(),
        500 => "IKE".into(),
        514 => "Syslog".into(),
        1900 => "SSDP".into(),
        5060 => "SIP".into(),
        p => format!("UDP/{p}"),
    }
}

/// Muitos domínios inexistentes consultados pelo mesmo host: típico de
/// malware que gera nomes por algoritmo até achar o servidor ativo.
fn dga(d: &Dados, saida: &mut Vec<Alerta>) {
    let mut por_cliente: BTreeMap<IpAddr, (BTreeSet<&str>, Grupo)> = BTreeMap::new();
    for e in d.dns {
        if e.rcode == Some(3) {
            let (nomes, g) = por_cliente.entry(e.cliente).or_default();
            nomes.insert(&e.consulta);
            g.somar(e.ts_us, e.fluxo);
        }
    }
    for (cliente, (nomes, g)) in por_cliente {
        if (nomes.len() as f64) < lim::DGA_NXDOMAIN {
            continue;
        }
        let exemplos: Vec<&str> = nomes.iter().take(3).copied().collect();
        saida.push(alerta(
            Novo {
                regra: "dga",
                severidade: "media",
                host: cliente,
                alvo: None,
                alvo_ip: None,
                parametros: vec![("quantidade", nomes.len().to_string()), ("exemplos", exemplos.join(", "))],
            },
            g,
        ));
    }
}

/// Dados escondidos em subdomínios: muitos nomes únicos e longos sob o mesmo
/// domínio, muitas vezes com consultas TXT.
fn tunel_dns(d: &Dados, saida: &mut Vec<Alerta>) {
    struct Acumulado<'a> {
        unicos: BTreeSet<&'a str>,
        consultas: u64,
        tamanho: u64,
        txt: u64,
        g: Grupo,
    }
    let mut grupos: BTreeMap<(IpAddr, &str), Acumulado> = BTreeMap::new();
    for e in d.dns {
        // A zona é o nome sem o primeiro rótulo: em <dados>.t.exemplo.net,
        // os dados mudam e a zona t.exemplo.net se repete.
        let Some((_, base)) = e.consulta.split_once('.') else { continue };
        if !base.contains('.') || conhecido(base) {
            continue;
        }
        let a = grupos.entry((e.cliente, base)).or_insert_with(|| Acumulado {
            unicos: BTreeSet::new(),
            consultas: 0,
            tamanho: 0,
            txt: 0,
            g: Grupo::default(),
        });
        a.unicos.insert(&e.consulta);
        a.consultas += 1;
        a.tamanho += e.consulta.len() as u64;
        a.txt += (e.tipo == "TXT") as u64;
        a.g.somar(e.ts_us, e.fluxo);
    }
    for ((cliente, base), a) in grupos {
        let media = a.tamanho / a.consultas.max(1);
        let longo = a.unicos.len() as f64 >= lim::TUNEL_UNICOS && media as f64 >= lim::TUNEL_TAMANHO;
        let txt = a.txt as f64 >= lim::TUNEL_TXT && a.unicos.len() >= 10;
        if !longo && !txt {
            continue;
        }
        saida.push(alerta(
            Novo {
                regra: "tunel_dns",
                severidade: "alta",
                host: cliente,
                alvo: Some(base.to_owned()),
                alvo_ip: None,
                parametros: vec![
                    ("consultas", a.consultas.to_string()),
                    ("unicos", a.unicos.len().to_string()),
                    ("tamanho_medio", media.to_string()),
                    ("txt", a.txt.to_string()),
                ],
            },
            a.g,
        ));
    }
}

/// Senha que atravessou a rede sem cifra. O valor nunca é guardado: só o
/// fato de que existiu e onde.
fn credencial_em_claro(d: &Dados, saida: &mut Vec<Alerta>) {
    let mut grupos: BTreeMap<(IpAddr, IpAddr, &str), Grupo> = BTreeMap::new();
    let mut nomes_http: BTreeMap<(IpAddr, IpAddr), String> = BTreeMap::new();
    for h in d.http {
        if h.autorizacao.is_some() || h.senha_em_claro {
            if let Some(n) = host_http(h) {
                nomes_http.entry((h.cliente, h.servidor)).or_insert(n);
            }
        }
        if h.autorizacao.as_deref().is_some_and(|e| e.eq_ignore_ascii_case("basic")) {
            grupos.entry((h.cliente, h.servidor, "HTTP Basic")).or_default().somar(h.ts_us, h.fluxo);
        }
        if h.senha_em_claro {
            grupos.entry((h.cliente, h.servidor, "HTTP")).or_default().somar(h.ts_us, h.fluxo);
        }
    }
    for f in d.fluxos {
        let protocolo = match (f.protocolo, f.porta_destino) {
            ("TCP", 21) => "FTP",
            ("TCP", 23) => "Telnet",
            ("TCP", 110) => "POP3",
            ("TCP", 143) => "IMAP",
            _ => continue,
        };
        // Só conta se a conexão foi aceita e houve conversa.
        if f.pacotes_volta > 2 && matches!(f.estado, "aberta" | "encerrada" | "em_andamento") {
            grupos.entry((f.origem, f.destino, protocolo)).or_default().somar(f.inicio_us, f.id);
        }
    }
    for ((cliente, servidor, protocolo), g) in grupos {
        saida.push(alerta(
            Novo {
                regra: "credencial_em_claro",
                severidade: "media",
                host: cliente,
                alvo: Some(nomes_http.get(&(cliente, servidor)).cloned().unwrap_or_else(|| d.nome_ou_ip(&servidor))),
                alvo_ip: Some(servidor),
                parametros: vec![("protocolo", protocolo.into())],
            },
            g,
        ));
    }
}

/// Muitas tentativas de conexão sem resposta ou recusadas: varredura de
/// portas num host, ou da mesma porta em muitos hosts.
fn varredura(d: &Dados, saida: &mut Vec<Alerta>) {
    let mut portas: BTreeMap<(IpAddr, IpAddr), (BTreeSet<u16>, Grupo)> = BTreeMap::new();
    let mut hosts: BTreeMap<(IpAddr, u16), (BTreeSet<IpAddr>, Grupo)> = BTreeMap::new();
    for f in d.fluxos {
        if f.protocolo != "TCP" || !matches!(f.estado, "sem_resposta" | "recusada") {
            continue;
        }
        let (p, g) = portas.entry((f.origem, f.destino)).or_default();
        p.insert(f.porta_destino);
        g.somar(f.inicio_us, f.id);
        let (h, g) = hosts.entry((f.origem, f.porta_destino)).or_default();
        h.insert(f.destino);
        g.somar(f.inicio_us, f.id);
    }
    for ((origem, destino), (p, g)) in portas {
        if p.len() as f64 >= lim::VARREDURA {
            saida.push(alerta(
                Novo {
                    regra: "varredura_portas",
                    severidade: "media",
                    host: origem,
                    alvo: Some(d.nome_ou_ip(&destino)),
                    alvo_ip: Some(destino),
                    parametros: vec![
                        ("quantidade", p.len().to_string()),
                        ("faixa", format!("{}-{}", p.first().unwrap_or(&0), p.last().unwrap_or(&0))),
                    ],
                },
                g,
            ));
        }
    }
    for ((origem, porta), (h, g)) in hosts {
        if h.len() as f64 >= lim::VARREDURA {
            saida.push(alerta(
                Novo {
                    regra: "varredura_hosts",
                    severidade: "media",
                    host: origem,
                    alvo: None,
                    alvo_ip: None,
                    parametros: vec![("quantidade", h.len().to_string()), ("porta", porta.to_string())],
                },
                g,
            ));
        }
    }
}

/// Um host interno usando serviços de administração remota em vários outros.
fn movimentacao_lateral(d: &Dados, saida: &mut Vec<Alerta>) {
    let mut por_origem: BTreeMap<IpAddr, (BTreeSet<IpAddr>, BTreeSet<&str>, Grupo)> = BTreeMap::new();
    for f in d.fluxos {
        let Some(app) = f.aplicacao else { continue };
        if !matches!(app, "SMB" | "RDP" | "WinRM" | "RPC" | "SSH")
            || !lado_de_dentro(&f.origem)
            || !lado_de_dentro(&f.destino)
            || matches!(f.estado, "sem_resposta" | "recusada")
        {
            continue;
        }
        let (destinos, apps, g) = por_origem.entry(f.origem).or_default();
        destinos.insert(f.destino);
        apps.insert(app);
        g.somar(f.inicio_us, f.id);
    }
    for (origem, (destinos, apps, g)) in por_origem {
        if (destinos.len() as f64) < lim::LATERAL_DESTINOS {
            continue;
        }
        let alvos: Vec<String> = destinos.iter().take(5).map(|ip| d.nome_ou_ip(ip)).collect();
        saida.push(alerta(
            Novo {
                regra: "movimentacao_lateral",
                severidade: "media",
                host: origem,
                alvo: None,
                alvo_ip: None,
                parametros: vec![
                    ("quantidade", destinos.len().to_string()),
                    ("protocolos", apps.into_iter().collect::<Vec<_>>().join(", ")),
                    ("alvos", alvos.join(", ")),
                ],
            },
            g,
        ));
    }
}

/// Volume grande saindo para um destino externo, muito maior do que voltou.
fn exfiltracao(d: &Dados, saida: &mut Vec<Alerta>) {
    let mut grupos: BTreeMap<(IpAddr, IpAddr), (u64, u64, Vec<&Fluxo>)> = BTreeMap::new();
    for f in d.fluxos {
        if para_fora(&f.origem, &f.destino) {
            let (ida, volta, fs) = grupos.entry((f.origem, f.destino)).or_default();
            *ida += f.bytes_ida;
            *volta += f.bytes_volta;
            fs.push(f);
        }
    }
    for ((origem, destino), (ida, volta, fs)) in grupos {
        if (ida as f64) < lim::EXFIL_MB * MIB as f64 || (ida as f64) < lim::EXFIL_PROPORCAO * volta.max(1) as f64 {
            continue;
        }
        // Evidência são os fluxos que carregaram o volume, não as conexões
        // pequenas que por acaso foram ao mesmo destino.
        let mut g = Grupo::default();
        for f in fs.iter().filter(|f| f.bytes_ida >= ida / 20) {
            g.somar(f.inicio_us, f.id);
        }
        let alvo = d.nome_ou_ip(&destino);
        saida.push(alerta(
            Novo {
                regra: "exfiltracao_volume",
                severidade: if conhecido(&alvo) { "media" } else { "alta" },
                host: origem,
                alvo: Some(alvo),
                alvo_ip: Some(destino),
                parametros: vec![("enviados", ida.to_string()), ("recebidos", volta.to_string())],
            },
            g,
        ));
    }
}

fn tls_antigo(d: &Dados, saida: &mut Vec<Alerta>) {
    let mut grupos: BTreeMap<(IpAddr, IpAddr, &str), (Grupo, Option<&str>)> = BTreeMap::new();
    for t in d.tls {
        let Some(v) = t.versao.as_deref() else { continue };
        if matches!(v, "SSL 3.0" | "TLS 1.0" | "TLS 1.1") {
            let (g, _) = grupos.entry((t.cliente, t.servidor, v)).or_insert_with(|| (Grupo::default(), t.sni.as_deref()));
            g.somar(t.ts_us, t.fluxo);
        }
    }
    for ((cliente, servidor, versao), (g, sni)) in grupos {
        saida.push(alerta(
            Novo {
                regra: "tls_antigo",
                severidade: "baixa",
                host: cliente,
                alvo: Some(sni.map_or_else(|| d.nome_ou_ip(&servidor), str::to_owned)),
                alvo_ip: Some(servidor),
                parametros: vec![("versao", versao.into())],
            },
            g,
        ));
    }
}

const FERRAMENTAS: &[&str] = &[
    "curl/", "wget/", "python-requests", "python-urllib", "powershell", "winhttp", "go-http-client",
    "libwww-perl", "nmap", "sqlmap", "nikto", "certutil", "bitsadmin", "msie 6.0", "msie 5.",
];

fn user_agent(d: &Dados, saida: &mut Vec<Alerta>) {
    let mut grupos: BTreeMap<(IpAddr, String), (Grupo, &'static str)> = BTreeMap::new();
    for h in d.http {
        let ua = h.user_agent.as_deref().unwrap_or("").trim();
        let minusculo = ua.to_ascii_lowercase();
        let marca = if ua.is_empty() {
            "vazio"
        } else if let Some(f) = FERRAMENTAS.iter().find(|f| minusculo.contains(*f)) {
            f
        } else if navegador_obsoleto(&minusculo) {
            "navegador_obsoleto"
        } else {
            continue;
        };
        let (g, _) = grupos.entry((h.cliente, ua.chars().take(120).collect())).or_insert_with(|| (Grupo::default(), marca));
        g.somar(h.ts_us, h.fluxo);
    }
    for ((cliente, ua), (g, marca)) in grupos {
        let grave = matches!(marca, "powershell" | "certutil" | "bitsadmin");
        saida.push(alerta(
            Novo {
                regra: "user_agent_suspeito",
                severidade: if grave { "media" } else { "baixa" },
                host: cliente,
                alvo: None,
                alvo_ip: None,
                parametros: vec![("user_agent", ua), ("marca", marca.trim_end_matches('/').into())],
            },
            g,
        ));
    }
}

/// Firefox abaixo do 78 ou Chrome abaixo do 80 (2020): ninguém navega mais
/// com eles, mas muito malware ainda copia esses user agents.
fn navegador_obsoleto(ua: &str) -> bool {
    let versao = |marca: &str| -> Option<u32> {
        let resto = &ua[ua.find(marca)? + marca.len()..];
        resto.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
    };
    // Edge e Opera também dizem "Chrome/": a versão do Chrome continua valendo.
    versao("firefox/").is_some_and(|v| v < 78) || versao("chrome/").is_some_and(|v| v < 80)
}

/// Forma de uma requisição sem os valores: método, cada pedaço do caminho
/// reduzido a tamanho (nomes de arquivo com ponto ficam como estão) e os nomes
/// dos parâmetros. "POST /irpw/" e "POST /lqjm/" têm a mesma forma.
fn forma(h: &EventoHttp) -> Option<String> {
    let (caminho, consulta) = h.caminho.split_once('?').unwrap_or((&h.caminho, ""));
    let pedacos: Vec<String> = caminho
        .split('/')
        .filter(|p| !p.is_empty())
        .map(|p| if p.contains('.') { p.to_ascii_lowercase() } else { format!("<{}>", p.len()) })
        .collect();
    // Só a raiz não diz nada: muita coisa legítima pede "/".
    if pedacos.is_empty() {
        return None;
    }
    let mut nomes: Vec<&str> = consulta.split('&').filter_map(|p| p.split('=').next()).filter(|n| !n.is_empty()).collect();
    nomes.sort_unstable();
    Some(format!("{} /{}/?{}", h.metodo, pedacos.join("/"), nomes.join("&")))
}

/// O mesmo formato de requisição, com o mesmo user agent, para muitos domínios
/// diferentes, quase sempre com erro: malware que espalha o contato por uma
/// lista de domínios (muitos deles iscas) para esconder o servidor de verdade.
fn c2_rotativo(d: &Dados, saida: &mut Vec<Alerta>) {
    struct Rotacao {
        hosts: BTreeSet<String>,
        pedidos: u64,
        erros: u64,
        g: Grupo,
    }
    let mut grupos: BTreeMap<(IpAddr, String, String), Rotacao> = BTreeMap::new();
    for h in d.http {
        let (Some(f), Some(host)) = (forma(h), host_http(h)) else { continue };
        if conhecido(&host) {
            continue;
        }
        let ua = h.user_agent.clone().unwrap_or_default();
        let r = grupos
            .entry((h.cliente, ua, f))
            .or_insert_with(|| Rotacao { hosts: BTreeSet::new(), pedidos: 0, erros: 0, g: Grupo::default() });
        r.hosts.insert(host.to_ascii_lowercase());
        r.pedidos += 1;
        r.erros += u64::from(!matches!(h.status, Some(200..=399)));
        r.g.somar(h.ts_us, h.fluxo);
    }
    // Um alerta por cliente: as formas (POST e GET) do mesmo malware se somam.
    let mut por_cliente: BTreeMap<IpAddr, (BTreeSet<String>, u64, Grupo, String)> = BTreeMap::new();
    for ((cliente, _, forma), r) in grupos {
        if (r.hosts.len() as f64) < lim::ROTACAO_DOMINIOS || r.pedidos < 15 || r.erros * 2 < r.pedidos {
            continue;
        }
        let c = por_cliente.entry(cliente).or_insert_with(|| (BTreeSet::new(), 0, Grupo::default(), forma.clone()));
        c.0.extend(r.hosts);
        c.1 += r.pedidos;
        c.2.inicio = c.2.inicio.min(r.g.inicio);
        c.2.fim = c.2.fim.max(r.g.fim);
        for f in r.g.fluxos {
            if c.2.fluxos.len() < MAX_EVIDENCIAS {
                c.2.fluxos.insert(f);
            }
        }
    }
    for (cliente, (hosts, pedidos, g, forma)) in por_cliente {
        let exemplos: Vec<&str> = hosts.iter().take(4).map(String::as_str).collect();
        saida.push(alerta(
            Novo {
                regra: "c2_rotativo",
                severidade: "alta",
                host: cliente,
                alvo: None,
                alvo_ip: None,
                parametros: vec![
                    ("dominios", hosts.len().to_string()),
                    ("pedidos", pedidos.to_string()),
                    ("forma", forma.chars().take(80).collect()),
                    ("exemplos", exemplos.join(", ")),
                ],
            },
            g,
        ));
    }
}

/// HTTP ou TLS confirmados pelo conteúdo, para fora, numa porta fora do comum.
fn porta_incomum(d: &Dados, saida: &mut Vec<Alerta>) {
    let mut grupos: BTreeMap<(IpAddr, IpAddr, u16, &str), Grupo> = BTreeMap::new();
    for f in d.fluxos {
        let (Some(app), false) = (f.aplicacao, f.aplicacao_por_porta) else { continue };
        let comum = match app {
            "HTTP" => matches!(f.porta_destino, 80 | 8080 | 8000 | 8008 | 8888 | 3128 | 591),
            "TLS" => matches!(
                f.porta_destino,
                443 | 8443 | 993 | 995 | 465 | 587 | 636 | 853 | 989 | 990 | 3269 | 5061 | 5223 | 4443 | 9443
            ),
            _ => true,
        };
        if !comum && para_fora(&f.origem, &f.destino) {
            grupos.entry((f.origem, f.destino, f.porta_destino, app)).or_default().somar(f.inicio_us, f.id);
        }
    }
    for ((origem, destino, porta, app), g) in grupos {
        saida.push(alerta(
            Novo {
                regra: "porta_incomum",
                severidade: "baixa",
                host: origem,
                alvo: Some(d.nome_ou_ip(&destino)),
                alvo_ip: Some(destino),
                parametros: vec![("protocolo", app.into()), ("porta", porta.to_string())],
            },
            g,
        ));
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    /// A interface lê a tabela de regras de um JSON: os dois precisam bater.
    #[test]
    fn regras_sincronizadas_com_a_interface() {
        let json: Vec<serde_json::Value> = serde_json::from_str(include_str!("../../web/src/regras.json")).unwrap();
        assert_eq!(json.len(), REGRAS.len());
        for (j, r) in json.iter().zip(REGRAS) {
            assert_eq!(j["regra"], r.regra);
            assert_eq!(j["tecnica"].as_str(), r.tecnica, "{}", r.regra);
            assert_eq!(j["fase"], r.fase, "{}", r.regra);
            let d3: Vec<&str> = j["d3fend"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
            assert_eq!(d3, r.d3fend, "{}", r.regra);
        }
    }

    /// Toda técnica e contramedida citada existe nos dados oficiais da MITRE.
    #[test]
    fn ids_existem_na_mitre() {
        let m: serde_json::Value = serde_json::from_str(include_str!("../../web/src/mitre.json")).unwrap();
        let tecnicas: Vec<&str> = m["tecnicas"].as_array().unwrap().iter().map(|t| t["id"].as_str().unwrap()).collect();
        for r in REGRAS {
            if let Some(t) = r.tecnica {
                assert!(tecnicas.contains(&t), "{t} não existe no ATT&CK");
            }
            for d in r.d3fend {
                assert!(m["defesas"].get(d).is_some(), "{d} não existe no D3FEND");
            }
        }
    }

    #[test]
    fn url_decodificada() {
        assert_eq!(decodificar_url("/download?file=..%2F..%2Fetc%2Fpasswd"), "/download?file=../../etc/passwd");
        assert_eq!(decodificar_url("%252e%252e%252f"), "../");
        assert_eq!(decodificar_url("a+b%zz"), "a b%zz");
    }

    #[test]
    fn navegadores_obsoletos() {
        assert!(navegador_obsoleto("mozilla/5.0 (windows nt 6.2; rv:39.0) gecko/20100101 firefox/39.0"));
        assert!(navegador_obsoleto("mozilla/5.0 applewebkit/537.36 chrome/49.0.2623.112 safari/537.36"));
        assert!(!navegador_obsoleto("mozilla/5.0 (windows nt 10.0; rv:131.0) gecko/20100101 firefox/131.0"));
        assert!(!navegador_obsoleto("mozilla/5.0 applewebkit/537.36 chrome/130.0.0.0 safari/537.36 edg/130.0"));
        assert!(!navegador_obsoleto("microsoft-delivery-optimization/10.1"));
    }

    #[test]
    fn conhecidos_por_sufixo() {
        assert!(conhecido("download.windowsupdate.com"));
        assert!(conhecido("google.com."));
        assert!(!conhecido("notgoogle.com"));
        assert!(!conhecido("cdn-sync.top"));
    }
}
