//! "Por que não disparou": para cada regra que ficou quieta, o caso da
//! captura que chegou mais perto, com cada condição medida contra o limiar.
//! Os agrupamentos são os mesmos das regras em `deteccao.rs`; se um limiar
//! mudar lá, muda aqui também (um teste confere os dois lados).

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::decodificacao::lado_de_dentro;
use crate::deteccao::{conhecido, mediana, para_fora, Dados, REGRAS};
use crate::relatorio::{Alerta, CasoProximo, Condicao, Diagnostico};

pub const BEACON_CONEXOES: f64 = 6.0;
pub const BEACON_INTERVALO_S: f64 = 5.0;
pub const BEACON_REGULARES_PCT: f64 = 80.0;
pub const DGA_NXDOMAIN: f64 = 15.0;
pub const TUNEL_UNICOS: f64 = 20.0;
pub const TUNEL_TAMANHO: f64 = 40.0;
pub const TUNEL_TXT: f64 = 20.0;
pub const VARREDURA: f64 = 10.0;
pub const LATERAL_DESTINOS: f64 = 3.0;
pub const EXFIL_MB: f64 = 50.0;
pub const EXFIL_PROPORCAO: f64 = 5.0;
pub const BRUTA_FALHAS: f64 = 10.0;
pub const SONDAGEM_UDP: f64 = 20.0;

fn condicao(medida: &'static str, valor: f64, limiar: f64) -> Condicao {
    Condicao { medida, valor: (valor * 10.0).round() / 10.0, limiar, ok: valor >= limiar }
}

/// Quão perto o caso está de disparar (1 por condição cumprida).
fn pontos(c: &[Condicao]) -> f64 {
    c.iter().map(|x| if x.limiar > 0.0 { (x.valor / x.limiar).min(1.0) } else { 1.0 }).sum()
}

struct Melhor {
    caso: Option<CasoProximo>,
    pontos: f64,
}

impl Melhor {
    fn novo() -> Self {
        Self { caso: None, pontos: -1.0 }
    }

    fn considerar(&mut self, host: IpAddr, alvo: Option<String>, condicoes: Vec<Condicao>) {
        let p = pontos(&condicoes);
        if p > self.pontos {
            self.pontos = p;
            self.caso = Some(CasoProximo { host, alvo, condicoes });
        }
    }
}

pub fn diagnosticar(d: &Dados, alertas: &[Alerta]) -> Vec<Diagnostico> {
    let disparou: BTreeSet<&str> = alertas.iter().map(|a| a.regra).collect();
    REGRAS
        .iter()
        .map(|r| {
            let (caso, inspecionados) = if disparou.contains(r.regra) { (None, 0) } else { mais_perto(d, r.regra) };
            Diagnostico { regra: r.regra, disparou: disparou.contains(r.regra), inspecionados, caso }
        })
        .collect()
}

fn mais_perto(d: &Dados, regra: &str) -> (Option<CasoProximo>, u64) {
    let mut m = Melhor::novo();
    let inspecionados = match regra {
        "beaconing" => {
            let mut grupos: BTreeMap<(IpAddr, IpAddr, u16), Vec<u64>> = BTreeMap::new();
            for f in d.fluxos {
                if para_fora(&f.origem, &f.destino) && (f.protocolo == "TCP" || f.protocolo == "UDP") {
                    grupos.entry((f.origem, f.destino, f.porta_destino)).or_default().push(f.inicio_us);
                }
            }
            for ((o, dst, _), mut ts) in grupos.iter().map(|(k, v)| (*k, v.clone())) {
                ts.sort_unstable();
                let mut iv: Vec<f64> = ts.windows(2).map(|w| (w[1] - w[0]) as f64 / 1e6).collect();
                let med = mediana(&mut iv);
                let regulares = if iv.is_empty() {
                    0.0
                } else {
                    iv.iter().filter(|x| (*x - med).abs() <= 0.2 * med).count() as f64 / iv.len() as f64 * 100.0
                };
                m.considerar(
                    o,
                    Some(d.nome_ou_ip(&dst)),
                    vec![
                        condicao("conexoes", ts.len() as f64, BEACON_CONEXOES),
                        condicao("intervalo_s", med, BEACON_INTERVALO_S),
                        condicao("regulares_pct", regulares, BEACON_REGULARES_PCT),
                    ],
                );
            }
            grupos.len() as u64
        }
        "dga" => {
            let mut por: BTreeMap<IpAddr, BTreeSet<&str>> = BTreeMap::new();
            for e in d.dns.iter().filter(|e| e.rcode == Some(3)) {
                por.entry(e.cliente).or_default().insert(&e.consulta);
            }
            for (c, nomes) in por {
                m.considerar(c, None, vec![condicao("dominios_inexistentes", nomes.len() as f64, DGA_NXDOMAIN)]);
            }
            d.dns.len() as u64
        }
        "tunel_dns" => {
            let mut por: BTreeMap<(IpAddr, &str), (BTreeSet<&str>, u64, u64, u64)> = BTreeMap::new();
            for e in d.dns {
                let Some((_, zona)) = e.consulta.split_once('.') else { continue };
                if !zona.contains('.') || conhecido(zona) {
                    continue;
                }
                let a = por.entry((e.cliente, zona)).or_default();
                a.0.insert(&e.consulta);
                a.1 += 1;
                a.2 += e.consulta.len() as u64;
                a.3 += (e.tipo == "TXT") as u64;
            }
            for ((c, zona), (unicos, n, soma, txt)) in por {
                m.considerar(
                    c,
                    Some(zona.to_owned()),
                    vec![
                        condicao("nomes_unicos", unicos.len() as f64, TUNEL_UNICOS),
                        condicao("tamanho_medio", soma as f64 / n.max(1) as f64, TUNEL_TAMANHO),
                        condicao("consultas_txt", txt as f64, TUNEL_TXT),
                    ],
                );
            }
            d.dns.len() as u64
        }
        "varredura_portas" | "varredura_hosts" => {
            let mut por: BTreeMap<(IpAddr, Option<IpAddr>, Option<u16>), BTreeSet<String>> = BTreeMap::new();
            let portas = regra == "varredura_portas";
            for f in d.fluxos.iter().filter(|f| f.protocolo == "TCP" && matches!(f.estado, "sem_resposta" | "recusada")) {
                let chave = if portas { (f.origem, Some(f.destino), None) } else { (f.origem, None, Some(f.porta_destino)) };
                let valor = if portas { f.porta_destino.to_string() } else { f.destino.to_string() };
                por.entry(chave).or_default().insert(valor);
            }
            for ((o, dst, porta), itens) in por {
                let alvo = dst.map(|x| d.nome_ou_ip(&x)).or(porta.map(|p| format!(":{p}")));
                let medida = if portas { "portas_sem_resposta" } else { "hosts_sem_resposta" };
                m.considerar(o, alvo, vec![condicao(medida, itens.len() as f64, VARREDURA)]);
            }
            d.fluxos.iter().filter(|f| f.protocolo == "TCP").count() as u64
        }
        "movimentacao_lateral" => {
            let mut por: BTreeMap<IpAddr, BTreeSet<IpAddr>> = BTreeMap::new();
            for f in d.fluxos {
                let admin = matches!(f.aplicacao, Some("SMB" | "RDP" | "WinRM" | "RPC" | "SSH"));
                if admin && lado_de_dentro(&f.origem) && lado_de_dentro(&f.destino) && !matches!(f.estado, "sem_resposta" | "recusada") {
                    por.entry(f.origem).or_default().insert(f.destino);
                }
            }
            for (o, destinos) in por {
                m.considerar(o, None, vec![condicao("destinos_internos", destinos.len() as f64, LATERAL_DESTINOS)]);
            }
            d.fluxos.len() as u64
        }
        "exfiltracao_volume" => {
            let mut por: BTreeMap<(IpAddr, IpAddr), (u64, u64)> = BTreeMap::new();
            for f in d.fluxos.iter().filter(|f| para_fora(&f.origem, &f.destino)) {
                let a = por.entry((f.origem, f.destino)).or_default();
                a.0 += f.bytes_ida;
                a.1 += f.bytes_volta;
            }
            for ((o, dst), (ida, volta)) in por {
                m.considerar(
                    o,
                    Some(d.nome_ou_ip(&dst)),
                    vec![
                        condicao("enviados_mb", ida as f64 / 1_048_576.0, EXFIL_MB),
                        condicao("proporcao", ida as f64 / volta.max(1) as f64, EXFIL_PROPORCAO),
                    ],
                );
            }
            d.fluxos.len() as u64
        }
        "forca_bruta" => {
            let mut por: BTreeMap<(IpAddr, IpAddr), u64> = BTreeMap::new();
            for h in d.http.iter().filter(|h| matches!(h.status, Some(401 | 403))) {
                *por.entry((h.cliente, h.servidor)).or_default() += 1;
            }
            for ((c, s), n) in por {
                m.considerar(c, Some(d.nome_ou_ip(&s)), vec![condicao("falhas_de_login", n as f64, BRUTA_FALHAS)]);
            }
            d.http.len() as u64
        }
        "sondagem_udp" => {
            let mut por: BTreeMap<(IpAddr, IpAddr), u64> = BTreeMap::new();
            for f in d.fluxos.iter().filter(|f| f.protocolo == "UDP" && f.estado == "sem_resposta" && f.porta_destino != 53) {
                *por.entry((f.origem, f.destino)).or_default() += 1;
            }
            for ((o, dst), n) in por {
                m.considerar(o, Some(d.nome_ou_ip(&dst)), vec![condicao("mensagens_sem_resposta", n as f64, SONDAGEM_UDP)]);
            }
            d.fluxos.iter().filter(|f| f.protocolo == "UDP").count() as u64
        }
        // Regras de sim ou não (um padrão aparece ou não): não há "quase".
        // Fica o quanto foi olhado.
        "download_executavel" | "ataque_web" | "credencial_em_claro" | "user_agent_suspeito" => d.http.len() as u64,
        "tls_antigo" | "certificado_suspeito" => d.tls.len() as u64,
        _ => d.fluxos.len() as u64,
    };
    (m.caso, inspecionados)
}
