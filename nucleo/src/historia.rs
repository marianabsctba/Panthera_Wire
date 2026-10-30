//! Monta a história da captura a partir dos alertas: para cada host interno,
//! a sequência de fatos no tempo, ligada por destino em comum e proximidade,
//! com uma confiança que cresce quando fases diferentes de um ataque
//! aparecem na ordem esperada.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::decodificacao::{escopo, lado_de_dentro, lado_de_fora};
use crate::relatorio::{Alerta, Cadeia, Fluxo, Historia, Passo};

/// Ordem das fases numa intrusão típica. `higiene` fica fora das cadeias.
fn ordem(fase: &str) -> Option<u8> {
    Some(match fase {
        "acesso_inicial" | "entrega" => 1,
        "comando_e_controle" => 2,
        "credenciais" => 3,
        "descoberta" => 3,
        "movimentacao_lateral" => 4,
        "exfiltracao" => 5,
        _ => return None,
    })
}

/// Dois fatos até 30 minutos um do outro contam como "pouco depois".
const PROXIMO_US: u64 = 30 * 60 * 1_000_000;

/// Sinais de comando e controle que programa legítimo quase nunca produz, e por
/// isso não precisam dividir destino com a entrega. Beaconing fica de fora (jogo
/// e atualizador também consultam servidor em intervalos regulares), assim como
/// certificado ruim, que aparece em serviço legítimo.
const CONTROLE_FORTE: &[&str] = &["protocolo_disfarcado", "c2_rotativo"];

/// Entrega e controle só se sustentam juntos com algo que os ligue: o mesmo
/// destino ou um sinal forte. Coincidir no tempo não basta: muito malware baixa
/// de um servidor e fala com outro, mas um programa comum também.
fn ligados(entrega: &Alerta, controle: &Alerta) -> bool {
    let mesmo_ip = entrega.alvo_ip.is_some() && entrega.alvo_ip == controle.alvo_ip;
    let mesmo_nome = entrega.alvo.is_some() && entrega.alvo == controle.alvo;
    mesmo_ip || mesmo_nome || CONTROLE_FORTE.contains(&controle.regra)
}

pub struct Contexto<'a> {
    pub alertas: &'a [Alerta],
    pub fluxos: &'a [Fluxo],
    pub tem_tls: bool,
    pub tem_avisos: bool,
}

pub fn montar(c: &Contexto) -> Historia {
    let mut por_host: BTreeMap<IpAddr, Vec<&Alerta>> = BTreeMap::new();
    for a in c.alertas {
        if ordem(a.fase).is_some() && escopo(&a.host) != "multicast" {
            por_host.entry(a.host).or_default().push(a);
        }
    }

    let mut cadeias = Vec::new();
    for (host, mut fatos) in por_host {
        fatos.sort_by_key(|a| a.inicio_us);
        // Alertas de severidade baixa entram na sequência, mas não contam
        // como fase: sozinhos não sustentam uma história.
        let fases: BTreeSet<&str> = fatos.iter().filter(|a| a.severidade != "baixa").map(|a| a.fase).collect();
        let altas = fatos.iter().filter(|a| a.severidade == "alta").count();
        // Um fato isolado de severidade baixa ou média não é história, é só um alerta.
        if fases.len() < 2 && altas == 0 {
            continue;
        }

        let entrega = |a: &&&Alerta| matches!(a.fase, "entrega" | "acesso_inicial") && a.severidade != "baixa";
        let controle = |a: &&&Alerta| a.fase == "comando_e_controle" && a.severidade != "baixa";
        let entrega_e_controle = fatos.iter().filter(entrega).any(|e| {
            fatos.iter().filter(controle).any(|c| {
                c.inicio_us >= e.inicio_us && c.inicio_us - e.inicio_us <= PROXIMO_US && ligados(e, c)
            })
        });
        let sem_ligacao = fases.len() == 2 && fatos.iter().any(|a| entrega(&a)) && fatos.iter().any(|a| controle(&a));
        // A confiança mede o quanto os fatos formam uma intrusão encadeada,
        // não a certeza de cada alerta. O motivo vai junto para a interface
        // explicar.
        let (confianca, motivo) = if entrega_e_controle {
            ("alta", "entrega_e_controle")
        } else if fases.len() >= 3 {
            ("alta", "tres_fases")
        } else if sem_ligacao {
            ("media", "sem_ligacao")
        } else if fases.len() >= 2 && altas >= 2 {
            ("alta", "duas_graves")
        } else if fases.len() == 2 {
            ("media", "duas_fases")
        } else {
            ("baixa", "uma_grave")
        };

        let mut passos: Vec<Passo> = Vec::with_capacity(fatos.len());
        for (i, a) in fatos.iter().enumerate() {
            let ligacao = (i > 0).then(|| {
                let anterior = fatos[i - 1];
                if a.alvo_ip.is_some() && a.alvo_ip == anterior.alvo_ip {
                    "mesmo_destino"
                } else if a.inicio_us.saturating_sub(anterior.inicio_us) <= PROXIMO_US {
                    "pouco_depois"
                } else {
                    "depois"
                }
            });
            passos.push(Passo { alerta: a.id, ts_us: a.inicio_us, fase: a.fase, ligacao });
        }
        cadeias.push(Cadeia {
            host,
            confianca,
            motivo,
            fases: fases.iter().copied().collect(),
            inicio_us: fatos.first().map_or(0, |a| a.inicio_us),
            fim_us: fatos.iter().map(|a| a.fim_us).max().unwrap_or(0),
            passos,
        });
    }

    let peso = |c: &str| match c {
        "alta" => 0,
        "media" => 1,
        _ => 2,
    };
    // Mais confiança primeiro; no empate, mais alertas graves, depois um host
    // da rede observada antes de um de fora, e o que começou antes.
    let gravidade: BTreeMap<u32, u32> = c
        .alertas
        .iter()
        .map(|a| (a.id, match a.severidade { "alta" => 3, "media" => 2, _ => 0 }))
        .collect();
    let pontos = |cad: &Cadeia| -> u32 { cad.passos.iter().map(|p| gravidade.get(&p.alerta).copied().unwrap_or(0)).sum() };
    cadeias.sort_by_key(|cad| (peso(cad.confianca), std::cmp::Reverse(pontos(cad)), !lado_de_dentro(&cad.host), cad.inicio_us));
    let paciente_zero = cadeias.first().map(|c| c.host);

    // Escopo: hosts com cadeia própria e hosts internos que falaram com os
    // destinos suspeitos (severidade média ou alta) do paciente zero.
    let mut afetados: BTreeSet<IpAddr> = cadeias.iter().map(|c| c.host).collect();
    if let Some(pz) = paciente_zero {
        let suspeitos: BTreeSet<IpAddr> = c
            .alertas
            .iter()
            // Só destinos que fazem papel de atacante (comando, entrega,
            // exfiltração). O alvo de uma varredura ou de um ataque é vítima.
            .filter(|a| a.host == pz && a.severidade != "baixa")
            .filter(|a| matches!(a.fase, "comando_e_controle" | "entrega" | "exfiltracao"))
            .filter_map(|a| a.alvo_ip)
            .filter(|ip| lado_de_fora(ip) && *ip != pz)
            .collect();
        for f in c.fluxos {
            if suspeitos.contains(&f.destino) && lado_de_dentro(&f.origem) {
                afetados.insert(f.origem);
            }
        }
        afetados.remove(&pz);
    }

    let mut nao_mostra = vec!["fora_do_periodo", "ponto_de_captura"];
    if c.tem_tls {
        nao_mostra.push("conteudo_cifrado");
    }
    nao_mostra.push("sem_remontagem");
    if c.tem_avisos {
        nao_mostra.push("captura_incompleta");
    }

    Historia { paciente_zero, hosts_afetados: afetados.into_iter().collect(), cadeias, nao_mostra }
}

#[cfg(test)]
mod testes {
    use super::*;

    const INSTANTE: u64 = 1_700_000_000_000_000;

    fn alerta(id: u32, regra: &'static str, severidade: &'static str, fase: &'static str, seg: u64, alvo: &str) -> Alerta {
        Alerta {
            id,
            regra,
            severidade,
            fase,
            tecnica: None,
            inicio_us: INSTANTE + seg * 1_000_000,
            fim_us: INSTANTE + seg * 1_000_000,
            host: "10.0.0.5".parse().unwrap(),
            alvo: Some(alvo.into()),
            alvo_ip: alvo.parse().ok(),
            parametros: BTreeMap::new(),
            fluxos: Vec::new(),
        }
    }

    fn resultado(alertas: &[Alerta]) -> (&'static str, &'static str) {
        let h = montar(&Contexto { alertas, fluxos: &[], tem_tls: false, tem_avisos: false });
        (h.cadeias[0].confianca, h.cadeias[0].motivo)
    }

    fn download(seg: u64, alvo: &str) -> Alerta {
        alerta(1, "download_executavel", "alta", "entrega", seg, alvo)
    }

    fn beaconing(seg: u64, alvo: &str) -> Alerta {
        alerta(2, "beaconing", "alta", "comando_e_controle", seg, alvo)
    }

    /// Baixar um jogo e ele consultar outro servidor não é história de intrusão.
    #[test]
    fn download_e_beaconing_sem_ligacao_ficam_em_media() {
        assert_eq!(resultado(&[download(0, "198.51.100.1"), beaconing(60, "203.0.113.9")]), ("media", "sem_ligacao"));
    }

    #[test]
    fn mesmo_destino_liga_entrega_e_controle() {
        assert_eq!(resultado(&[download(0, "203.0.113.9"), beaconing(60, "203.0.113.9")]), ("alta", "entrega_e_controle"));
        assert_eq!(resultado(&[download(0, "jogo.example"), beaconing(60, "jogo.example")]), ("alta", "entrega_e_controle"));
    }

    /// Como na infecção real de 2026-10-01: baixa de um servidor e, segundos
    /// depois, fala com outro por um protocolo disfarçado.
    #[test]
    fn sinal_forte_dispensa_o_mesmo_destino() {
        let disfarcado = alerta(2, "protocolo_disfarcado", "media", "comando_e_controle", 8, "203.0.113.9");
        assert_eq!(resultado(&[download(0, "198.51.100.1"), disfarcado]), ("alta", "entrega_e_controle"));
    }

    #[test]
    fn certificado_ruim_nao_e_sinal_forte() {
        let cert = alerta(2, "certificado_suspeito", "media", "comando_e_controle", 8, "203.0.113.9");
        assert_eq!(resultado(&[download(0, "198.51.100.1"), cert]), ("media", "sem_ligacao"));
    }

    #[test]
    fn longe_no_tempo_nao_liga_mesmo_com_o_mesmo_destino() {
        assert_eq!(resultado(&[download(0, "203.0.113.9"), beaconing(3600, "203.0.113.9")]), ("media", "sem_ligacao"));
    }

    /// Download de fonte conhecida tem severidade baixa e não conta como entrega.
    #[test]
    fn entrega_de_severidade_baixa_nao_liga() {
        let baixa = alerta(1, "download_executavel", "baixa", "entrega", 0, "203.0.113.9");
        assert_eq!(resultado(&[baixa, beaconing(60, "203.0.113.9")]), ("baixa", "uma_grave"));
    }

    #[test]
    fn tres_fases_continuam_altas_sem_ligacao() {
        let exfil = alerta(3, "exfiltracao_volume", "alta", "exfiltracao", 120, "192.0.2.7");
        assert_eq!(resultado(&[download(0, "198.51.100.1"), beaconing(60, "203.0.113.9"), exfil]), ("alta", "tres_fases"));
    }

    #[test]
    fn duas_fases_graves_sem_entrega_continuam_altas() {
        let exfil = alerta(3, "exfiltracao_volume", "alta", "exfiltracao", 120, "192.0.2.7");
        assert_eq!(resultado(&[beaconing(60, "203.0.113.9"), exfil]), ("alta", "duas_graves"));
    }
}
