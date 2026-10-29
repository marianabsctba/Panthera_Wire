//! Lê as capturas de `amostras/` (geradas por `scripts/gerar_amostra.py`) e
//! confere o relatório de ponta a ponta.

use panthera_wire_nucleo::{Analise, Relatorio};

const PCAP: &[u8] = include_bytes!("../../amostras/exemplo.pcap");
const PCAPNG: &[u8] = include_bytes!("../../amostras/exemplo.pcapng");

fn analisar(arquivo: &[u8], bloco: usize) -> Relatorio {
    let mut a = Analise::new();
    for parte in arquivo.chunks(bloco) {
        a.alimentar(parte).unwrap();
    }
    a.finalizar()
}

#[test]
fn cenario_completo() {
    let r = analisar(PCAP, 8 * 1024 * 1024);
    assert_eq!(r.captura.formato, "pcap");
    assert_eq!(r.captura.pacotes, 101);
    assert!(r.captura.avisos.is_empty());

    let estacao = r.hosts.iter().find(|h| h.ip.to_string() == "10.0.0.5").unwrap();
    assert!(estacao.nomes.contains("desktop-fin01"));
    assert_eq!(estacao.mac.as_deref(), Some("3c:52:82:0a:0b:0c"));
    assert!(r.hosts.iter().all(|h| !h.ip.is_unspecified()));

    let c2 = r.hosts.iter().find(|h| h.ip.to_string() == "198.51.100.7").unwrap();
    assert!(c2.nomes.contains("cdn-sync.top"));

    let beacons = r.tls.iter().filter(|t| t.sni.as_deref() == Some("cdn-sync.top")).count();
    assert_eq!(beacons, 10);
    assert!(r.tls.iter().all(|t| t.versao.as_deref() == Some("TLS 1.3")));

    let download = &r.http[0];
    assert_eq!(download.caminho, "/patch/KB5031.exe");
    assert_eq!(download.status, Some(200));
    assert_eq!(download.tipo_conteudo.as_deref(), Some("application/x-msdownload"));

    let nx = r.dns.iter().find(|d| d.consulta == "qx7kz2v9lmw3.info").unwrap();
    assert_eq!(nx.rcode, Some(3));

    let rdp = r.fluxos.iter().find(|f| f.porta_destino == 3389).unwrap();
    assert_eq!((rdp.aplicacao, rdp.aplicacao_por_porta, rdp.estado), (Some("RDP"), true, "recusada"));
}

#[test]
fn pcap_e_pcapng_dao_o_mesmo_resultado() {
    let a = analisar(PCAP, 4096);
    let b = analisar(PCAPNG, 4096);
    assert_eq!(b.captura.formato, "pcapng");
    assert_eq!(a.captura.pacotes, b.captura.pacotes);
    assert_eq!(a.total_fluxos, b.total_fluxos);
    assert_eq!(a.total_dns, b.total_dns);
    assert_eq!(a.total_tls, b.total_tls);
    // Os horários batem até o microssegundo (o gerador arredonda em float).
    assert!(a.captura.inicio_us.abs_diff(b.captura.inicio_us) <= 1);
}

#[test]
fn qualquer_tamanho_de_bloco() {
    let referencia = analisar(PCAPNG, usize::MAX);
    for bloco in [1, 7, 100, 1500] {
        let r = analisar(PCAPNG, bloco);
        assert_eq!(r.captura.pacotes, referencia.captura.pacotes, "bloco de {bloco}");
        assert_eq!(r.total_fluxos, referencia.total_fluxos, "bloco de {bloco}");
    }
}

#[test]
fn arquivo_cortado_entrega_o_que_deu() {
    let r = analisar(&PCAP[..PCAP.len() - 50], 1024);
    assert!(r.captura.pacotes > 90);
    assert_eq!(r.captura.avisos[0].codigo, "arquivo_truncado");
}

#[test]
fn bytes_corrompidos_nao_derrubam() {
    // Embaralha o miolo do arquivo de várias formas: pode parar com erro,
    // nunca com pânico.
    for semente in 0..64u32 {
        let mut v = PCAPNG.to_vec();
        let mut x = semente.wrapping_mul(2_654_435_761).wrapping_add(1);
        for _ in 0..40 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let i = 64 + (x as usize % (v.len() - 64));
            v[i] = (x >> 8) as u8;
        }
        let mut a = Analise::new();
        let _ = a.alimentar(&v);
        let _ = a.finalizar();
    }
}
