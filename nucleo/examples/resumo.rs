//! Lê uma captura em blocos de 8 MB, como o navegador faz, e imprime o
//! relatório em JSON.
//!
//!     cargo run --release -p panthera-wire-nucleo --example resumo -- captura.pcap

use std::fs::File;
use std::io::Read;
use std::time::Instant;

use panthera_wire_nucleo::Analise;

fn main() -> std::io::Result<()> {
    let caminho = std::env::args().nth(1).expect("uso: resumo <captura>");
    let mut arquivo = File::open(&caminho)?;
    let mut bloco = vec![0u8; 8 * 1024 * 1024];
    let mut analise = Analise::new();
    let inicio = Instant::now();
    let mut lidos = 0u64;
    loop {
        let n = arquivo.read(&mut bloco)?;
        if n == 0 {
            break;
        }
        lidos += n as u64;
        if let Err(e) = analise.alimentar(&bloco[..n]) {
            eprintln!("parou: {} no offset {}", e.codigo, e.offset);
            break;
        }
    }
    let relatorio = analise.finalizar();
    let s = inicio.elapsed().as_secs_f64();
    eprintln!(
        "{} MB, {} pacotes, {} fluxos em {:.2} s ({:.0} MB/s)",
        lidos / 1_048_576,
        relatorio.captura.pacotes,
        relatorio.total_fluxos,
        s,
        lidos as f64 / 1_048_576.0 / s
    );
    println!("{}", serde_json::to_string_pretty(&relatorio).unwrap());
    Ok(())
}
