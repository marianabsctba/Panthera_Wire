//! Arquivo inteiro vindo do fuzzer, entregue ao núcleo em blocos de tamanhos
//! variados (o primeiro byte escolhe o tamanho), como o navegador faz.
#![no_main]

use libfuzzer_sys::fuzz_target;
use panthera_wire_nucleo::Analise;

fuzz_target!(|dados: &[u8]| {
    let Some((&tam, arquivo)) = dados.split_first() else { return };
    let bloco = 1 + tam as usize * 7;
    let mut a = Analise::new();
    for parte in arquivo.chunks(bloco) {
        if a.alimentar(parte).is_err() {
            break;
        }
    }
    let _ = a.finalizar();
});
