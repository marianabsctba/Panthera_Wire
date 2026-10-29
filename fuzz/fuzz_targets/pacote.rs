//! Um pacote qualquer dentro de um pcap válido: exercita enlace, IP,
//! transporte e os leitores de DNS, HTTP, TLS e DHCP, e depois a detecção e a
//! história sobre o que sair dele.
#![no_main]

mod comum;

use libfuzzer_sys::fuzz_target;
use panthera_wire_nucleo::Analise;

fuzz_target!(|dados: &[u8]| {
    let mut a = Analise::new();
    let _ = a.alimentar(&comum::pcap_de_um_pacote(dados));
    let _ = a.finalizar();
});
