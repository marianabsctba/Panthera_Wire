//! Um pacote qualquer dentro de um pcap válido: exercita enlace, IP,
//! transporte e os leitores de DNS, HTTP, TLS e DHCP, e depois a detecção e a
//! história sobre o que sair dele, e a visão pacote a pacote.
#![no_main]

mod comum;

use libfuzzer_sys::fuzz_target;
use panthera_wire_nucleo::pacotes::{Filtro, ListaPacotes};
use panthera_wire_nucleo::Analise;

fuzz_target!(|dados: &[u8]| {
    let pcap = comum::pcap_de_um_pacote(dados);
    let mut a = Analise::new();
    let _ = a.alimentar(&pcap);
    let _ = a.finalizar();
    // E a visão pacote a pacote, que decodifica campo a campo.
    let mut l = ListaPacotes::new(Filtro { limite: 10, ..Default::default() });
    l.alimentar(&pcap);
    let _ = l.finalizar();
});
