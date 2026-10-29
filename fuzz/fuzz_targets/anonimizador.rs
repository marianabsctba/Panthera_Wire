//! Um pacote qualquer passado pelo anonimizador, nos dois modos de conteúdo.
//! A saída precisa continuar sendo uma captura que o próprio núcleo lê.
#![no_main]

mod comum;

use libfuzzer_sys::fuzz_target;
use panthera_wire_nucleo::anonimizador::{Anonimizador, Conteudo, Enderecos, Opcoes};
use panthera_wire_nucleo::Analise;

fuzz_target!(|dados: &[u8]| {
    let pcap = comum::pcap_de_um_pacote(dados);
    for conteudo in [Conteudo::Cabecalhos, Conteudo::Protocolos] {
        let op = Opcoes {
            chave: "00112233445566778899aabbccddeeff".into(),
            enderecos: Enderecos::Todos,
            conteudo,
            manter_fabricante: false,
            deslocar_horarios: true,
            nomes_internos: vec!["host".into()],
            dominios_internos: vec!["exemplo.com".into()],
        };
        let mut anon = Anonimizador::new(op).unwrap();
        let mut saida = anon.alimentar(&pcap).unwrap_or_default();
        let (resto, _) = anon.finalizar();
        saida.extend(resto);

        let mut a = Analise::new();
        assert!(a.alimentar(&saida).is_ok(), "o anonimizador gerou uma captura ilegível");
        let _ = a.finalizar();
    }
});
