<p align="center">
  <img src="web/public/pantera.webp" width="140" alt="Panthera Wire" />
</p>

<h1 align="center">Panthera Wire</h1>
<p align="center"><i>See beyond the packets.</i></p>

Leitor de capturas de rede (pcap e pcapng) feito para a comunidade de
cibersegurança. Em vez de mostrar pacote por pacote, mostra **o que
aconteceu**: quem falou com quem, o que foi resolvido, baixado e enviado, e o
que merece atenção.

- **A captura vira uma história:** o que aconteceu, em que ordem e com que
  confiança, com cada frase ligada à evidência.
- **Anonimizador** para compartilhar capturas com a comunidade sem expor
  pessoas, credenciais ou a rede de origem: endereços trocados preservando a
  rede, nomes internos mascarados, conteúdo cortado e um relatório do que
  ainda pode identificar alguém.
- **Nada sai do seu navegador.** Sem upload, sem servidor, sem telemetria, e
  funciona offline, inclusive em rede isolada.
- **Capturas de vários GB**, lidas aos poucos sem travar a página.
- **Resumo antes do detalhe:** visão geral, linha do tempo, fluxos, hosts, DNS,
  TLS (com JA3, JA4 e certificado) e HTTP, e os **pacotes** um a um, com camadas
  e bytes, quando precisar descer até lá.
- **Alertas explicados**, com a técnica MITRE ATT&CK e as contramedidas
  MITRE D3FEND de cada um.
- **Cobertura MITRE completa:** todas as técnicas do ATT&CK Enterprise e todas
  as contramedidas do D3FEND, dizendo o que é detectado, o que é visível na rede
  e o que só se vê dentro da máquina.
- **Exportação para CTI:** JSON completo, CSV de IOCs e bundle STIX 2.1.
- **Interface em português, inglês e espanhol.**

> Em construção. O plano completo está em [docs/ARQUITETURA.md](docs/ARQUITETURA.md).

## Desenvolvimento

Precisa de Node 22, Rust estável com o alvo `wasm32-unknown-unknown` e o
`wasm-bindgen-cli` na versão **0.2.129** (a mesma de `wasm/Cargo.toml`).

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.129
```

```bash
cargo test -p panthera-wire-nucleo     # testes do núcleo
cd web
npm install
npm run nucleo                         # compila o núcleo para WASM
npm run dev
```

O núcleo também roda direto no terminal, útil para medir desempenho:

```bash
cargo run --release -p panthera-wire-nucleo --example resumo -- captura.pcap
```

Capturas de teste: `python scripts/gerar_amostra.py amostras/` gera o cenário
de exemplo, e `--grande 1024` gera um arquivo de cerca de 1 GB.

Dados da MITRE: `python -I scripts/gerar_mitre.py <pasta>` regenera
`web/src/mitre.json` a partir de `enterprise-attack.json` e `d3fend.json`.

## Licença

GPL-2.0 ou posterior (veja [LICENSE](LICENSE)). O detalhe pacote a pacote vai
usar o Wireshark compilado para WebAssembly, que também é GPL.

## Atribuição

MITRE ATT&CK® e MITRE D3FEND™ são da The MITRE Corporation e são usados
conforme os termos de uso da MITRE.
