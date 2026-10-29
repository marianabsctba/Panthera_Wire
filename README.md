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
  pessoas, credenciais ou a rede de origem.
- **Nada sai do seu navegador.** Sem upload, sem servidor, sem telemetria, e
  funciona offline, inclusive em rede isolada.
- **Capturas de vários GB**, lidas aos poucos sem travar a página.
- **Resumo antes do detalhe:** visão geral, linha do tempo, fluxos, hosts, DNS,
  TLS e HTTP.
- **Alertas explicados**, com a técnica MITRE ATT&CK quando houver.
- **Exportação** em JSON, CSV de IOCs e STIX 2.1.
- **Interface em português, inglês e espanhol.**

> Em construção. O plano completo está em [docs/ARQUITETURA.md](docs/ARQUITETURA.md).

## Rodando a interface localmente

```bash
cd web
npm install
npm run dev
```
