# Panthera Wire: arquitetura

Leitor de capturas de rede (pcap e pcapng) para a comunidade de cibersegurança.
Em vez de mostrar pacote por pacote, mostra **o que aconteceu**: quem falou com
quem, o que foi resolvido, baixado e enviado, e o que merece atenção.

## Princípios

1. **Nada sai do navegador.** A análise roda inteira na máquina de quem abriu a
   página. Não há servidor, upload, telemetria nem dependência de CDN em tempo
   de execução. O site é estático e fica no GitHub Pages.
2. **Arquivos de GB.** O pcap nunca é carregado inteiro na memória. É lido em
   blocos, indexado numa passada só, e os detalhes são relidos do arquivo
   original sob demanda.
3. **Entrada hostil.** Todo pcap é tratado como não confiável: parser sem
   `unsafe`, limites de tamanho em tudo, fuzzing contínuo.
4. **Resumo antes do detalhe.** A primeira tela responde "o que aconteceu aqui?".
   O pacote individual é o último nível, não o primeiro.

## Diferenciais

O que nenhuma outra ferramenta junta, e que guia as prioridades:

1. **A captura vira uma história.** Os eventos são correlacionados nas fases de
   um ataque e viram uma narrativa em linguagem natural, em que cada frase leva
   à evidência. Sem IA e sem internet: é determinístico e auditável.
2. **Anonimizador.** Gera um pcap sanitizado, com endereços trocados de forma
   consistente e credenciais e conteúdo removidos, para compartilhar com a
   comunidade, pedir ajuda ou montar treinamento.
3. **Funciona offline.** Instala como aplicativo pelo navegador e roda em rede
   isolada, sem instalar nada.

Detalhes de cada um nas seções "História da captura", "Anonimizador" e
"Offline", mais abaixo.

## Estrutura do repositório

```
panthera-wire/
├── nucleo/        Rust: leitura, decodificação, fluxos, protocolos, analisadores
├── wasm/          Rust: ponte do núcleo para o navegador (wasm-bindgen)
├── cli/           Rust: mesmo núcleo como binário nativo, para capturas enormes
├── web/           React + Vite + TypeScript (mesmo padrão visual do Panthera RE)
└── docs/
```

O núcleo não conhece navegador nem terminal. `wasm/` e `cli/` são só
adaptadores, como no Panthera RE.

## Fluxo de dados

```
Arquivo (File)
   │  File.slice em blocos de 8 MB
   ▼
Web Worker ──► nucleo.alimentar(bloco)
   │              │
   │              ├─ decodifica Ethernet, VLAN, IPv4, IPv6, TCP, UDP, ICMP
   │              ├─ agrupa em fluxos (5-tupla, com expiração por inatividade)
   │              ├─ dissectores de aplicação (DNS, HTTP, TLS, ...)
   │              └─ analisadores (beaconing, DNS anômalo, ...)
   │
   │  lotes de linhas (Arrow IPC), progresso, alertas
   ▼
DuckDB-WASM em OPFS  ◄──  consultas da interface
   │
   ▼
Interface (React)  ──► detalhe de um fluxo: relê só os offsets dele no arquivo
```

### Por que assim

- **Worker:** a leitura de GB não trava a tela, e a pessoa acompanha o progresso.
- **Fluxos com expiração:** um fluxo inativo há N segundos é finalizado e
  descarregado do worker. A memória fica proporcional aos fluxos ativos, não ao
  tamanho do arquivo.
- **DuckDB-WASM em OPFS:** milhões de fluxos e eventos ficam em disco local do
  navegador, e filtros, ordenações e agregações viram SQL rápido. O índice
  sobrevive a recarregar a página.
- **Offsets em vez de bytes:** o índice guarda onde cada pacote está no arquivo
  original, não o pacote. Abrir o detalhe de um fluxo custa uma releitura
  pequena e pontual.
- **Sem SharedArrayBuffer:** o GitHub Pages não permite configurar os
  cabeçalhos de isolamento (COOP/COEP). Usamos a versão do DuckDB-WASM e do
  núcleo que roda numa thread só por worker, e paralelizamos com mais de um
  worker quando fizer sentido.

## Modelo normalizado

| Tabela | Conteúdo principal |
|---|---|
| `captura` | arquivo, formato, tipo de enlace, início, fim, pacotes, bytes, pacotes descartados |
| `host` | IP, MAC, nomes vistos (DNS, DHCP, NetBIOS, SNI), interno ou externo, bytes enviados e recebidos |
| `fluxo` | id, 5-tupla, início, fim, pacotes e bytes por direção, protocolo de aplicação, flags TCP, estado |
| `pacote` | fluxo, offset no arquivo, tamanho, timestamp (só posição, nunca conteúdo) |
| `dns` | consulta, tipo, resposta, código, servidor, TTL |
| `http` | método, host, caminho, status, user agent, tipo e tamanho do conteúdo |
| `tls` | versão, SNI, ALPN, JA3, JA4, certificado (sujeito, emissor, validade, autoassinado) |
| `arquivo` | origem (HTTP, SMB, FTP), nome, tamanho, SHA256, tipo detectado |
| `alerta` | regra, severidade, explicação, evidências (ids), técnica MITRE ATT&CK |

## Contrato entre núcleo e interface

O worker fala com a interface por mensagens tipadas:

| Mensagem | Quando |
|---|---|
| `progresso` | a cada bloco: bytes lidos, pacotes, fluxos ativos |
| `lote` | linhas novas de uma tabela, em Arrow IPC |
| `alerta` | assim que um analisador dispara |
| `concluido` | fim da passada, com o resumo da captura |
| `erro` | arquivo inválido, truncado ou formato não suportado (com o ponto onde parou) |

A interface pede detalhe com `detalhe(fluxo_id)`, e o worker devolve os pacotes
decodificados daquele fluxo, relidos do arquivo.

## Protocolos

| Fase | Protocolos |
|---|---|
| 1 | Ethernet, VLAN, ARP, IPv4, IPv6, ICMP, TCP, UDP, DNS, HTTP/1.x, TLS (handshake), DHCP |
| 2 | SMB2/3, Kerberos, LDAP, NTLM, FTP, SMTP, QUIC (handshake), mDNS, LLMNR, NetBIOS |
| 3 | Extração de arquivos (HTTP, SMB, FTP), HTTP/2 em claro, SSH (banner e algoritmos) |

Conteúdo cifrado não é decifrado. Se a pessoa tiver um arquivo de chaves
(`SSLKEYLOGFILE`), isso entra numa fase futura.

## Analisadores

Cada alerta diz **o que** viu, **por que** importa e **onde** está a evidência,
com a técnica ATT&CK quando houver.

- **Beaconing:** conexões em intervalo regular para o mesmo destino (T1071).
- **DNS anômalo:** domínios com alta entropia, excesso de NXDOMAIN, consultas
  longas ou TXT em volume, sinais de tunelamento (T1568, T1071.004).
- **TLS suspeito:** certificado autoassinado ou vencido, ausência de SNI, JA3/JA4
  conhecidos de ferramentas ofensivas.
- **Credenciais em claro:** HTTP Basic, FTP, Telnet, LDAP simples. A interface
  mostra só que existem e onde, com o valor mascarado.
- **Movimentação lateral:** SMB e RPC entre estações, Kerberos com cifra fraca
  (T1021, T1558).
- **Exfiltração:** volume de saída desproporcional para um destino externo
  (T1041).
- **Portas e serviços incomuns** para o protocolo detectado.

## História da captura

É a primeira tela depois que a captura termina de ser lida. Responde, em
texto corrido, o que aconteceu, em que ordem e com que confiança.

```
fluxos, eventos de aplicação, alertas
   │
   ▼
Fatos  ──►  Grafo de entidades  ──►  Cadeias  ──►  Narrativa
```

- **Fatos:** cada evento relevante vira um fato com horário, entidades
  envolvidas (host, IP, domínio, arquivo, certificado), tática ATT&CK e os ids
  das evidências. Exemplo: "host 10.0.0.5 baixou executável de 2 MB de
  update-cdn.xyz por HTTP".
- **Grafo de entidades:** liga os fatos pelas entidades em comum. É ele que
  permite dizer que o domínio do download é o mesmo que depois recebe o
  beaconing.
- **Cadeias:** regras de sequência no tempo sobre o grafo, cada uma com uma
  confiança. Exemplos:
  - download de executável → conexão periódica nova do mesmo host em até N
    minutos = possível infecção seguida de C2;
  - autenticação Kerberos ou NTLM de uma estação → SMB para várias outras
    estações = possível movimentação lateral;
  - consulta a muitos subdomínios longos do mesmo domínio + volume de saída =
    possível exfiltração por DNS.
- **Paciente zero e escopo:** a primeira entidade interna de cada cadeia é
  destacada, e a narrativa diz quais outros hosts foram tocados depois.
- **Narrativa:** gerada por modelos de frase, em cada idioma da interface,
  agrupada por fase (reconhecimento, acesso inicial, execução, C2, movimentação
  lateral, exfiltração). Cada frase é clicável e abre as evidências. No final,
  uma seção **"O que esta captura não mostra"** diz o que não dá para afirmar,
  como o conteúdo de tráfego cifrado e o período fora da captura.
- **Ruído:** o tráfego reconhecidamente comum (atualizações do sistema, CDNs,
  telemetria de navegadores) é rebaixado usando listas de domínios embutidas
  no site, carregadas sob demanda. Nada é consultado na internet.
- **Captura sem nada suspeito** gera uma história também: quem eram os hosts,
  o que fizeram e por que nada se destacou.

As regras de cadeia ficam em arquivos declarativos versionados no repositório,
o que prepara o terreno para as regras da comunidade numa fase futura.

## Anonimizador

Gera uma nova captura a partir da original, sem alterar o arquivo de origem.
Roda no mesmo worker, numa segunda passada em streaming, e funciona com
arquivos de GB.

| Item | O que acontece (padrão em negrito) |
|---|---|
| IPv4 e IPv6 | **troca consistente que preserva prefixo** (mesma rede continua mesma rede), ou troca simples |
| MAC | **troca consistente** mantendo o fabricante (OUI) opcionalmente |
| Nomes internos (DNS, DHCP, NetBIOS, SNI, Kerberos) | **trocados por nomes genéricos consistentes**; domínios públicos podem ser mantidos |
| Credenciais, cookies, tokens, cabeçalhos de autorização | **sempre removidos** |
| Conteúdo dos pacotes | **mantém só cabeçalhos** ou corta em N bytes, ou mantém com mascaramento dos protocolos conhecidos |
| Horários | **mantidos** ou deslocados por um valor fixo |
| Checksums | recalculados |

- **Chave da sessão:** a troca consistente usa uma chave aleatória gerada no
  navegador. Ela não é salva, a não ser que a pessoa queira anonimizar várias
  capturas com a mesma correspondência.
- **Tabela de correspondência** (original → anônimo) é opcional, exportada à
  parte e marcada como sensível.
- **Relatório de anonimização:** o que foi trocado, removido e mantido, e o
  **risco residual** (por exemplo: conteúdo de protocolo desconhecido mantido,
  padrões de tempo que podem identificar alguém). A interface é honesta: dados
  anonimizados reduzem o risco, mas não o eliminam.
- **Gravação de arquivo grande:** a saída é escrita em blocos no armazenamento
  local do navegador (OPFS) e baixada no final, sem montar o arquivo inteiro
  na memória. Onde o navegador permite escolher o destino, grava direto no
  disco.
- O mesmo módulo do núcleo é usado pela CLI.

## Offline

- **Aplicativo instalável (PWA):** manifesto e service worker que guardam todos
  os arquivos do site, incluindo o núcleo WASM e as listas de domínios. Depois
  da primeira visita, abre sem internet.
- **Pacote para rede isolada:** cada release publica um ZIP do site pronto para
  ser servido por qualquer servidor interno (ou aberto com um servidor local de
  uma linha), para SOCs sem acesso à internet.
- **Atualização:** quando há versão nova, a interface avisa e a pessoa escolhe
  a hora de atualizar. Uma análise em andamento nunca é interrompida.
- Combina com a política de conteúdo: como a página não faz requisições depois
  de carregar, o comportamento online e offline é o mesmo.

## Saídas

- Interface interativa (visão geral, fluxos, hosts, DNS, TLS, HTTP, alertas,
  linha do tempo).
- Relatório para imprimir ou salvar em PDF, com tema claro, como no Panthera RE.
- JSON completo, CSV de IOCs e bundle **STIX 2.1** (indicadores, observáveis e
  padrões de ataque), pronto para plataformas de CTI.

## Segurança

- Núcleo com `#![forbid(unsafe_code)]` e `cargo-fuzz` no CI sobre os
  decodificadores.
- Limites explícitos: tamanho de pacote, bytes remontados por fluxo, fluxos
  ativos, tamanho de campo de protocolo. Estourou, o item é marcado como
  truncado e a análise segue.
- Política de conteúdo (CSP) restrita por meta tag, já que o Pages não permite
  cabeçalhos próprios. Nenhuma requisição de rede depois que a página carrega.
- Valores sensíveis (senhas, cookies, tokens) mascarados por padrão na
  interface e nas exportações.

## Publicação

GitHub Actions: compila o núcleo para WASM, gera a interface com Vite e
publica no GitHub Pages a cada push na `main`. A CLI sai como binário nas
releases (Windows, Linux, macOS).

## Fases

| Fase | Entrega |
|---|---|
| 0 | Esqueleto: repositório, CI, Pages no ar, identidade visual, três idiomas (feito) |
| 1 | Núcleo: pcap e pcapng, fluxos, hosts, DNS, HTTP, TLS, visão geral e linha do tempo, **offline (PWA)** |
| 2 | Analisadores com ATT&CK e **história da captura** |
| 3 | **Anonimizador** e exportação JSON, CSV e STIX |
| 4 | Protocolos de rede corporativa (SMB, Kerberos, LDAP), extração de arquivos, CLI |
| 5 | Replay da rede, diff de capturas, regras da comunidade |
| 6 | Experimental: perguntas em linguagem natural com IA rodando no navegador |
| 7 | Opcional: serviço no VPS que recebe só dados derivados (IOCs, resumo), nunca o pcap |

O offline entra já na fase 1 porque é barato e define como os arquivos do site
são organizados desde o começo.

## Idiomas

A interface sai em **português, inglês e espanhol**. Os textos ficam em
`web/src/idiomas.ts`, um dicionário por idioma com o mesmo formato (o
TypeScript acusa chave faltando). O idioma inicial vem da escolha salva da
pessoa, senão do navegador, senão inglês. Relatórios e alertas seguem o idioma
escolhido; nomes de campos nas exportações (JSON, CSV, STIX) ficam fixos em
inglês para não quebrar integrações.

## Decisões em aberto

- Licença (sugestão: Apache-2.0).
