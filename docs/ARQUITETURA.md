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

### Regras implementadas (fase 2)

Todas rodam sobre a captura inteira, antes de qualquer corte para a interface.
Os limiares são fixos e ficam no código, à vista, para a pessoa poder discordar.

| Regra | Dispara quando | ATT&CK | D3FEND aplicado |
|---|---|---|---|
| `beaconing` | 6 ou mais conexões de um host interno ao mesmo destino externo e porta, com intervalo mediano de 5 s ou mais e 80% dos intervalos a até 20% da mediana | T1071 | D3-PMAD |
| `download_executavel` | resposta HTTP 2xx com extensão (.exe, .dll, .ps1, .hta...) ou tipo executável | T1105 | D3-APCA |
| `dga` | 15 ou mais domínios distintos com NXDOMAIN para o mesmo cliente | T1568.002 | D3-DNSTA |
| `tunel_dns` | sob a mesma zona: 20 ou mais nomes únicos com média de 40 caracteres, ou 20 ou mais consultas TXT | T1071.004 | D3-DNSTA |
| `credencial_em_claro` | HTTP Basic, campo de senha em formulário ou URL, ou FTP, Telnet, POP3, IMAP com conexão aceita | T1552 | D3-APCA |
| `forca_bruta` | 10 ou mais respostas 401 ou 403 do mesmo servidor ao mesmo cliente; alta se depois vier sucesso no mesmo caminho | T1110.001 | D3-ANET |
| `ataque_web` | URL com path traversal, SQL injection, XSS, injeção de comando ou Log4Shell (decodificada duas vezes); alta se a resposta foi 2xx | T1190 | D3-APCA |
| `varredura_portas` / `varredura_hosts` | 10 ou mais portas (ou hosts) com conexão sem resposta ou recusada | T1046 | D3-CAA |
| `sondagem_udp` | 20 ou mais mensagens UDP sem resposta do mesmo host para o mesmo destino (fora DNS) | T1046 | D3-CAA, D3-ISVA |
| `movimentacao_lateral` | SMB, RDP, WinRM, RPC ou SSH aceitos de um host interno para 3 ou mais internos | T1021 | D3-ANAA, D3-RTSD |
| `exfiltracao_volume` | 50 MB ou mais para um destino externo, com 5 vezes mais saída que entrada | T1041 | D3-PHDURA |
| `tls_antigo` | SSL 3.0, TLS 1.0 ou 1.1 negociados | (higiene) | D3-PMAD |
| `user_agent_suspeito` | user agent vazio, de ferramenta (curl, PowerShell, certutil...) ou de navegador obsoleto | T1071.001 | D3-PMAD |
| `porta_incomum` | HTTP ou TLS confirmados pelo conteúdo, para fora, em porta fora do padrão | T1571 | D3-PMAD |
| `protocolo_disfarcado` | dados numa porta de DNS, HTTP ou TLS que não são esse protocolo (64 bytes ou mais, com resposta); alta na porta 53 | T1571 | D3-PMAD |
| `certificado_suspeito` | certificado autoassinado, vencido, ainda não válido ou emitido para outro nome, em conexão para fora | T1573.002 | D3-PCA |

Faixas de documentação e teste (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
198.18.0.0/15, 2001:db8::/32) têm escopo próprio, `reservado`, e contam como
podendo estar dos dois lados: capturas de laboratório funcionam sem IP privado.
Uma conexão cujo SYN-ACK ficou fora da captura, mas que teve resposta, conta
como aberta, e não como sem resposta.

Na história, alertas de severidade baixa entram na sequência mas não contam
como fase. A confiança é alta com três fases, com entrega seguida de comando,
ou com duas condutas graves em fases diferentes. Abaixo das sequências, a
seção **O que aconteceu na rede** descreve cada host (conexões, sem resposta,
DNS, HTTP, volume) com ou sem alerta.

Domínios de infraestrutura muito comum (Microsoft, Google, Apple, CAs...) só
rebaixam a severidade: o alerta nunca some. A tabela de regras existe em dois
lugares, no núcleo (`deteccao.rs`) e na interface (`web/src/regras.json`), e um
teste falha se os dois divergirem ou se algum ID não existir nos dados da MITRE.

## Cobertura MITRE ATT&CK e D3FEND

O Panthera Wire mapeia **todas** as técnicas do ATT&CK Enterprise e **todas** as
contramedidas do D3FEND, a partir dos dados oficiais
(`scripts/gerar_mitre.py` gera `web/src/mitre.json`, e os arquivos brutos da
MITRE ficam fora do Git). Mapear tudo não é detectar tudo: uma captura de rede
só vê o que passa pela rede, e a tela de cobertura diz isso para cada técnica.

| Status | Critério | ATT&CK 20.0 |
|---|---|---|
| Detectada | alguma regra do Panthera Wire cobre a técnica (ou uma subtécnica dela) | 11 |
| Visível na rede, sem regra ainda | a MITRE associa Network Traffic Content, Network Traffic Flow, Network Connection Creation ou Network Share Access à detecção dela | 221 |
| Fora do alcance da rede | a MITRE não associa dados de rede à detecção (acontece dentro da máquina) ou não publicou estratégia de detecção | 474 |

A segunda linha é a lista de trabalho das próximas regras.

**D3FEND (1.6.0, 272 contramedidas):** o mapeamento técnica → contramedida é
inferido pelo mesmo método do D3FEND: a técnica produz, usa ou modifica um
artefato digital (por exemplo, `OutboundInternetNetworkTraffic`), e a defesa
analisa, filtra ou isola esse artefato ou um mais genérico que o contém.
Subtécnicas herdam os artefatos da técnica-mãe. Técnicas que a ontologia ainda
não liga a nenhum artefato (como T1046) aparecem como "sem contramedida no
D3FEND", sem inventar. Cada alerta mostra a contramedida que o próprio Panthera
Wire aplica (7 no total, todas de detecção) e as demais como recomendação,
agrupadas por tática defensiva.

Atualizar: baixar `enterprise-attack.json` e `d3fend.json` numa pasta e rodar
`python -I scripts/gerar_mitre.py <pasta>`.

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

### Como ficou (fase 3)

`nucleo/src/anonimizador.rs`, exposto ao navegador como `Anonimizacao` e
rodando em `web/src/anonimizacao.worker.ts`. A saída é sempre **pcapng**.

| Item | Implementado |
|---|---|
| Chave | 128 bits gerados no navegador (ou informados pela pessoa); a troca é SipHash-2-4 sobre ela |
| IPv4 / IPv6 | troca bit a bit preservando prefixo; 10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16, fe80::/64 e fc00::/7 continuam na mesma faixa. Opções: só os da rede (**padrão**, externos ficam como IOC), todos, nenhum |
| MAC | troca consistente para endereço administrado localmente, ou mantendo o fabricante (opcional); broadcast e multicast ficam |
| Opções IP | viram NOP (podem carregar endereços); IPv6 com cabeçalho de roteamento é removido |
| Conteúdo | **só cabeçalhos** (padrão), ou DNS, DHCP e handshake TLS mantidos. HTTP e qualquer outro conteúdo são sempre cortados, então credenciais, cookies e tokens nunca passam |
| DNS | nomes internos mascarados no mesmo tamanho (a mensagem continua válida, ponteiros de compressão incluídos); endereços nas respostas trocados com o mesmo mapa |
| Nome interno | sufixos de rede local (.local, .lan, .corp, .internal...), nome sem ponto, nomes que a análise já sabe que são da rede, domínios informados pela pessoa, nomes que resolvem para IP interno, reverso de IP interno |
| DHCP | MAC do cliente, endereços, hostname, domínio, FQDN e identificador do cliente trocados ou mascarados; sname, file e opção de fabricante zerados |
| TLS | só a mensagem ClientHello ou ServerHello fica (o certificado, que tem nomes, sai); SNI interno mascarado |
| ICMP | só os 8 primeiros bytes (erros carregam o cabeçalho IP original) |
| Horários | mantidos (**padrão**) ou deslocados para 2000-01-01 mantendo os intervalos |
| Checksums | IPv4 recalculado; TCP e UDP zerados (o conteúdo cortado não fecharia a soma) |
| Não reconhecido | protocolo de rede desconhecido: pacote removido e contado |

O relatório traz o que foi trocado, cortado e removido e os riscos que
continuam (tamanhos e tempos, horários reais, IPs externos, fabricante, nomes
públicos). Testes: nada de hostname, nome interno, credencial ou MAC original
sobra na saída; a captura anonimizada continua gerando os mesmos alertas de
beaconing, túnel DNS, exfiltração e varredura; a mesma chave dá a mesma saída.

## Exportações (fase 3)

Montadas no navegador a partir do relatório (`web/src/stix.ts`):

- **JSON:** o relatório completo, com os campos estáveis.
- **CSV de IOCs:** endereços, domínios e URLs, com severidade, regras,
  técnicas, período e hosts.
- **STIX 2.1:** `identity` (Panthera Wire), um `indicator` por IOC com padrão
  STIX, `attack-pattern` com a referência ATT&CK, `relationship` *indicates*
  entre eles e um `report` com o resumo da história.

Só viram IOC os alvos de regras em que o alvo faz papel de atacante (comando,
entrega, exfiltração) e os hosts de fora que atacam (varredura, ataque web). A
vítima de uma varredura nunca vira indicador.

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
| 1 | Núcleo: pcap e pcapng, fluxos, hosts, DNS, HTTP, TLS, visão geral e linha do tempo, **offline (PWA)** (feito, ver abaixo) |
| 2 | Analisadores com ATT&CK e **história da captura**, cobertura completa ATT&CK e D3FEND (feito) |
| 3 | **Anonimizador** e exportação JSON, CSV e STIX (feito) |
| 4 | Detalhe pacote a pacote com o Wireshark (Wiregasm), protocolos de rede corporativa (SMB, Kerberos, LDAP), extração de arquivos, CLI |
| 5 | Replay da rede, diff de capturas, regras da comunidade |
| 6 | Experimental: perguntas em linguagem natural com IA rodando no navegador |
| 7 | Opcional: serviço no VPS que recebe só dados derivados (IOCs, resumo), nunca o pcap |

O offline entra já na fase 1 porque é barato e define como os arquivos do site
são organizados desde o começo.

### Estado da fase 1

Pronto:

- Leitura em streaming de pcap (micro e nanossegundos, as duas ordens de bytes)
  e pcapng (várias seções e interfaces, `if_tsresol`, blocos EPB, SPB e PB).
- Enlaces Ethernet (com VLAN e QinQ), Linux SLL e SLL2, loopback e IP cru;
  IPv4, IPv6 com cabeçalhos de extensão, fragmentos, TCP, UDP, ICMP e ARP.
- Fluxos bidirecionais com expiração por inatividade e reuso de porta, estado
  TCP e aplicação confirmada pelo conteúdo ou deduzida pela porta.
- DNS (com compressão e pareamento consulta e resposta), HTTP/1.x (sem guardar
  credenciais), TLS (SNI, ALPN, versão e cifra negociadas) e DHCP.
- Hosts com nomes aprendidos por DNS, SNI, HTTP e DHCP.
- Interface: visão geral, linha do tempo, fluxos, hosts, DNS, TLS e HTTP, nos
  três idiomas.
- Offline: service worker gerado no build e manifesto para instalar.
- Medido: 1 GB sintético em 4 s no terminal (255 MB/s) e 300 MB em 2,4 s no
  navegador.

Ainda não, e por quê:

- **Fluxos e eventos ficam em memória**, com limites (2 milhões de fluxos,
  1 milhão de hosts, 500 mil eventos por tipo) e aviso quando estouram. A
  interface recebe os 50 mil maiores fluxos e os primeiros 50 mil eventos de
  cada tipo. Descarregar para OPFS com DuckDB-WASM é o próximo passo, quando
  capturas reais mostrarem que os limites apertam.
- **Remontagem TCP só do handshake TLS** (veja abaixo). HTTP ainda é lido do
  segmento em que começa; extração de arquivos vai exigir remontar o corpo.
- **Pacote ZIP para rede isolada** nas releases.

### Remontagem, fingerprints e certificado

- O começo de cada direção dos fluxos TLS é remontado pela ordem do número de
  sequência: até 16 KB do cliente e 32 KB do servidor, no máximo 8.192 ao mesmo
  tempo, liberados assim que o handshake é lido. A base é o SYN da direção
  quando está na captura (segmentos fora de ordem funcionam); sem SYN, o
  primeiro segmento. Quando o handshake cabe num segmento, não há remontagem.
- **JA3** (MD5), **JA3S** e **JA4** (FoxIO) de cada handshake, calculados só
  para os eventos guardados. O JA4 é testado contra o exemplo oficial
  (`t13d1516h2_8daaf6152771_e5627efa2ab1`).
- **Certificado** do servidor no TLS 1.2: sujeito, emissor, organização,
  validade, nomes alternativos e se é autoassinado. No TLS 1.3 o certificado
  vai cifrado e a interface diz isso. A regra `certificado_suspeito`
  (T1573.002, D3-PCA) avisa de certificado autoassinado, vencido, ainda não
  válido ou emitido para outro nome, em conexões para fora.
- Custo medido no arquivo sintético de 1 GB, que é extremo (1,3 milhão de
  handshakes): de 4,8 s para 7,7 s no terminal (134 MB/s).

### Pacotes

A página **Pacotes** relê a captura e lista os pacotes no estilo do Wireshark
(número, tempo relativo, origem, destino, protocolo, tamanho, informação), com
as camadas decodificadas campo a campo e os bytes em hexadecimal e ASCII. Filtra
por busca de texto (na informação, nos endereços e nos valores dos campos), por
protocolo, IP, porta ou fluxo (botão na tabela de fluxos), 1.000 por página. A
leitura para assim que tem o bastante, então os primeiros pacotes de um arquivo
de GB aparecem rápido. Os nomes dos campos seguem a convenção do Wireshark. O
valor de `Authorization` e `Cookie` não aparece decodificado (está nos bytes).
A dissecação profunda de milhares de protocolos fica para o Wiregasm.

### Confiança da história

Mede o quanto os fatos de um host formam uma intrusão encadeada, não a certeza
de cada alerta. Alertas de severidade baixa entram na sequência mas não contam
como fase.

| Confiança | Quando |
|---|---|
| Alta | entrega (download ou acesso inicial) seguida de comando e controle em até 30 minutos; ou três fases ou mais; ou duas fases com dois ou mais alertas graves |
| Média | duas fases |
| Baixa | uma fase só, com alerta grave |

Cada sequência traz o motivo (`motivo`) e as fases que contaram, e a interface
explica isso na própria história.

### Calibração com capturas reais

Capturas públicas, fora do repositório, rodadas no núcleo a cada mudança de
regra:

| Captura (wiki.wireshark.org) | Esperado | Resultado |
|---|---|---|
| `http.cap`, `dns.cap`, `nb6-startup.pcap` | tráfego normal, nenhum alerta | nenhum alerta |
| `imap.cap`, `telnet-cooked.pcap` | senha em claro | `credencial_em_claro` |
| `dns-remoteshell.pcap` | shell remoto do Windows nas portas 53 e 80 | `protocolo_disfarcado` nas duas portas e o Telnet |

O que essas capturas corrigiram: o shell pela porta 53 passava batido (nasceu
a regra `protocolo_disfarcado`), e pedidos HTTP partidos em vários segmentos
(`GET /` e o resto, como o roteador do `nb6-startup` manda) não eram lidos, o
que gerava um falso positivo. Agora o cabeçalho HTTP do cliente é remontado
até 8 KB, e a resposta HTTP também identifica o fluxo. Os dois casos estão no
laboratório como regressão.

### Fuzzing

`fuzz/` tem três alvos para `cargo-fuzz` (arquivo inteiro em blocos de tamanho
variado, pacote único em qualquer tipo de enlace, e o anonimizador conferindo
que a saída continua legível), rodando no CI do Linux a cada mudança no núcleo
e toda semana. Nos testes normais, 3.000 pacotes aleatórios passam pela análise
e pelo anonimizador em qualquer sistema.

## Idiomas

A interface sai em **português, inglês e espanhol**. Os textos ficam em
`web/src/idiomas.ts`, um dicionário por idioma com o mesmo formato (o
TypeScript acusa chave faltando). O idioma inicial vem da escolha salva da
pessoa, senão do navegador, senão inglês. Relatórios e alertas seguem o idioma
escolhido; nomes de campos nas exportações (JSON, CSV, STIX) ficam fixos em
inglês para não quebrar integrações.

## Licença e Wireshark

**GPL-2.0 ou posterior.** A decisão vem do detalhe pacote a pacote: em vez de
reescrever milhares de dissectores, o Panthera Wire vai usar o Wiregasm (o
Wireshark compilado para WebAssembly, GPL-2.0) só quando a pessoa abre um fluxo.
O núcleo próprio continua fazendo a leitura rápida, a história, os alertas e o
anonimizador: o Wireshark em WASM tem 69 MB (19 MB compactado) e disseca cada
pacote em profundidade, o que não serve para a passada de GB, mas serve bem
para os poucos pacotes de um fluxo. Ele é baixado na primeira vez que alguém
abre um detalhe e fica guardado para uso offline.
