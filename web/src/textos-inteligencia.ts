// Textos de alertas, história e cobertura MITRE, nos três idiomas. Ficam à
// parte de idiomas.ts porque cada regra do núcleo tem título, frase da
// história e explicação próprios.

import type { Idioma } from "./idiomas";
import { tamanho } from "./formatos";

/** O que um modelo de frase recebe: host já com nome, alvo e parâmetros. */
export interface A {
  h: string;
  alvo: string;
  p: Record<string, string>;
}

interface TextoRegra {
  nome: string;
  titulo: (a: A) => string;
  frase: (a: A) => string;
  porque: string;
}

const bytes = (v: string | undefined) => tamanho(Number(v ?? 0));

const TIPOS_WEB: Record<"pt" | "en" | "es", Record<string, string>> = {
  pt: { traversal: "path traversal", sqli: "SQL injection", xss: "XSS", comando: "injeção de comando", log4shell: "Log4Shell" },
  en: { traversal: "path traversal", sqli: "SQL injection", xss: "XSS", comando: "command injection", log4shell: "Log4Shell" },
  es: { traversal: "path traversal", sqli: "inyección SQL", xss: "XSS", comando: "inyección de comandos", log4shell: "Log4Shell" },
};

const pt = {
  severidades: { baixa: "Baixa", media: "Média", alta: "Alta" } as Record<string, string>,
  confiancas: { baixa: "confiança baixa", media: "confiança média", alta: "confiança alta" } as Record<string, string>,
  fases: {
    acesso_inicial: "Acesso inicial",
    entrega: "Entrega",
    comando_e_controle: "Comando e controle",
    credenciais: "Credenciais",
    descoberta: "Descoberta",
    movimentacao_lateral: "Movimentação lateral",
    exfiltracao: "Exfiltração",
    higiene: "Higiene",
  } as Record<string, string>,
  ligacoes: { mesmo_destino: "No mesmo destino, ", pouco_depois: "Pouco depois, ", depois: "Mais tarde, " } as Record<string, string>,
  naoMostra: {
    fora_do_periodo: "O que aconteceu antes e depois do período capturado.",
    ponto_de_captura: "Tráfego que não passou pelo ponto onde a captura foi feita, como conversas entre máquinas do mesmo switch.",
    conteudo_cifrado: "O conteúdo das conexões cifradas: dá para ver com quem e quando, não o que foi dito.",
    sem_remontagem: "O conteúdo completo de conversas longas: por enquanto, só o começo de cada uma é lido.",
    captura_incompleta: "Trechos da captura corrompidos, cortados ou além dos limites de leitura.",
  } as Record<string, string>,
  historia: {
    pacienteZero: (h: string, n: number, fases: number, ini: string, fim: string) =>
      `Tudo indica que ${h} é o ponto de partida: ${n} ${n === 1 ? "fato" : "fatos"} em ${fases} ${fases === 1 ? "fase" : "fases"}, das ${ini} às ${fim} (UTC).`,
    tambem: "Também envolvidos",
    tambemDetalhe: "Hosts da rede com alertas próprios ou que falaram com os mesmos destinos maliciosos (comando, entrega, exfiltração).",
    outras: "Outras sequências",
    sequencia: (h: string) => `Sequência de ${h}`,
    naoMostraTitulo: "O que esta captura não mostra",
    semSuspeitas: "Nada nesta captura se encaixa nos padrões de ataque que o Panthera Wire conhece.",
    semSuspeitasDetalhe: (hosts: string, fluxos: string, dominios: string) =>
      `Foram ${hosts} hosts, ${fluxos} fluxos e ${dominios} domínios consultados. Isso não prova que nada aconteceu: veja abaixo o que a captura não mostra.`,
    alertasSoltos: (n: number) => `${n} ${n === 1 ? "alerta isolado não entrou" : "alertas isolados não entraram"} em nenhuma sequência. Veja em Alertas.`,
  },
  alertas: {
    nenhum: "Nenhum alerta nesta captura.",
    porque: "Por que importa",
    tecnica: "Técnica ATT&CK",
    contramedidas: "Contramedidas D3FEND para esta técnica",
    semD3fend: "O D3FEND ainda não liga contramedidas a esta técnica.",
    implementa: "Contramedida que o Panthera Wire aplica aqui",
    evidencias: (n: number) => `Ver evidências (${n} ${n === 1 ? "fluxo" : "fluxos"})`,
    ocultar: "Ocultar evidências",
    evidenciasFora: "Os eventos destes fluxos ficaram além do limite exibido.",
    maisContramedidas: (n: number) => `e mais ${n}`,
  },
  d3fendTaticas: {
    Model: "Modelar", Harden: "Fortalecer", Detect: "Detectar", Isolate: "Isolar",
    Deceive: "Enganar", Evict: "Expulsar", Restore: "Restaurar",
  } as Record<string, string>,
  cobertura: {
    subtitulo: "Todas as técnicas do MITRE ATT&CK Enterprise e o que é possível ver delas numa captura de rede.",
    detectada: "Detectada",
    observavel: "Visível na rede, sem regra ainda",
    nao_observavel: "Fora do alcance da rede",
    explicacao:
      "Uma captura de rede só enxerga o que passa pela rede. A classificação usa os próprios dados da MITRE: uma técnica é visível na rede quando a MITRE associa tráfego, fluxos ou conexões à detecção dela.",
    tecnicas: (n: string) => `${n} técnicas`,
    filtro: "Filtrar por ID ou nome",
    componentes: "Pegada de rede segundo a MITRE",
    semPegada: "A MITRE não associa dados de rede à detecção desta técnica: ela acontece dentro da máquina.",
    semEstrategia: "A MITRE ainda não publicou estratégia de detecção para esta técnica.",
    regras: "Regras do Panthera Wire",
    viaSub: "detectada por meio de subtécnica",
    subtecnicas: "Subtécnicas",
    verNaMitre: "Ver na MITRE",
    d3fendTitulo: "MITRE D3FEND",
    d3fendResumo: (impl: number, total: number) =>
      `O Panthera Wire implementa ${impl} das ${total} contramedidas do D3FEND, todas de detecção por análise de tráfego. As demais dependem de outras camadas (endpoint, identidade, rede ativa) e aparecem como recomendação em cada alerta.`,
    implementada: "Implementada pelo Panthera Wire",
    versoes: (a: string, d: string) => `ATT&CK ${a} · D3FEND ${d}`,
  },
  regras: {
    beaconing: {
      nome: "Beaconing",
      titulo: (a) => `Conexões regulares para ${a.alvo}`,
      frase: (a) => `${a.h} passou a contatar ${a.alvo} a cada ${a.p.intervalo} s (${a.p.conexoes} conexões, variação de ${a.p.variacao}%).`,
      porque: "Malware costuma checar o servidor de comando em intervalo fixo. Pessoas não navegam assim; programas, sim.",
    },
    download_executavel: {
      nome: "Download de executável",
      titulo: (a) => `Download de executável de ${a.alvo}`,
      frase: (a) => `${a.h} baixou ${a.p.url}${a.p.tamanho ? ` (${bytes(a.p.tamanho)})` : ""}${a.p.ip_direto === "true" ? ", direto de um IP, sem nome de domínio" : ""}.`,
      porque: "Executáveis e scripts baixados por HTTP sem cifra, de domínios pouco conhecidos, são uma forma comum de entregar malware.",
    },
    ataque_web: {
      nome: "Ataque a aplicação web",
      titulo: (a) => `Tentativa de ${TIPOS_WEB.pt[a.p.tipo] ?? a.p.tipo} em ${a.alvo}`,
      frase: (a) => `${a.h} enviou ${a.p.tentativas} ${a.p.tentativas === "1" ? "requisição" : "requisições"} com ${TIPOS_WEB.pt[a.p.tipo] ?? a.p.tipo} para ${a.alvo}, como ${a.p.exemplo}, e ${a.p.sucesso === "true" ? "o servidor respondeu com sucesso" : "o servidor não respondeu com sucesso"}.`,
      porque: "URLs com esses padrões tentam explorar falhas da aplicação para ler arquivos do servidor, mexer no banco de dados ou executar comandos.",
    },
    dga: {
      nome: "Domínios gerados por algoritmo",
      titulo: () => "Muitos domínios que não existem",
      frase: (a) => `${a.h} consultou ${a.p.quantidade} domínios inexistentes, como ${a.p.exemplos}.`,
      porque: "Nomes aleatórios que não existem são típicos de malware que gera domínios por algoritmo até encontrar o servidor ativo.",
    },
    tunel_dns: {
      nome: "Túnel DNS",
      titulo: (a) => `Possível túnel DNS em ${a.alvo}`,
      frase: (a) => `${a.h} fez ${a.p.consultas} consultas sob ${a.alvo}, com nomes de ${a.p.tamanho_medio} caracteres em média${Number(a.p.txt) > 0 ? ` (${a.p.txt} do tipo TXT)` : ""}.`,
      porque: "Subdomínios longos e variados sob um mesmo domínio podem carregar dados escondidos dentro do DNS, que quase nunca é bloqueado.",
    },
    credencial_em_claro: {
      nome: "Senha sem cifra",
      titulo: (a) => `Senha sem cifra (${a.p.protocolo})`,
      frase: (a) => `${a.h} enviou uma credencial por ${a.p.protocolo} para ${a.alvo}, sem cifra.`,
      porque: "Qualquer um no caminho consegue ler essa senha. O valor não é guardado nem mostrado aqui.",
    },
    varredura_portas: {
      nome: "Varredura de portas",
      titulo: (a) => `Varredura de portas em ${a.alvo}`,
      frase: (a) => `${a.h} tentou ${a.p.quantidade} portas de ${a.alvo} (${a.p.faixa}), e as conexões falharam.`,
      porque: "Tentar muitas portas em sequência é como se descobre quais serviços estão abertos numa máquina.",
    },
    varredura_hosts: {
      nome: "Varredura de hosts",
      titulo: (a) => `Varredura da porta ${a.p.porta}`,
      frase: (a) => `${a.h} tentou a porta ${a.p.porta} em ${a.p.quantidade} hosts, sem sucesso.`,
      porque: "Testar a mesma porta em muitos hosts é como se procura um serviço vulnerável pela rede.",
    },
    movimentacao_lateral: {
      nome: "Acesso remoto a vários hosts",
      titulo: () => "Acesso remoto a vários hosts internos",
      frase: (a) => `${a.h} abriu ${a.p.protocolos} com ${a.p.quantidade} hosts internos (${a.p.alvos}).`,
      porque: "Uma estação usando serviços de administração em várias outras pode ser alguém se espalhando pela rede.",
    },
    exfiltracao_volume: {
      nome: "Volume de saída desproporcional",
      titulo: (a) => `Grande volume enviado para ${a.alvo}`,
      frase: (a) => `${a.h} enviou ${bytes(a.p.enviados)} para ${a.alvo} e recebeu só ${bytes(a.p.recebidos)}.`,
      porque: "Muito mais dados saindo do que voltando, para um destino externo, é o padrão de um vazamento.",
    },
    tls_antigo: {
      nome: "TLS antigo",
      titulo: (a) => `${a.p.versao} com ${a.alvo}`,
      frase: (a) => `${a.h} negociou ${a.p.versao} com ${a.alvo}.`,
      porque: "Versões antigas de TLS têm fraquezas conhecidas e já foram abandonadas pelos navegadores.",
    },
    user_agent_suspeito: {
      nome: "User agent suspeito",
      titulo: (a) => (a.p.marca === "vazio" ? "Requisições sem user agent" : `User agent de ${a.p.marca}`),
      frase: (a) => (a.p.marca === "vazio"
        ? `${a.h} fez requisições HTTP sem se identificar.`
        : `${a.h} fez requisições HTTP como "${a.p.user_agent}".`),
      porque: "Ferramentas de linha de comando e navegadores obsoletos aparecem muito em scripts de ataque; navegadores atuais não se identificam assim.",
    },
    porta_incomum: {
      nome: "Porta fora do comum",
      titulo: (a) => `${a.p.protocolo} na porta ${a.p.porta}`,
      frase: (a) => `${a.h} usou ${a.p.protocolo} com ${a.alvo} na porta ${a.p.porta}, fora do comum.`,
      porque: "Servidores de comando costumam usar portas fora do padrão para escapar de filtros simples.",
    },
  } as Record<string, TextoRegra>,
};

export type TextosInteligencia = typeof pt;

const en: TextosInteligencia = {
  severidades: { baixa: "Low", media: "Medium", alta: "High" },
  confiancas: { baixa: "low confidence", media: "medium confidence", alta: "high confidence" },
  fases: {
    acesso_inicial: "Initial access",
    entrega: "Delivery",
    comando_e_controle: "Command and control",
    credenciais: "Credentials",
    descoberta: "Discovery",
    movimentacao_lateral: "Lateral movement",
    exfiltracao: "Exfiltration",
    higiene: "Hygiene",
  },
  ligacoes: { mesmo_destino: "To the same destination, ", pouco_depois: "Shortly after, ", depois: "Later, " },
  naoMostra: {
    fora_do_periodo: "What happened before and after the captured period.",
    ponto_de_captura: "Traffic that did not pass through the capture point, such as conversations between machines on the same switch.",
    conteudo_cifrado: "The content of encrypted connections: you can see who and when, not what was said.",
    sem_remontagem: "The full content of long conversations: for now, only the beginning of each one is read.",
    captura_incompleta: "Parts of the capture that were corrupted, cut short or beyond the reading limits.",
  },
  historia: {
    pacienteZero: (h, n, fases, ini, fim) =>
      `${h} is most likely the starting point: ${n} ${n === 1 ? "fact" : "facts"} across ${fases} ${fases === 1 ? "phase" : "phases"}, from ${ini} to ${fim} (UTC).`,
    tambem: "Also involved",
    tambemDetalhe: "Network hosts with their own alerts, or that talked to the same malicious destinations (command, delivery, exfiltration).",
    outras: "Other sequences",
    sequencia: (h) => `Sequence for ${h}`,
    naoMostraTitulo: "What this capture does not show",
    semSuspeitas: "Nothing in this capture matches the attack patterns Panthera Wire knows.",
    semSuspeitasDetalhe: (hosts, fluxos, dominios) =>
      `There were ${hosts} hosts, ${fluxos} flows and ${dominios} domains queried. This does not prove nothing happened: see below what the capture does not show.`,
    alertasSoltos: (n) => `${n} isolated ${n === 1 ? "alert is" : "alerts are"} not part of any sequence. See Alerts.`,
  },
  alertas: {
    nenhum: "No alerts in this capture.",
    porque: "Why it matters",
    tecnica: "ATT&CK technique",
    contramedidas: "D3FEND countermeasures for this technique",
    semD3fend: "D3FEND does not link countermeasures to this technique yet.",
    implementa: "Countermeasure Panthera Wire applies here",
    evidencias: (n) => `Show evidence (${n} ${n === 1 ? "flow" : "flows"})`,
    ocultar: "Hide evidence",
    evidenciasFora: "The events of these flows are beyond the displayed limit.",
    maisContramedidas: (n) => `and ${n} more`,
  },
  d3fendTaticas: {
    Model: "Model", Harden: "Harden", Detect: "Detect", Isolate: "Isolate",
    Deceive: "Deceive", Evict: "Evict", Restore: "Restore",
  },
  cobertura: {
    subtitulo: "Every MITRE ATT&CK Enterprise technique and what a network capture can see of it.",
    detectada: "Detected",
    observavel: "Visible on the network, no rule yet",
    nao_observavel: "Out of network reach",
    explicacao:
      "A network capture only sees what crosses the network. The classification uses MITRE's own data: a technique is visible on the network when MITRE ties traffic, flows or connections to its detection.",
    tecnicas: (n) => `${n} techniques`,
    filtro: "Filter by ID or name",
    componentes: "Network footprint according to MITRE",
    semPegada: "MITRE ties no network data to detecting this technique: it happens inside the machine.",
    semEstrategia: "MITRE has not published a detection strategy for this technique yet.",
    regras: "Panthera Wire rules",
    viaSub: "detected through a sub-technique",
    subtecnicas: "Sub-techniques",
    verNaMitre: "View on MITRE",
    d3fendTitulo: "MITRE D3FEND",
    d3fendResumo: (impl, total) =>
      `Panthera Wire implements ${impl} of the ${total} D3FEND countermeasures, all of them detection through traffic analysis. The others depend on other layers (endpoint, identity, active network) and show up as recommendations on each alert.`,
    implementada: "Implemented by Panthera Wire",
    versoes: (a, d) => `ATT&CK ${a} · D3FEND ${d}`,
  },
  regras: {
    beaconing: {
      nome: "Beaconing",
      titulo: (a) => `Regular connections to ${a.alvo}`,
      frase: (a) => `${a.h} started contacting ${a.alvo} every ${a.p.intervalo} s (${a.p.conexoes} connections, ${a.p.variacao}% variation).`,
      porque: "Malware often checks in with its command server at a fixed interval. People do not browse like that; programs do.",
    },
    download_executavel: {
      nome: "Executable download",
      titulo: (a) => `Executable downloaded from ${a.alvo}`,
      frase: (a) => `${a.h} downloaded ${a.p.url}${a.p.tamanho ? ` (${bytes(a.p.tamanho)})` : ""}${a.p.ip_direto === "true" ? ", straight from an IP, with no domain name" : ""}.`,
      porque: "Executables and scripts downloaded over unencrypted HTTP from little-known domains are a common way to deliver malware.",
    },
    ataque_web: {
      nome: "Web application attack",
      titulo: (a) => `${TIPOS_WEB.en[a.p.tipo] ?? a.p.tipo} attempt against ${a.alvo}`,
      frase: (a) => `${a.h} sent ${a.p.tentativas} ${a.p.tentativas === "1" ? "request" : "requests"} with ${TIPOS_WEB.en[a.p.tipo] ?? a.p.tipo} to ${a.alvo}, such as ${a.p.exemplo}, and ${a.p.sucesso === "true" ? "the server answered with success" : "the server did not answer with success"}.`,
      porque: "URLs with these patterns try to exploit application flaws to read server files, tamper with the database or run commands.",
    },
    dga: {
      nome: "Algorithm-generated domains",
      titulo: () => "Many domains that do not exist",
      frase: (a) => `${a.h} queried ${a.p.quantidade} non-existent domains, such as ${a.p.exemplos}.`,
      porque: "Random names that do not exist are typical of malware that generates domains by algorithm until it finds the live server.",
    },
    tunel_dns: {
      nome: "DNS tunnel",
      titulo: (a) => `Possible DNS tunnel in ${a.alvo}`,
      frase: (a) => `${a.h} made ${a.p.consultas} queries under ${a.alvo}, with names averaging ${a.p.tamanho_medio} characters${Number(a.p.txt) > 0 ? ` (${a.p.txt} of type TXT)` : ""}.`,
      porque: "Long, varied subdomains under one domain can carry data hidden inside DNS, which is almost never blocked.",
    },
    credencial_em_claro: {
      nome: "Unencrypted password",
      titulo: (a) => `Unencrypted password (${a.p.protocolo})`,
      frase: (a) => `${a.h} sent a credential over ${a.p.protocolo} to ${a.alvo}, unencrypted.`,
      porque: "Anyone on the path can read this password. The value is not stored or shown here.",
    },
    varredura_portas: {
      nome: "Port scan",
      titulo: (a) => `Port scan against ${a.alvo}`,
      frase: (a) => `${a.h} tried ${a.p.quantidade} ports on ${a.alvo} (${a.p.faixa}), and the connections failed.`,
      porque: "Trying many ports in a row is how someone finds out which services are open on a machine.",
    },
    varredura_hosts: {
      nome: "Host sweep",
      titulo: (a) => `Scan of port ${a.p.porta}`,
      frase: (a) => `${a.h} tried port ${a.p.porta} on ${a.p.quantidade} hosts, without success.`,
      porque: "Testing the same port on many hosts is how someone looks for a vulnerable service across the network.",
    },
    movimentacao_lateral: {
      nome: "Remote access to several hosts",
      titulo: () => "Remote access to several internal hosts",
      frase: (a) => `${a.h} opened ${a.p.protocolos} with ${a.p.quantidade} internal hosts (${a.p.alvos}).`,
      porque: "A workstation using administration services on several others may be someone spreading through the network.",
    },
    exfiltracao_volume: {
      nome: "Disproportionate outbound volume",
      titulo: (a) => `Large volume sent to ${a.alvo}`,
      frase: (a) => `${a.h} sent ${bytes(a.p.enviados)} to ${a.alvo} and received only ${bytes(a.p.recebidos)}.`,
      porque: "Far more data leaving than coming back, to an external destination, is the pattern of a leak.",
    },
    tls_antigo: {
      nome: "Old TLS",
      titulo: (a) => `${a.p.versao} with ${a.alvo}`,
      frase: (a) => `${a.h} negotiated ${a.p.versao} with ${a.alvo}.`,
      porque: "Old TLS versions have known weaknesses and browsers have already dropped them.",
    },
    user_agent_suspeito: {
      nome: "Suspicious user agent",
      titulo: (a) => (a.p.marca === "vazio" ? "Requests without a user agent" : `${a.p.marca} user agent`),
      frase: (a) => (a.p.marca === "vazio"
        ? `${a.h} made HTTP requests without identifying itself.`
        : `${a.h} made HTTP requests as "${a.p.user_agent}".`),
      porque: "Command-line tools and obsolete browsers show up a lot in attack scripts; current browsers do not identify like that.",
    },
    porta_incomum: {
      nome: "Unusual port",
      titulo: (a) => `${a.p.protocolo} on port ${a.p.porta}`,
      frase: (a) => `${a.h} used ${a.p.protocolo} with ${a.alvo} on port ${a.p.porta}, which is unusual.`,
      porque: "Command servers often use non-standard ports to slip past simple filters.",
    },
  },
};

const es: TextosInteligencia = {
  severidades: { baixa: "Baja", media: "Media", alta: "Alta" },
  confiancas: { baixa: "confianza baja", media: "confianza media", alta: "confianza alta" },
  fases: {
    acesso_inicial: "Acceso inicial",
    entrega: "Entrega",
    comando_e_controle: "Comando y control",
    credenciais: "Credenciales",
    descoberta: "Descubrimiento",
    movimentacao_lateral: "Movimiento lateral",
    exfiltracao: "Exfiltración",
    higiene: "Higiene",
  },
  ligacoes: { mesmo_destino: "Al mismo destino, ", pouco_depois: "Poco después, ", depois: "Más tarde, " },
  naoMostra: {
    fora_do_periodo: "Lo que pasó antes y después del período capturado.",
    ponto_de_captura: "El tráfico que no pasó por el punto donde se hizo la captura, como conversaciones entre equipos del mismo switch.",
    conteudo_cifrado: "El contenido de las conexiones cifradas: se ve con quién y cuándo, no qué se dijo.",
    sem_remontagem: "El contenido completo de conversaciones largas: por ahora, solo se lee el comienzo de cada una.",
    captura_incompleta: "Partes de la captura dañadas, cortadas o fuera de los límites de lectura.",
  },
  historia: {
    pacienteZero: (h, n, fases, ini, fim) =>
      `Todo indica que ${h} es el punto de partida: ${n} ${n === 1 ? "hecho" : "hechos"} en ${fases} ${fases === 1 ? "fase" : "fases"}, de las ${ini} a las ${fim} (UTC).`,
    tambem: "También involucrados",
    tambemDetalhe: "Hosts de la red con alertas propias o que hablaron con los mismos destinos maliciosos (comando, entrega, exfiltración).",
    outras: "Otras secuencias",
    sequencia: (h) => `Secuencia de ${h}`,
    naoMostraTitulo: "Lo que esta captura no muestra",
    semSuspeitas: "Nada en esta captura coincide con los patrones de ataque que Panthera Wire conoce.",
    semSuspeitasDetalhe: (hosts, fluxos, dominios) =>
      `Hubo ${hosts} hosts, ${fluxos} flujos y ${dominios} dominios consultados. Eso no prueba que no haya pasado nada: mira abajo lo que la captura no muestra.`,
    alertasSoltos: (n) => `${n} ${n === 1 ? "alerta aislada no entró" : "alertas aisladas no entraron"} en ninguna secuencia. Míralas en Alertas.`,
  },
  alertas: {
    nenhum: "No hay alertas en esta captura.",
    porque: "Por qué importa",
    tecnica: "Técnica ATT&CK",
    contramedidas: "Contramedidas D3FEND para esta técnica",
    semD3fend: "D3FEND todavía no vincula contramedidas a esta técnica.",
    implementa: "Contramedida que Panthera Wire aplica aquí",
    evidencias: (n) => `Ver evidencias (${n} ${n === 1 ? "flujo" : "flujos"})`,
    ocultar: "Ocultar evidencias",
    evidenciasFora: "Los eventos de estos flujos quedaron fuera del límite mostrado.",
    maisContramedidas: (n) => `y ${n} más`,
  },
  d3fendTaticas: {
    Model: "Modelar", Harden: "Reforzar", Detect: "Detectar", Isolate: "Aislar",
    Deceive: "Engañar", Evict: "Expulsar", Restore: "Restaurar",
  },
  cobertura: {
    subtitulo: "Todas las técnicas de MITRE ATT&CK Enterprise y lo que una captura de red puede ver de ellas.",
    detectada: "Detectada",
    observavel: "Visible en la red, sin regla todavía",
    nao_observavel: "Fuera del alcance de la red",
    explicacao:
      "Una captura de red solo ve lo que pasa por la red. La clasificación usa los propios datos de MITRE: una técnica es visible en la red cuando MITRE asocia tráfico, flujos o conexiones a su detección.",
    tecnicas: (n) => `${n} técnicas`,
    filtro: "Filtrar por ID o nombre",
    componentes: "Huella de red según MITRE",
    semPegada: "MITRE no asocia datos de red a la detección de esta técnica: ocurre dentro del equipo.",
    semEstrategia: "MITRE todavía no publicó una estrategia de detección para esta técnica.",
    regras: "Reglas de Panthera Wire",
    viaSub: "detectada por medio de una subtécnica",
    subtecnicas: "Subtécnicas",
    verNaMitre: "Ver en MITRE",
    d3fendTitulo: "MITRE D3FEND",
    d3fendResumo: (impl, total) =>
      `Panthera Wire implementa ${impl} de las ${total} contramedidas de D3FEND, todas de detección por análisis de tráfico. Las demás dependen de otras capas (endpoint, identidad, red activa) y aparecen como recomendación en cada alerta.`,
    implementada: "Implementada por Panthera Wire",
    versoes: (a, d) => `ATT&CK ${a} · D3FEND ${d}`,
  },
  regras: {
    beaconing: {
      nome: "Beaconing",
      titulo: (a) => `Conexiones regulares a ${a.alvo}`,
      frase: (a) => `${a.h} empezó a contactar ${a.alvo} cada ${a.p.intervalo} s (${a.p.conexoes} conexiones, variación de ${a.p.variacao}%).`,
      porque: "El malware suele consultar al servidor de comando a intervalos fijos. Las personas no navegan así; los programas, sí.",
    },
    download_executavel: {
      nome: "Descarga de ejecutable",
      titulo: (a) => `Descarga de ejecutable desde ${a.alvo}`,
      frase: (a) => `${a.h} descargó ${a.p.url}${a.p.tamanho ? ` (${bytes(a.p.tamanho)})` : ""}${a.p.ip_direto === "true" ? ", directo desde una IP, sin nombre de dominio" : ""}.`,
      porque: "Ejecutables y scripts descargados por HTTP sin cifrar, desde dominios poco conocidos, son una forma común de entregar malware.",
    },
    ataque_web: {
      nome: "Ataque a aplicación web",
      titulo: (a) => `Intento de ${TIPOS_WEB.es[a.p.tipo] ?? a.p.tipo} en ${a.alvo}`,
      frase: (a) => `${a.h} envió ${a.p.tentativas} ${a.p.tentativas === "1" ? "solicitud" : "solicitudes"} con ${TIPOS_WEB.es[a.p.tipo] ?? a.p.tipo} a ${a.alvo}, como ${a.p.exemplo}, y ${a.p.sucesso === "true" ? "el servidor respondió con éxito" : "el servidor no respondió con éxito"}.`,
      porque: "Las URL con estos patrones intentan explotar fallas de la aplicación para leer archivos del servidor, alterar la base de datos o ejecutar comandos.",
    },
    dga: {
      nome: "Dominios generados por algoritmo",
      titulo: () => "Muchos dominios que no existen",
      frase: (a) => `${a.h} consultó ${a.p.quantidade} dominios inexistentes, como ${a.p.exemplos}.`,
      porque: "Nombres aleatorios que no existen son típicos de malware que genera dominios por algoritmo hasta encontrar el servidor activo.",
    },
    tunel_dns: {
      nome: "Túnel DNS",
      titulo: (a) => `Posible túnel DNS en ${a.alvo}`,
      frase: (a) => `${a.h} hizo ${a.p.consultas} consultas bajo ${a.alvo}, con nombres de ${a.p.tamanho_medio} caracteres en promedio${Number(a.p.txt) > 0 ? ` (${a.p.txt} de tipo TXT)` : ""}.`,
      porque: "Subdominios largos y variados bajo un mismo dominio pueden llevar datos escondidos dentro del DNS, que casi nunca se bloquea.",
    },
    credencial_em_claro: {
      nome: "Contraseña sin cifrar",
      titulo: (a) => `Contraseña sin cifrar (${a.p.protocolo})`,
      frase: (a) => `${a.h} envió una credencial por ${a.p.protocolo} a ${a.alvo}, sin cifrar.`,
      porque: "Cualquiera en el camino puede leer esa contraseña. El valor no se guarda ni se muestra aquí.",
    },
    varredura_portas: {
      nome: "Escaneo de puertos",
      titulo: (a) => `Escaneo de puertos en ${a.alvo}`,
      frase: (a) => `${a.h} probó ${a.p.quantidade} puertos de ${a.alvo} (${a.p.faixa}), y las conexiones fallaron.`,
      porque: "Probar muchos puertos seguidos es la forma de descubrir qué servicios están abiertos en un equipo.",
    },
    varredura_hosts: {
      nome: "Barrido de hosts",
      titulo: (a) => `Escaneo del puerto ${a.p.porta}`,
      frase: (a) => `${a.h} probó el puerto ${a.p.porta} en ${a.p.quantidade} hosts, sin éxito.`,
      porque: "Probar el mismo puerto en muchos hosts es la forma de buscar un servicio vulnerable en la red.",
    },
    movimentacao_lateral: {
      nome: "Acceso remoto a varios hosts",
      titulo: () => "Acceso remoto a varios hosts internos",
      frase: (a) => `${a.h} abrió ${a.p.protocolos} con ${a.p.quantidade} hosts internos (${a.p.alvos}).`,
      porque: "Una estación que usa servicios de administración en varias otras puede ser alguien expandiéndose por la red.",
    },
    exfiltracao_volume: {
      nome: "Volumen de salida desproporcionado",
      titulo: (a) => `Gran volumen enviado a ${a.alvo}`,
      frase: (a) => `${a.h} envió ${bytes(a.p.enviados)} a ${a.alvo} y recibió solo ${bytes(a.p.recebidos)}.`,
      porque: "Muchos más datos saliendo que volviendo, hacia un destino externo, es el patrón de una fuga.",
    },
    tls_antigo: {
      nome: "TLS antiguo",
      titulo: (a) => `${a.p.versao} con ${a.alvo}`,
      frase: (a) => `${a.h} negoció ${a.p.versao} con ${a.alvo}.`,
      porque: "Las versiones antiguas de TLS tienen debilidades conocidas y los navegadores ya las abandonaron.",
    },
    user_agent_suspeito: {
      nome: "User agent sospechoso",
      titulo: (a) => (a.p.marca === "vazio" ? "Solicitudes sin user agent" : `User agent de ${a.p.marca}`),
      frase: (a) => (a.p.marca === "vazio"
        ? `${a.h} hizo solicitudes HTTP sin identificarse.`
        : `${a.h} hizo solicitudes HTTP como "${a.p.user_agent}".`),
      porque: "Herramientas de línea de comandos y navegadores obsoletos aparecen mucho en scripts de ataque; los navegadores actuales no se identifican así.",
    },
    porta_incomum: {
      nome: "Puerto inusual",
      titulo: (a) => `${a.p.protocolo} en el puerto ${a.p.porta}`,
      frase: (a) => `${a.h} usó ${a.p.protocolo} con ${a.alvo} en el puerto ${a.p.porta}, algo inusual.`,
      porque: "Los servidores de comando suelen usar puertos no estándar para esquivar filtros simples.",
    },
  },
};

export const TEXTOS_INTELIGENCIA: Record<Idioma, TextosInteligencia> = { pt, en, es };
