// Espelho de nucleo/src/relatorio.rs. Horários em microssegundos desde 1970.

export interface Aviso {
  codigo: string;
  offset?: number;
}

export interface ResumoCaptura {
  formato: string;
  enlaces: string[];
  inicio_us: number;
  fim_us: number;
  pacotes: number;
  bytes: number;
  nao_decodificados: number;
  avisos: Aviso[];
}

export interface Contagem {
  nome: string;
  pacotes: number;
  bytes: number;
  fluxos: number;
}

export interface Host {
  ip: string;
  escopo: "interno" | "externo" | "multicast" | "reservado";
  mac: string | null;
  nomes: string[];
  pacotes_enviados: number;
  pacotes_recebidos: number;
  bytes_enviados: number;
  bytes_recebidos: number;
  fluxos_iniciados: number;
  fluxos_recebidos: number;
  primeiro_us: number;
  ultimo_us: number;
}

export interface Fluxo {
  id: number;
  protocolo: string;
  origem: string;
  porta_origem: number;
  destino: string;
  porta_destino: number;
  inicio_us: number;
  fim_us: number;
  pacotes_ida: number;
  pacotes_volta: number;
  bytes_ida: number;
  bytes_volta: number;
  aplicacao: string | null;
  aplicacao_por_porta: boolean;
  conteudo_desconhecido: boolean;
  estado: string;
  offset: number;
}

export interface EventoDns {
  ts_us: number;
  fluxo: number;
  cliente: string;
  servidor: string;
  consulta: string;
  tipo: string;
  rcode: number | null;
  respostas: string[];
  resposta_us: number | null;
}

export interface EventoHttp {
  ts_us: number;
  fluxo: number;
  cliente: string;
  servidor: string;
  porta: number;
  metodo: string;
  host: string | null;
  caminho: string;
  user_agent: string | null;
  autorizacao: string | null;
  senha_em_claro: boolean;
  status: number | null;
  tipo_conteudo: string | null;
  tamanho: number | null;
  servidor_http: string | null;
}

export interface EventoTls {
  ts_us: number;
  fluxo: number;
  cliente: string;
  servidor: string;
  porta: number;
  sni: string | null;
  alpn: string[];
  versao_oferecida: string;
  versao: string | null;
  cifra: string | null;
  ja3: string | null;
  ja4: string | null;
  ja3s: string | null;
  certificado: Certificado | null;
}

export interface Certificado {
  sujeito: string | null;
  emissor: string | null;
  emissor_organizacao: string | null;
  nao_antes_us: number | null;
  nao_depois_us: number | null;
  autoassinado: boolean;
  nomes: string[];
}

export interface EventoDhcp {
  ts_us: number;
  mac: string;
  tipo: string;
  nome_host: string | null;
  ip: string | null;
}

export interface Relatorio {
  captura: ResumoCaptura;
  protocolos: Contagem[];
  aplicacoes: Contagem[];
  hosts: Host[];
  total_hosts: number;
  fluxos: Fluxo[];
  total_fluxos: number;
  dns: EventoDns[];
  total_dns: number;
  http: EventoHttp[];
  total_http: number;
  tls: EventoTls[];
  total_tls: number;
  dhcp: EventoDhcp[];
  total_dhcp: number;
  alertas: Alerta[];
  diagnosticos: Diagnostico[];
  historia: Historia;
}

export interface Condicao {
  medida: string;
  valor: number;
  limiar: number;
  ok: boolean;
}

export interface Diagnostico {
  regra: string;
  disparou: boolean;
  inspecionados: number;
  caso: { host: string; alvo: string | null; condicoes: Condicao[] } | null;
}

export type Severidade = "baixa" | "media" | "alta";

export interface Alerta {
  id: number;
  regra: string;
  severidade: Severidade;
  fase: string;
  tecnica: string | null;
  inicio_us: number;
  fim_us: number;
  host: string;
  alvo: string | null;
  alvo_ip: string | null;
  parametros: Record<string, string>;
  fluxos: number[];
}

export interface Passo {
  alerta: number;
  ts_us: number;
  fase: string;
  ligacao: "mesmo_destino" | "pouco_depois" | "depois" | null;
}

export interface Cadeia {
  host: string;
  confianca: Severidade;
  motivo: "entrega_e_controle" | "tres_fases" | "duas_graves" | "duas_fases" | "uma_grave";
  fases: string[];
  inicio_us: number;
  fim_us: number;
  passos: Passo[];
}

export interface Historia {
  paciente_zero: string | null;
  hosts_afetados: string[];
  cadeias: Cadeia[];
  nao_mostra: string[];
}

export interface ErroCaptura {
  codigo: string;
  offset: number;
}

/** Espelho de `Opcoes` em nucleo/src/anonimizador.rs. */
export interface OpcoesAnonimizacao {
  chave: string;
  enderecos: "internos" | "todos" | "nenhum";
  conteudo: "cabecalhos" | "protocolos";
  manter_fabricante: boolean;
  deslocar_horarios: boolean;
  nomes_internos: string[];
  dominios_internos: string[];
}

export interface RelatorioAnonimizacao {
  pacotes: number;
  pacotes_removidos: number;
  pacotes_cortados: number;
  bytes_removidos: number;
  enderecos_trocados: number;
  macs_trocados: number;
  nomes_mascarados: number;
  riscos: string[];
  erro: ErroCaptura | null;
}

export type MensagemAnonimizacao =
  | { tipo: "progresso"; lidos: number; total: number }
  | { tipo: "concluido"; arquivo: Blob; relatorio: RelatorioAnonimizacao; tabela: string; erro: ErroCaptura | null }
  | { tipo: "falha"; mensagem: string };

/** Mensagens que o worker de leitura manda para a interface. */
export type MensagemLeitura =
  | { tipo: "progresso"; lidos: number; total: number; pacotes: number; fluxos: number }
  | { tipo: "concluido"; relatorio: Relatorio; erro: ErroCaptura | null; segundos: number }
  | { tipo: "falha"; mensagem: string };

/** Espelho de `Filtro` em nucleo/src/pacotes.rs. */
export interface FiltroPacotes {
  ips: string[];
  portas: number[];
  protocolo?: string;
  texto?: string;
  pular: number;
  limite: number;
}

export interface CampoPacote {
  nome: string;
  valor: string;
}

export interface CamadaPacote {
  nome: string;
  campos: CampoPacote[];
}

export interface Pacote {
  numero: number;
  offset: number;
  ts_us: number;
  tamanho: number;
  capturado: number;
  origem: string;
  destino: string;
  protocolo: string;
  info: string;
  camadas: CamadaPacote[];
  /** Hexadecimal, até 4 KB. */
  bytes: string;
}

export interface ResultadoPacotes {
  pacotes: Pacote[];
  encontrados: number;
  tem_mais: boolean;
  erro: ErroCaptura | null;
}

export type MensagemPacotes =
  | { tipo: "progresso"; lidos: number; total: number }
  | { tipo: "concluido"; resultado: ResultadoPacotes }
  | { tipo: "falha"; mensagem: string };
