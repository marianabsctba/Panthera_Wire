// Diff de capturas: o que aparece no incidente e não aparece numa captura de
// referência da mesma rede, tirada num período normal. Só novidades: o que
// sumiu raramente explica um incidente.

import type { Alerta, Relatorio } from "./tipos";

export type Categoria = "alertas" | "hostsInternos" | "destinos" | "dominios" | "sni" | "ja4" | "userAgents" | "portas";

export interface Novidade {
  valor: string;
  nome?: string;
  /** Quando a linha junta vários subdomínios novos do mesmo pai. */
  subdominios?: number;
  /** Quantas vezes aparece no incidente. */
  vezes: number;
  /** Quem fez: hosts de origem ou clientes. */
  quem: string[];
  filtro?: { ips: string[]; portas: number[] };
}

export interface Diferencas {
  alertas: Alerta[];
  categorias: { chave: Exclude<Categoria, "alertas">; itens: Novidade[] }[];
  /** Alguma das capturas passou do limite de itens guardados no relatório. */
  truncado: boolean;
  total: number;
}

const AGRUPAR_SUBDOMINIOS = 5;

class Contador {
  private m = new Map<string, Novidade & { _quem: Set<string> }>();
  somar(valor: string, quem: string, extra?: Partial<Novidade>, n = 1) {
    let x = this.m.get(valor);
    if (!x) {
      x = { valor, vezes: 0, quem: [], _quem: new Set(), ...extra };
      this.m.set(valor, x);
    }
    x.vezes += n;
    x._quem.add(quem);
  }
  itens(): Novidade[] {
    return [...this.m.values()]
      .map(({ _quem, ...x }) => ({ ...x, quem: [..._quem].sort() }))
      .sort((a, b) => b.vezes - a.vezes || a.valor.localeCompare(b.valor));
  }
}

const chaveAlerta = (a: Alerta) => `${a.regra}|${a.host}|${a.alvo ?? a.alvo_ip ?? ""}`;
const respondeu = (estado: string) => !["sem_resposta", "recusada"].includes(estado);

export function comparar(inc: Relatorio, ref: Relatorio): Diferencas {
  const nomes = new Map(inc.hosts.filter((h) => h.nomes.length).map((h) => [h.ip, h.nomes[0]]));
  const escopo = new Map(inc.hosts.map((h) => [h.ip, h.escopo]));
  const deFora = (ip: string) => ["externo", "reservado"].includes(escopo.get(ip) ?? "externo");

  const alertasRef = new Set(ref.alertas.map(chaveAlerta));
  const alertas = inc.alertas.filter((a) => !alertasRef.has(chaveAlerta(a)));

  const ipsRef = new Set(ref.hosts.map((h) => h.ip));
  const hostsInternos = new Contador();
  for (const h of inc.hosts) {
    if (h.escopo === "interno" && !ipsRef.has(h.ip)) {
      hostsInternos.somar(h.ip, h.ip, { nome: nomes.get(h.ip), filtro: { ips: [h.ip], portas: [] } }, h.fluxos_iniciados);
    }
  }

  const destinosRef = new Set(ref.fluxos.map((f) => f.destino));
  const destinos = new Contador();
  for (const f of inc.fluxos) {
    if (deFora(f.destino) && !destinosRef.has(f.destino) && !ipsRef.has(f.destino)) {
      destinos.somar(f.destino, f.origem, { nome: nomes.get(f.destino), filtro: { ips: [f.destino], portas: [] } });
    }
  }

  const dominiosRef = new Set(ref.dns.map((d) => d.consulta.toLowerCase()));
  // Muitos subdomínios novos sob o mesmo pai (túnel, DGA por subdomínio)
  // viram uma linha só: *.pai.
  const novas = inc.dns.map((d) => ({ q: d.consulta.toLowerCase(), cliente: d.cliente })).filter((x) => x.q && !dominiosRef.has(x.q));
  const pai = (q: string) => q.slice(q.indexOf(".") + 1);
  const filhos = new Map<string, Set<string>>();
  for (const { q } of novas) {
    if (q.split(".").length > 2) filhos.set(pai(q), (filhos.get(pai(q)) ?? new Set()).add(q));
  }
  const dominios = new Contador();
  for (const { q, cliente } of novas) {
    const n = filhos.get(pai(q))?.size ?? 0;
    if (q.split(".").length > 2 && n >= AGRUPAR_SUBDOMINIOS) dominios.somar(`*.${pai(q)}`, cliente, { subdominios: n });
    else dominios.somar(q, cliente);
  }

  const sniRef = new Set(ref.tls.map((s) => s.sni?.toLowerCase()).filter(Boolean));
  const ja4Ref = new Set(ref.tls.map((s) => s.ja4).filter(Boolean));
  const sni = new Contador();
  const ja4 = new Contador();
  for (const s of inc.tls) {
    const nome = s.sni?.toLowerCase();
    if (nome && !sniRef.has(nome)) sni.somar(nome, s.cliente);
    if (s.ja4 && !ja4Ref.has(s.ja4)) ja4.somar(s.ja4, s.cliente, { nome: s.sni ?? undefined });
  }

  const uaRef = new Set(ref.http.map((h) => h.user_agent).filter(Boolean));
  const userAgents = new Contador();
  for (const h of inc.http) {
    if (h.user_agent && !uaRef.has(h.user_agent)) userAgents.somar(h.user_agent, h.cliente);
  }

  // Serviço: protocolo e porta de destino de conexões que tiveram resposta.
  // Sem resposta é varredura, e a varredura já tem regra própria.
  const servico = (p: string, porta: number) => `${p}/${porta}`;
  const portasRef = new Set(ref.fluxos.filter((f) => respondeu(f.estado)).map((f) => servico(f.protocolo, f.porta_destino)));
  const portas = new Contador();
  for (const f of inc.fluxos) {
    const s = servico(f.protocolo, f.porta_destino);
    if (f.porta_destino && respondeu(f.estado) && !portasRef.has(s)) {
      portas.somar(s, f.origem, { nome: f.aplicacao ?? undefined, filtro: { ips: [], portas: [f.porta_destino] } });
    }
  }

  const categorias = [
    { chave: "hostsInternos" as const, itens: hostsInternos.itens() },
    { chave: "destinos" as const, itens: destinos.itens() },
    { chave: "dominios" as const, itens: dominios.itens() },
    { chave: "sni" as const, itens: sni.itens() },
    { chave: "ja4" as const, itens: ja4.itens() },
    { chave: "userAgents" as const, itens: userAgents.itens() },
    { chave: "portas" as const, itens: portas.itens() },
  ];

  const cortado = (r: Relatorio) =>
    r.total_fluxos > r.fluxos.length || r.total_dns > r.dns.length || r.total_http > r.http.length || r.total_tls > r.tls.length;

  return {
    alertas,
    categorias,
    truncado: cortado(inc) || cortado(ref),
    total: alertas.length + categorias.reduce((n, c) => n + c.itens.length, 0),
  };
}
