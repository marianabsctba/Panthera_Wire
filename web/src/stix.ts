// Exportações da análise: IOCs em CSV e bundle STIX 2.1. Montadas aqui, a
// partir do relatório, porque são só formatação: nada sai do navegador.

import { TECNICAS, urlTecnica } from "./mitre";
import type { Alerta, Relatorio, Severidade } from "./tipos";

export interface Ioc {
  tipo: "ipv4" | "ipv6" | "dominio" | "url";
  valor: string;
  severidade: Severidade;
  alertas: Alerta[];
}

/** Regras em que o alvo faz papel de atacante (comando, entrega, exfiltração). */
const ALVO_MALICIOSO = new Set(["beaconing", "download_executavel", "tunel_dns", "exfiltracao_volume", "porta_incomum"]);
/** Regras em que quem age é o atacante: o host vira IOC quando é de fora. */
const HOST_ATACANTE = new Set(["ataque_web", "varredura_portas", "varredura_hosts"]);

const PESO: Record<Severidade, number> = { baixa: 0, media: 1, alta: 2 };

const ehIp = (v: string) => /^[\d.]+$/.test(v) || v.includes(":");

export function iocs(r: Relatorio): Ioc[] {
  const escopo = new Map(r.hosts.map((h) => [h.ip, h.escopo]));
  const deFora = (ip: string) => ["externo", "reservado"].includes(escopo.get(ip) ?? "externo");
  const achados = new Map<string, Ioc>();
  const somar = (tipo: Ioc["tipo"], valor: string, a: Alerta) => {
    const chave = `${tipo}:${valor.toLowerCase()}`;
    const atual = achados.get(chave);
    if (atual) {
      atual.alertas.push(a);
      if (PESO[a.severidade] > PESO[atual.severidade]) atual.severidade = a.severidade;
    } else {
      achados.set(chave, { tipo, valor, severidade: a.severidade, alertas: [a] });
    }
  };
  const ip = (v: string, a: Alerta) => somar(v.includes(":") ? "ipv6" : "ipv4", v, a);

  for (const a of r.alertas) {
    if (ALVO_MALICIOSO.has(a.regra)) {
      if (a.alvo_ip && deFora(a.alvo_ip)) ip(a.alvo_ip, a);
      if (a.alvo && !ehIp(a.alvo)) somar("dominio", a.alvo, a);
      if (a.regra === "download_executavel" && a.parametros.url) somar("url", `http://${a.parametros.url}`, a);
    }
    if (HOST_ATACANTE.has(a.regra) && deFora(a.host)) ip(a.host, a);
  }
  return [...achados.values()].sort((x, y) => PESO[y.severidade] - PESO[x.severidade] || x.valor.localeCompare(y.valor));
}

const iso = (us: number) => new Date(us / 1000).toISOString();

function celula(v: string): string {
  return /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
}

export function csvIocs(r: Relatorio): string {
  const linhas = [["tipo", "valor", "severidade", "regras", "tecnicas", "primeira_vez_utc", "ultima_vez_utc", "hosts"]];
  for (const i of iocs(r)) {
    const unico = (xs: string[]) => [...new Set(xs)].join(" ");
    linhas.push([
      i.tipo,
      i.valor,
      i.severidade,
      unico(i.alertas.map((a) => a.regra)),
      unico(i.alertas.map((a) => a.tecnica ?? "").filter(Boolean)),
      iso(Math.min(...i.alertas.map((a) => a.inicio_us))),
      iso(Math.max(...i.alertas.map((a) => a.fim_us))),
      unico(i.alertas.map((a) => a.host)),
    ]);
  }
  return linhas.map((l) => l.map(celula).join(",")).join("\n") + "\n";
}

const novoId = (tipo: string) => `${tipo}--${crypto.randomUUID()}`;
const aspas = (v: string) => v.replace(/\\/g, "\\\\").replace(/'/g, "\\'");

const PADRAO: Record<Ioc["tipo"], (v: string) => string> = {
  ipv4: (v) => `[ipv4-addr:value = '${aspas(v)}']`,
  ipv6: (v) => `[ipv6-addr:value = '${aspas(v)}']`,
  dominio: (v) => `[domain-name:value = '${aspas(v)}']`,
  url: (v) => `[url:value = '${aspas(v)}']`,
};

/**
 * Bundle STIX 2.1: um indicador por IOC, o padrão de ataque (ATT&CK) de cada
 * um e um relatório que junta tudo. `titulo` e `frase` dão o texto no idioma
 * da interface.
 */
export function bundleStix(
  r: Relatorio,
  arquivo: string,
  textos: { titulo: (a: Alerta) => string; frase: (a: Alerta) => string; resumo: string },
): object {
  const agora = new Date().toISOString();
  const autor = { type: "identity", spec_version: "2.1", id: novoId("identity"), created: agora, modified: agora, name: "Panthera Wire", identity_class: "system" };
  const objetos: Record<string, unknown>[] = [autor];
  const padroes = new Map<string, string>();

  const padraoDeAtaque = (tecnica: string) => {
    if (!padroes.has(tecnica)) {
      const id = novoId("attack-pattern");
      padroes.set(tecnica, id);
      objetos.push({
        type: "attack-pattern", spec_version: "2.1", id, created: agora, modified: agora, created_by_ref: autor.id,
        name: TECNICAS.get(tecnica)?.nome ?? tecnica,
        external_references: [{ source_name: "mitre-attack", external_id: tecnica, url: urlTecnica(tecnica) }],
      });
    }
    return padroes.get(tecnica)!;
  };

  for (const i of iocs(r)) {
    const principal = i.alertas[0];
    const id = novoId("indicator");
    objetos.push({
      type: "indicator", spec_version: "2.1", id, created: agora, modified: agora, created_by_ref: autor.id,
      name: textos.titulo(principal),
      description: i.alertas.map(textos.frase).join(" "),
      indicator_types: [i.severidade === "alta" ? "malicious-activity" : "anomalous-activity"],
      pattern: PADRAO[i.tipo](i.valor),
      pattern_type: "stix",
      valid_from: iso(Math.min(...i.alertas.map((a) => a.inicio_us))),
      labels: [...new Set(i.alertas.map((a) => a.regra))],
    });
    for (const tecnica of new Set(i.alertas.map((a) => a.tecnica).filter((t): t is string => !!t))) {
      objetos.push({
        type: "relationship", spec_version: "2.1", id: novoId("relationship"), created: agora, modified: agora,
        created_by_ref: autor.id, relationship_type: "indicates", source_ref: id, target_ref: padraoDeAtaque(tecnica),
      });
    }
  }

  objetos.push({
    type: "report", spec_version: "2.1", id: novoId("report"), created: agora, modified: agora, created_by_ref: autor.id,
    name: `Panthera Wire: ${arquivo}`,
    description: textos.resumo,
    report_types: ["threat-report"],
    published: agora,
    object_refs: objetos.map((o) => o.id as string),
  });
  return { type: "bundle", id: novoId("bundle"), objects: objetos };
}

export function baixar(conteudo: Blob | string, nome: string, tipo = "application/octet-stream") {
  const blob = typeof conteudo === "string" ? new Blob([conteudo], { type: tipo }) : conteudo;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = nome;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

