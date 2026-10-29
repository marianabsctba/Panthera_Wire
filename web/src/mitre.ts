// Dados oficiais da MITRE (gerados por scripts/gerar_mitre.py) e a tabela de
// regras do núcleo, com o que cada técnica significa para uma captura de rede.

import dados from "./mitre.json";
import tabelaRegras from "./regras.json";

export interface TecnicaMitre {
  id: string;
  nome: string;
  taticas: string[];
  sub: boolean;
  rede: string[];
  estrategia: boolean;
  d3fend: string[];
}

export interface TaticaMitre {
  id: string;
  nome: string;
  fase: string;
  ordem: number;
}

export interface Defesa {
  nome: string;
  tatica: string | null;
  classe: string;
}

export interface RegraNucleo {
  regra: string;
  tecnica: string | null;
  fase: string;
  d3fend: string[];
}

export const MITRE = dados as {
  atribuicao: string;
  versao_attack: string;
  versao_d3fend: string;
  taticas: TaticaMitre[];
  tecnicas: TecnicaMitre[];
  defesas: Record<string, Defesa>;
};

export const REGRAS = tabelaRegras as RegraNucleo[];
export const TECNICAS = new Map(MITRE.tecnicas.map((t) => [t.id, t]));
export const REGRA = new Map(REGRAS.map((r) => [r.regra, r]));

const DETECTADAS = new Set(REGRAS.map((r) => r.tecnica).filter((t): t is string => !!t));
export const D3FEND_IMPLEMENTADAS = new Set(REGRAS.flatMap((r) => r.d3fend));

export type Status = "detectada" | "observavel" | "nao_observavel";

const SUBS = new Map<string, TecnicaMitre[]>();
for (const t of MITRE.tecnicas) {
  if (t.sub) {
    const pai = t.id.split(".")[0];
    SUBS.set(pai, [...(SUBS.get(pai) ?? []), t]);
  }
}

// Calculado uma vez: a matriz consulta o status de cada célula a cada filtro.
const STATUS = new Map<string, Status>(MITRE.tecnicas.map((t) => {
  if (DETECTADAS.has(t.id)) return [t.id, "detectada"];
  if (!t.sub && [...DETECTADAS].some((d) => d.startsWith(`${t.id}.`))) return [t.id, "detectada"];
  return [t.id, t.rede.length ? "observavel" : "nao_observavel"];
}));

export function status(t: TecnicaMitre): Status {
  return STATUS.get(t.id) ?? "nao_observavel";
}

/** Uma técnica-mãe conta como detectada quando só uma subtécnica é. */
export function detectadaViaSub(t: TecnicaMitre): boolean {
  return !DETECTADAS.has(t.id) && status(t) === "detectada";
}

export function subtecnicas(id: string): TecnicaMitre[] {
  return SUBS.get(id) ?? [];
}

export function regrasDe(id: string): RegraNucleo[] {
  return REGRAS.filter((r) => r.tecnica === id || r.tecnica?.startsWith(`${id}.`));
}

/** Contramedidas D3FEND da técnica; sem mapeamento próprio, as da técnica-mãe. */
export function defesasDe(id: string | null): string[] {
  if (!id) return [];
  const t = TECNICAS.get(id);
  if (t?.d3fend.length) return t.d3fend;
  return TECNICAS.get(id.split(".")[0])?.d3fend ?? [];
}

export const urlTecnica = (id: string) => `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
export const urlDefesa = (id: string) => `https://d3fend.mitre.org/technique/d3f:${MITRE.defesas[id]?.classe ?? ""}/`;

export const ORDEM_D3FEND = ["Model", "Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore"];
