import type { Idioma } from "./idiomas";

const LOCALE: Record<Idioma, string> = { pt: "pt-BR", en: "en-US", es: "es-ES" };

export function tamanho(bytes: number): string {
  const unidades = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = bytes;
  while (v >= 1024 && i < unidades.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${unidades[i]}`;
}

export function numero(n: number, idioma: Idioma): string {
  return n.toLocaleString(LOCALE[idioma]);
}

/** Data e hora completas, em UTC, como em qualquer relatório de incidente. */
export function dataHora(us: number, idioma: Idioma): string {
  return new Date(us / 1000).toLocaleString(LOCALE[idioma], { timeZone: "UTC", hour12: false }) + " UTC";
}

/** Só a hora, com milissegundos, para listas longas. */
export function hora(us: number): string {
  const d = new Date(us / 1000);
  const p = (n: number, t = 2) => String(n).padStart(t, "0");
  return `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}.${p(d.getUTCMilliseconds(), 3)}`;
}

export function duracao(us: number): string {
  const s = us / 1_000_000;
  if (s < 1) return `${Math.round(s * 1000)} ms`;
  if (s < 60) return `${s.toFixed(1)} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ${Math.round(s % 60)} s`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h} h ${m % 60} min`;
  return `${Math.floor(h / 24)} d ${h % 24} h`;
}

export function ponta(ip: string, porta: number): string {
  if (!porta) return ip;
  return ip.includes(":") ? `[${ip}]:${porta}` : `${ip}:${porta}`;
}
