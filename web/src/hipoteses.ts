// Hipóteses guiadas: perguntas que a própria captura responde, geradas a
// partir dos alertas. Cada resposta vem dos dados do relatório, nunca de
// suposição, e traz o filtro para ver os pacotes que a sustentam.

import type { TextosInteligencia } from "./textos-inteligencia";
import { tamanho } from "./formatos";
import type { Alerta, Relatorio } from "./tipos";

export interface Hipotese {
  chave: string;
  pergunta: string;
  resposta: string;
  /** true: a resposta encontrou algo; false: não encontrou; ausente: pergunta de medida. */
  achou?: boolean;
  filtro?: { ips: string[]; portas: number[] };
}

const MAX = 8;
const FASES_MALICIOSAS = new Set(["comando_e_controle", "entrega", "exfiltracao"]);
const PESO: Record<string, number> = { alta: 0, media: 1, baixa: 2 };

const ehIp = (v: string) => /^[\d.]+$/.test(v) || v.includes(":");

export function hipoteses(r: Relatorio, nomes: Map<string, string>, ti: TextosInteligencia): Hipotese[] {
  const h = ti.hipoteses;
  const escopo = new Map(r.hosts.map((x) => [x.ip, x.escopo]));
  const deFora = (ip: string) => ["externo", "reservado"].includes(escopo.get(ip) ?? "externo");
  const rotulo = (ip: string) => (nomes.get(ip) ? `${ip} (${nomes.get(ip)})` : ip);
  const lista = (xs: string[]) => xs.slice(0, 3).join(", ") + (xs.length > 3 ? "…" : "");
  const saida: Hipotese[] = [];
  const vistas = new Set<string>();
  const somar = (x: Hipotese) => {
    if (!vistas.has(x.chave) && saida.length < MAX) {
      vistas.add(x.chave);
      saida.push(x);
    }
  };

  const alertas = [...r.alertas].sort((a, b) => PESO[a.severidade] - PESO[b.severidade] || a.inicio_us - b.inicio_us);

  // O paciente zero antes de tudo começar.
  const pz = r.historia.paciente_zero;
  if (pz) {
    const primeiro = Math.min(...r.alertas.filter((a) => a.host === pz).map((a) => a.inicio_us));
    const antes = r.fluxos.filter((f) => f.origem === pz && f.inicio_us < primeiro);
    const destinos = [...new Set(antes.map((f) => f.destino))];
    somar({
      chave: `antes:${pz}`,
      pergunta: h.antes(rotulo(pz)),
      resposta: antes.length ? h.antesSim(antes.length, destinos.length, lista(destinos.map(rotulo))) : h.antesNao,
      achou: antes.length > 0,
      filtro: { ips: [pz], portas: [] },
    });
  }

  for (const a of alertas) {
    porAlerta(a);
  }
  return saida;

  function porAlerta(a: Alerta) {
    const alvo = a.alvo ?? a.alvo_ip ?? "";

    if (a.regra === "download_executavel") {
      const antes = new Set(r.fluxos.filter((f) => f.origem === a.host && f.inicio_us <= a.inicio_us).map((f) => f.destino));
      const novos = [...new Set(r.fluxos
        .filter((f) => f.origem === a.host && f.inicio_us > a.inicio_us && deFora(f.destino) && !antes.has(f.destino))
        .map((f) => f.destino))];
      somar({
        chave: `download:${a.host}`,
        pergunta: h.download(rotulo(a.host)),
        resposta: novos.length ? h.downloadSim(novos.length, lista(novos.map(rotulo))) : h.downloadNao(rotulo(a.host)),
        achou: novos.length > 0,
        filtro: { ips: [a.host], portas: [] },
      });
    }

    if (FASES_MALICIOSAS.has(a.fase) && a.alvo_ip && deFora(a.alvo_ip)) {
      const outros = [...new Set(r.fluxos.filter((f) => f.destino === a.alvo_ip && f.origem !== a.host).map((f) => f.origem))];
      somar({
        chave: `outros-ip:${a.alvo_ip}`,
        pergunta: h.outrosIp(rotulo(a.alvo_ip)),
        resposta: outros.length ? h.outrosSim(outros.length, lista(outros.map(rotulo))) : h.outrosNao,
        achou: outros.length > 0,
        filtro: { ips: [a.alvo_ip], portas: [] },
      });
    }

    if (FASES_MALICIOSAS.has(a.fase) && a.alvo && !ehIp(a.alvo)) {
      const dominio = a.alvo.toLowerCase();
      const outros = [...new Set(r.dns
        .filter((d) => d.cliente !== a.host && (d.consulta === dominio || d.consulta.endsWith(`.${dominio}`)))
        .map((d) => d.cliente))];
      somar({
        chave: `outros-dns:${dominio}`,
        pergunta: h.outrosDns(dominio),
        resposta: outros.length ? h.outrosSim(outros.length, lista(outros.map(rotulo))) : h.outrosNao,
        achou: outros.length > 0,
      });
    }

    if (a.regra === "forca_bruta") {
      const sucesso = a.parametros.sucesso === "true";
      somar({
        chave: `bruta:${a.host}:${a.alvo_ip}`,
        pergunta: h.bruta(alvo),
        resposta: sucesso ? h.brutaSim : h.brutaNao,
        achou: sucesso,
        filtro: a.alvo_ip ? { ips: [a.host, a.alvo_ip], portas: [] } : undefined,
      });
    }

    if (a.regra === "varredura_portas" && a.alvo_ip) {
      const abertas = [...new Set(r.fluxos
        .filter((f) => f.origem === a.host && f.destino === a.alvo_ip && ["aberta", "encerrada"].includes(f.estado))
        .map((f) => f.porta_destino))].sort((x, y) => x - y);
      somar({
        chave: `varredura:${a.host}:${a.alvo_ip}`,
        pergunta: h.varredura(alvo),
        resposta: abertas.length ? h.varreduraSim(abertas.slice(0, 10).join(", ")) : h.varreduraNao,
        achou: abertas.length > 0,
        filtro: { ips: [a.host, a.alvo_ip], portas: [] },
      });
    }

    if (a.regra === "exfiltracao_volume" || a.regra === "tunel_dns" || a.regra === "beaconing") {
      const fora = r.fluxos.filter((f) => f.origem === a.host && deFora(f.destino));
      const porDestino = new Map<string, number>();
      for (const f of fora) porDestino.set(f.destino, (porDestino.get(f.destino) ?? 0) + f.bytes_ida);
      const total = [...porDestino.values()].reduce((x, y) => x + y, 0);
      const maior = [...porDestino.entries()].sort((x, y) => y[1] - x[1])[0];
      if (maior) {
        somar({
          chave: `volume:${a.host}`,
          pergunta: h.volume(rotulo(a.host)),
          resposta: h.volumeResposta(tamanho(total), porDestino.size, `${rotulo(maior[0])} (${tamanho(maior[1])})`),
          filtro: { ips: [a.host], portas: [] },
        });
      }
    }
  }
}
