// Replay da rede: as conexões acendem e apagam no tempo da captura, com os
// alertas marcados na régua. Quem inicia fica à esquerda, quem recebe à
// direita; a captura inteira toca em DURACAO_BASE segundos na velocidade 1×.

import { useEffect, useMemo, useRef, useState } from "react";
import { Pause, Play, SkipBack } from "lucide-react";
import { useTextos } from "./idiomas";
import { TEXTOS_INTELIGENCIA } from "./textos-inteligencia";
import { duracao, hora, numero, tamanho } from "./formatos";
import type { Contexto } from "./paginas";
import type { Alerta, Fluxo } from "./tipos";

const DURACAO_BASE = 30;
const VELOCIDADES = [0.25, 0.5, 1, 2, 4];
const MAX_ORIGENS = 10;
const MAX_DESTINOS = 14;
const LINHA = 34;
const LARGURA = 900;
const X_ESQ = 200;
const X_DIR = 700;
/** Fração da captura em que uma conexão curta continua acesa, para dar para ver. */
const RASTRO = 0.015;

interface Par {
  origem: string;
  destino: string;
  fluxos: Fluxo[];
  bytes: number;
  alerta: boolean;
}

const corta = (s: string, n = 26) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

export function Replay({ r, nomes }: Contexto) {
  const { idioma } = useTextos();
  const tr = TEXTOS_INTELIGENCIA[idioma].replay;
  const ti = TEXTOS_INTELIGENCIA[idioma];
  const inicio = r.captura.inicio_us;
  const total = Math.max(1, r.captura.fim_us - inicio);

  const [pos, setPos] = useState(0);
  const [tocando, setTocando] = useState(false);
  const [velocidade, setVelocidade] = useState(1);
  const anterior = useRef<number | null>(null);

  const modelo = useMemo(() => {
    const fluxosDeAlerta = new Set(r.alertas.flatMap((a) => a.fluxos));
    const porOrigem = new Map<string, number>();
    for (const f of r.fluxos) porOrigem.set(f.origem, (porOrigem.get(f.origem) ?? 0) + f.bytes_ida + f.bytes_volta);
    // Hosts com alerta entram primeiro: é por eles que se abre o replay.
    const comAlerta = new Set(r.alertas.map((a) => a.host));
    const origens = [...porOrigem.entries()]
      .sort((a, b) => Number(comAlerta.has(b[0])) - Number(comAlerta.has(a[0])) || b[1] - a[1])
      .slice(0, MAX_ORIGENS)
      .map(([ip]) => ip);
    const setOrigens = new Set(origens);

    const porDestino = new Map<string, number>();
    const alvos = new Set(r.alertas.map((a) => a.alvo_ip).filter(Boolean) as string[]);
    for (const f of r.fluxos) {
      if (setOrigens.has(f.origem)) porDestino.set(f.destino, (porDestino.get(f.destino) ?? 0) + f.bytes_ida + f.bytes_volta);
    }
    const destinos = [...porDestino.entries()]
      .sort((a, b) => Number(alvos.has(b[0])) - Number(alvos.has(a[0])) || b[1] - a[1])
      .slice(0, MAX_DESTINOS)
      .map(([ip]) => ip);
    const setDestinos = new Set(destinos);

    const pares = new Map<string, Par>();
    let fora = 0;
    for (const f of r.fluxos) {
      if (!setOrigens.has(f.origem) || !setDestinos.has(f.destino)) {
        fora++;
        continue;
      }
      const k = `${f.origem}|${f.destino}`;
      let p = pares.get(k);
      if (!p) {
        p = { origem: f.origem, destino: f.destino, fluxos: [], bytes: 0, alerta: false };
        pares.set(k, p);
      }
      p.fluxos.push(f);
      p.bytes += f.bytes_ida + f.bytes_volta;
      if (fluxosDeAlerta.has(f.id)) p.alerta = true;
    }
    const maxBytes = Math.max(1, ...[...pares.values()].map((p) => p.bytes));
    return { origens, destinos, pares: [...pares.values()], fora, maxBytes };
  }, [r]);

  useEffect(() => {
    if (!tocando) {
      anterior.current = null;
      return;
    }
    let quadro = 0;
    const passo = (agora: number) => {
      if (anterior.current !== null) {
        const dt = (agora - anterior.current) / 1000;
        setPos((p) => {
          const n = p + (dt * velocidade) / DURACAO_BASE;
          if (n >= 1) {
            setTocando(false);
            return 1;
          }
          return n;
        });
      }
      anterior.current = agora;
      quadro = requestAnimationFrame(passo);
    };
    quadro = requestAnimationFrame(passo);
    return () => cancelAnimationFrame(quadro);
  }, [tocando, velocidade]);

  const t = inicio + pos * total;
  const rastro = RASTRO * total;
  const ativo = (f: Fluxo) => f.inicio_us <= t && f.fim_us + rastro >= t;
  const ativos = modelo.pares.filter((p) => p.fluxos.some(ativo));
  const nosAtivos = new Set(ativos.flatMap((p) => [`o:${p.origem}`, `d:${p.destino}`]));
  const conexoesAtivas = r.fluxos.filter(ativo).length;
  const alertasAgora = r.alertas.filter((a) => a.inicio_us <= t && a.fim_us + rastro >= t);

  const altura = Math.max(modelo.origens.length, modelo.destinos.length) * LINHA + 50;
  const y = (i: number, n: number) => 40 + i * LINHA + ((Math.max(modelo.origens.length, modelo.destinos.length) - n) * LINHA) / 2;
  const yOrigem = new Map(modelo.origens.map((ip, i) => [ip, y(i, modelo.origens.length)]));
  const yDestino = new Map(modelo.destinos.map((ip, i) => [ip, y(i, modelo.destinos.length)]));
  const rotulo = (ip: string) => corta(nomes.get(ip) ? `${nomes.get(ip)} · ${ip}` : ip);
  const espessura = (b: number) => 1 + 4 * (Math.log(1 + b) / Math.log(1 + modelo.maxBytes));
  const hostsComAlerta = new Set(r.alertas.map((a) => a.host));

  function irPara(a: Alerta) {
    setTocando(false);
    setPos(Math.min(1, Math.max(0, (a.inicio_us - inicio) / total)));
  }

  if (r.fluxos.length === 0) return <div className="bloco suave">{tr.vazio}</div>;

  return (
    <>
      <div className="bloco">
        <div className="suave">{tr.explicacao}</div>
      </div>

      <div className="bloco replay">
        <div className="replay-controles">
          <button onClick={() => { if (pos >= 1) setPos(0); setTocando(!tocando); }} aria-label={tocando ? tr.pausar : tr.tocar}>
            {tocando ? <Pause size={15} /> : <Play size={15} />} {tocando ? tr.pausar : tr.tocar}
          </button>
          <button onClick={() => { setTocando(false); setPos(0); }} aria-label={tr.reiniciar} title={tr.reiniciar}>
            <SkipBack size={15} />
          </button>
          <label className="replay-velocidade">
            {tr.velocidade}
            <select value={velocidade} onChange={(e) => setVelocidade(Number(e.target.value))}>
              {VELOCIDADES.map((v) => <option key={v} value={v}>{v}×</option>)}
            </select>
          </label>
          <span className="mono replay-relogio">{hora(t)} UTC · +{duracao(t - inicio)}</span>
          <span className="suave">{tr.ativas(conexoesAtivas, numero(conexoesAtivas, idioma))}</span>
        </div>

        <div className="replay-regua">
          <input
            type="range"
            min={0}
            max={1000}
            value={Math.round(pos * 1000)}
            aria-label={tr.posicao}
            onChange={(e) => { setTocando(false); setPos(Number(e.target.value) / 1000); }}
          />
          <div className="replay-marcas">
            {r.alertas.map((a) => (
              <button
                key={a.id}
                className={`replay-marca sev-${a.severidade}`}
                style={{ left: `${((a.inicio_us - inicio) / total) * 100}%` }}
                title={`${hora(a.inicio_us)} · ${ti.regras[a.regra]?.nome ?? a.regra}`}
                aria-label={`${hora(a.inicio_us)} · ${ti.regras[a.regra]?.nome ?? a.regra}`}
                onClick={() => irPara(a)}
              />
            ))}
          </div>
        </div>

        <div className="rolagem">
          <svg className="replay-grafo" viewBox={`0 0 ${LARGURA} ${altura}`} role="img" aria-label={tr.titulo}>
            <text x={X_ESQ} y={18} textAnchor="end" className="replay-coluna">{tr.quemInicia}</text>
            <text x={X_DIR} y={18} className="replay-coluna">{tr.quemRecebe}</text>

            {modelo.pares.map((p) => {
              const aceso = ativos.includes(p);
              const y1 = yOrigem.get(p.origem)!;
              const y2 = yDestino.get(p.destino)!;
              const meio = (X_ESQ + X_DIR) / 2;
              return (
                <path
                  key={`${p.origem}|${p.destino}`}
                  d={`M ${X_ESQ + 8} ${y1} C ${meio} ${y1}, ${meio} ${y2}, ${X_DIR - 8} ${y2}`}
                  className={`replay-aresta ${aceso ? "acesa" : ""} ${p.alerta ? "alerta" : ""}`}
                  strokeWidth={aceso ? espessura(p.bytes) : 1}
                >
                  <title>{`${p.origem} → ${p.destino} · ${p.fluxos.length} · ${tamanho(p.bytes)}`}</title>
                </path>
              );
            })}

            {modelo.origens.map((ip) => (
              <g key={`o:${ip}`} className={`replay-no ${nosAtivos.has(`o:${ip}`) ? "aceso" : ""} ${hostsComAlerta.has(ip) ? "alerta" : ""}`}>
                <circle cx={X_ESQ} cy={yOrigem.get(ip)} r={6} />
                <text x={X_ESQ - 14} y={yOrigem.get(ip)! + 4} textAnchor="end">{rotulo(ip)}</text>
                <title>{ip}</title>
              </g>
            ))}
            {modelo.destinos.map((ip) => (
              <g key={`d:${ip}`} className={`replay-no ${nosAtivos.has(`d:${ip}`) ? "aceso" : ""}`}>
                <circle cx={X_DIR} cy={yDestino.get(ip)} r={6} />
                <text x={X_DIR + 14} y={yDestino.get(ip)! + 4}>{rotulo(ip)}</text>
                <title>{ip}</title>
              </g>
            ))}
          </svg>
        </div>

        <div className="legenda">
          <span><span className="marca-linha" /> {tr.conexao}</span>
          <span><span className="marca-linha alerta" /> {tr.conexaoAlerta}</span>
          {modelo.fora > 0 && <span>{tr.fora(numero(modelo.fora, idioma))}</span>}
        </div>
      </div>

      <div className="bloco">
        <h2>{tr.agora}</h2>
        {alertasAgora.length === 0 ? (
          <div className="fraco">{tr.nenhumAlerta}</div>
        ) : (
          <ul className="lista">
            {alertasAgora.map((a) => (
              <li key={a.id}>
                <span className={`selo ${a.severidade === "alta" ? "erro" : a.severidade === "media" ? "andamento" : ""}`}>{ti.severidades[a.severidade]}</span>{" "}
                {ti.regras[a.regra]?.titulo({ h: a.host, alvo: a.alvo ?? "", p: a.parametros }) ?? a.regra}
                <span className="fraco"> · {a.host}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </>
  );
}
