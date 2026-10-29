import { useMemo, useState } from "react";
import { BookOpen, ChevronDown, ChevronRight, ExternalLink, ShieldCheck } from "lucide-react";
import { useTextos } from "./idiomas";
import { TEXTOS_INTELIGENCIA, type A } from "./textos-inteligencia";
import { duracao, hora, numero, ponta, tamanho } from "./formatos";
import {
  D3FEND_IMPLEMENTADAS, MITRE, ORDEM_D3FEND, REGRA, TECNICAS, defesasDe, detectadaViaSub, regrasDe, status,
  subtecnicas, urlDefesa, urlTecnica, type Status, type TecnicaMitre,
} from "./mitre";
import type { Contexto } from "./paginas";
import type { Alerta, Relatorio } from "./tipos";

function useTi() {
  const { idioma } = useTextos();
  return TEXTOS_INTELIGENCIA[idioma];
}

const rotulo = (ip: string, nomes: Map<string, string>) => (nomes.get(ip) ? `${ip} (${nomes.get(ip)})` : ip);

function dadosDoAlerta(a: Alerta, nomes: Map<string, string>): A {
  return { h: rotulo(a.host, nomes), alvo: a.alvo ?? "", p: a.parametros };
}

function textoRegra(ti: ReturnType<typeof useTi>, a: Alerta) {
  return ti.regras[a.regra];
}

const CLASSE_SEVERIDADE: Record<string, string> = { alta: "erro", media: "andamento", baixa: "" };

function SeloSeveridade({ s }: { s: string }) {
  const ti = useTi();
  return <span className={`selo resultado ${CLASSE_SEVERIDADE[s]}`}>{ti.severidades[s]}</span>;
}

function LinkTecnica({ id }: { id: string }) {
  const t = TECNICAS.get(id);
  return (
    <a className="tecnica" href={urlTecnica(id)} target="_blank" rel="noreferrer noopener" title={t?.nome}>
      {id} {t?.nome}
    </a>
  );
}

// ---------- evidências ----------

function Evidencias({ r, ids, nomes }: { r: Relatorio; ids: number[]; nomes: Map<string, string> }) {
  const { t } = useTextos();
  const ti = useTi();
  const conjunto = useMemo(() => new Set(ids), [ids]);
  const fluxos = useMemo(() => r.fluxos.filter((f) => conjunto.has(f.id)).sort((a, b) => a.inicio_us - b.inicio_us), [r, conjunto]);
  const eventos = useMemo(() => {
    const e: { ts: number; tipo: string; texto: string }[] = [];
    const nome = (ip: string) => rotulo(ip, nomes);
    for (const d of r.dns) if (conjunto.has(d.fluxo)) e.push({ ts: d.ts_us, tipo: "DNS", texto: t.linha.dns(nome(d.cliente), d.consulta, d.tipo, d.respostas.slice(0, 2).join(", ")) });
    for (const h of r.http) if (conjunto.has(h.fluxo)) e.push({ ts: h.ts_us, tipo: "HTTP", texto: t.linha.http(nome(h.cliente), h.metodo, `${h.host ?? h.servidor}${h.caminho}`, h.status ? String(h.status) : "") });
    for (const s of r.tls) if (conjunto.has(s.fluxo)) e.push({ ts: s.ts_us, tipo: "TLS", texto: t.linha.tls(nome(s.cliente), s.sni ?? s.servidor, s.versao ?? "") });
    return e.sort((a, b) => a.ts - b.ts).slice(0, 50);
  }, [r, conjunto, nomes, t]);

  return (
    <div className="evidencias">
      {eventos.length > 0 && (
        <ul className="lista-eventos">
          {eventos.map((e, i) => (
            <li key={i}><span className="mono fraco">{hora(e.ts)}</span> <span className="selo">{e.tipo}</span> {e.texto}</li>
          ))}
        </ul>
      )}
      <div className="rolagem">
        <table>
          <thead>
            <tr>
              <th>{t.col.inicio}</th><th>{t.col.origem}</th><th>{t.col.destino}</th><th>{t.col.aplicacao}</th>
              <th>{t.col.estado}</th><th className="num">{t.col.bytes}</th><th className="num">{t.col.duracao}</th>
            </tr>
          </thead>
          <tbody>
            {fluxos.slice(0, 50).map((f) => (
              <tr key={f.id}>
                <td className="mono">{hora(f.inicio_us)}</td>
                <td className="mono">{ponta(f.origem, f.porta_origem)}</td>
                <td className="mono">{ponta(f.destino, f.porta_destino)}{nomes.get(f.destino) && <span className="fraco"> · {nomes.get(f.destino)}</span>}</td>
                <td>{f.aplicacao}</td>
                <td>{t.estados[f.estado]}</td>
                <td className="num">{tamanho(f.bytes_ida + f.bytes_volta)}</td>
                <td className="num">{duracao(f.fim_us - f.inicio_us)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {fluxos.length > 50 && <div className="fraco">{t.mostrando("50", String(fluxos.length))}</div>}
      {eventos.length === 0 && fluxos.length === 0 && <div className="fraco">{ti.alertas.evidenciasFora}</div>}
    </div>
  );
}

function BotaoEvidencias({ r, a, nomes }: { r: Relatorio; a: Alerta; nomes: Map<string, string> }) {
  const ti = useTi();
  const [aberto, setAberto] = useState(false);
  return (
    <>
      <button className="link" onClick={() => setAberto(!aberto)}>
        {aberto ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        {aberto ? ti.alertas.ocultar : ti.alertas.evidencias(a.fluxos.length)}
      </button>
      {aberto && <Evidencias r={r} ids={a.fluxos} nomes={nomes} />}
    </>
  );
}

// ---------- contramedidas ----------

function Contramedidas({ tecnica, implementa }: { tecnica: string | null; implementa: string[] }) {
  const ti = useTi();
  const [todas, setTodas] = useState(false);
  const ids = defesasDe(tecnica).filter((d) => !implementa.includes(d));
  const porTatica = ORDEM_D3FEND.map((tat) => [tat, ids.filter((d) => MITRE.defesas[d]?.tatica === tat)] as const)
    .filter(([, ds]) => ds.length);
  const LIMITE = 10;
  let restantes = todas ? Infinity : LIMITE;

  return (
    <div className="contramedidas">
      {implementa.length > 0 && (
        <div>
          <span className="fraco">{ti.alertas.implementa}: </span>
          {implementa.map((d) => <ChipDefesa key={d} id={d} implementada />)}
        </div>
      )}
      <div className="fraco">{ti.alertas.contramedidas}</div>
      {ids.length === 0 && <div className="fraco">{ti.alertas.semD3fend}</div>}
      {porTatica.map(([tat, ds]) => {
        if (restantes <= 0) return null;
        const mostrar = ds.slice(0, restantes);
        restantes -= mostrar.length;
        return (
          <div key={tat} className="linha-defesas">
            <span className="tatica-defesa">{ti.d3fendTaticas[tat] ?? tat}</span>
            {mostrar.map((d) => <ChipDefesa key={d} id={d} />)}
          </div>
        );
      })}
      {!todas && ids.length > LIMITE && (
        <button className="link" onClick={() => setTodas(true)}>{ti.alertas.maisContramedidas(ids.length - LIMITE)}</button>
      )}
    </div>
  );
}

function ChipDefesa({ id, implementada }: { id: string; implementada?: boolean }) {
  const d = MITRE.defesas[id];
  return (
    <a className={`chip-defesa ${implementada ? "implementada" : ""}`} href={urlDefesa(id)} target="_blank" rel="noreferrer noopener" title={d?.nome}>
      {implementada && <ShieldCheck size={12} />} {id} {d?.nome}
    </a>
  );
}

// ---------- página: alertas ----------

const PESO: Record<string, number> = { alta: 0, media: 1, baixa: 2 };

export function Alertas({ r, nomes }: Contexto) {
  const ti = useTi();
  const { idioma } = useTextos();
  const ordenados = useMemo(() => [...r.alertas].sort((a, b) => PESO[a.severidade] - PESO[b.severidade] || a.inicio_us - b.inicio_us), [r]);
  const contagem = (s: string) => r.alertas.filter((a) => a.severidade === s).length;

  if (r.alertas.length === 0) return <div className="vazio">{ti.alertas.nenhum}</div>;
  return (
    <>
      <div className="cartoes">
        {(["alta", "media", "baixa"] as const).map((s) => (
          <div key={s} className="cartao">
            <div className="rotulo">{ti.severidades[s]}</div>
            <div className={`valor ${s === "alta" && contagem(s) ? "destaque" : ""}`}>{numero(contagem(s), idioma)}</div>
          </div>
        ))}
      </div>
      {ordenados.map((a) => {
        const tx = textoRegra(ti, a);
        const d = dadosDoAlerta(a, nomes);
        return (
          <div key={a.id} className={`bloco alerta sev-${a.severidade}`}>
            <div className="alerta-topo">
              <SeloSeveridade s={a.severidade} />
              <h3>{tx ? tx.titulo(d) : a.regra}</h3>
              <span className="fraco mono alerta-hora">{hora(a.inicio_us)}{a.fim_us > a.inicio_us && ` → ${hora(a.fim_us)}`}</span>
            </div>
            <p>{tx ? tx.frase(d) : ""}</p>
            {tx && <p className="suave"><b>{ti.alertas.porque}:</b> {tx.porque}</p>}
            <div className="alerta-meta">
              <span className="selo">{ti.fases[a.fase]}</span>
              {a.tecnica && <LinkTecnica id={a.tecnica} />}
            </div>
            <Contramedidas tecnica={a.tecnica} implementa={REGRA.get(a.regra)?.d3fend ?? []} />
            <BotaoEvidencias r={r} a={a} nomes={nomes} />
          </div>
        );
      })}
    </>
  );
}

// ---------- página: história ----------

export function Historia({ r, nomes }: Contexto) {
  const ti = useTi();
  const { idioma } = useTextos();
  const h = r.historia;
  const porId = useMemo(() => new Map(r.alertas.map((a) => [a.id, a])), [r]);
  const dominios = useMemo(() => new Set(r.dns.map((d) => d.consulta)).size, [r]);
  const nasCadeias = new Set(h.cadeias.flatMap((c) => c.passos.map((p) => p.alerta)));
  const soltos = r.alertas.filter((a) => !nasCadeias.has(a.id)).length;

  const principal = h.cadeias[0];
  return (
    <>
      {principal ? (
        <div className="bloco destaque-rosa resumo-historia">
          <BookOpen size={18} />
          <div>
            {ti.historia.pacienteZero(
              rotulo(principal.host, nomes),
              principal.passos.length,
              new Set(principal.passos.map((p) => p.fase)).size,
              hora(principal.inicio_us).slice(0, 8),
              hora(principal.fim_us).slice(0, 8),
            )}
            {" "}<span className="selo suspeita">{ti.confiancas[principal.confianca]}</span>
          </div>
        </div>
      ) : r.alertas.length > 0 ? (
        <div className="bloco aviso">
          <p>{ti.historia.semCadeia(r.alertas.length)}</p>
        </div>
      ) : (
        <div className="bloco">
          <p>{ti.historia.semSuspeitas}</p>
          <p className="suave">
            {ti.historia.semSuspeitasDetalhe(numero(r.total_hosts, idioma), numero(r.total_fluxos, idioma), numero(dominios, idioma))}
          </p>
        </div>
      )}

      {h.hosts_afetados.length > 0 && (
        <div className="bloco">
          <h2>{ti.historia.tambem}</h2>
          <div className="suave">{ti.historia.tambemDetalhe}</div>
          <div className="tecnicas" style={{ marginTop: 8 }}>
            {h.hosts_afetados.map((ip) => <span key={ip} className="selo">{rotulo(ip, nomes)}</span>)}
          </div>
        </div>
      )}

      {h.cadeias.map((c, i) => (
        <div key={c.host} className="bloco">
          {i === 1 && <h2>{ti.historia.outras}</h2>}
          <div className="cadeia-topo">
            <h3>{ti.historia.sequencia(rotulo(c.host, nomes))}</h3>
            <span className="selo">{ti.confiancas[c.confianca]}</span>
          </div>
          <ol className="passos">
            {c.passos.map((p) => {
              const a = porId.get(p.alerta);
              if (!a) return null;
              const tx = textoRegra(ti, a);
              const frase = tx ? tx.frase(dadosDoAlerta(a, nomes)) : a.regra;
              const prefixo = p.ligacao ? ti.ligacoes[p.ligacao] : "";
              return (
                <li key={p.alerta} className={`passo sev-${a.severidade}`}>
                  <div className="passo-cabeca">
                    <span className="mono fraco">{hora(p.ts_us).slice(0, 8)}</span>
                    <span className="selo">{ti.fases[p.fase]}</span>
                    <SeloSeveridade s={a.severidade} />
                    {a.tecnica && <LinkTecnica id={a.tecnica} />}
                  </div>
                  <p>{prefixo}{frase}</p>
                  <BotaoEvidencias r={r} a={a} nomes={nomes} />
                </li>
              );
            })}
          </ol>
        </div>
      ))}

      {soltos > 0 && h.cadeias.length > 0 && <div className="fraco">{ti.historia.alertasSoltos(soltos)}</div>}

      <HistoriaFactual r={r} nomes={nomes} />

      <div className="bloco">
        <h2>{ti.historia.naoMostraTitulo}</h2>
        <ul className="lista">
          {h.nao_mostra.map((c) => <li key={c}>{ti.naoMostra[c] ?? c}</li>)}
        </ul>
      </div>
    </>
  );
}

/**
 * A parte factual da história: o que cada host fez, com ou sem alerta. Sem
 * isso, uma captura que nenhuma regra reconhece ficaria sem narrativa.
 */
function HistoriaFactual({ r, nomes }: { r: Relatorio; nomes: Map<string, string> }) {
  const ti = useTi();
  const MOSTRAR = 8;
  const linhas = useMemo(() => {
    interface Atividade {
      host: string; conexoes: number; destinos: Set<string>; sem: number; recusadas: number; enviados: number;
      dns: number; dnsSem: number; nx: number; http: number; erros: number;
    }
    const por = new Map<string, Atividade>();
    const de = (host: string) => {
      let a = por.get(host);
      if (!a) {
        a = { host, conexoes: 0, destinos: new Set(), sem: 0, recusadas: 0, enviados: 0, dns: 0, dnsSem: 0, nx: 0, http: 0, erros: 0 };
        por.set(host, a);
      }
      return a;
    };
    for (const f of r.fluxos) {
      // DNS entra pelas consultas, não como conexão.
      if (f.aplicacao === "DNS" && !f.aplicacao_por_porta) continue;
      const a = de(f.origem);
      a.conexoes++;
      a.destinos.add(f.destino);
      a.enviados += f.bytes_ida;
      if (f.estado === "sem_resposta") a.sem++;
      if (f.estado === "recusada") a.recusadas++;
    }
    for (const d of r.dns) {
      const a = de(d.cliente);
      a.dns++;
      if (d.rcode === null) a.dnsSem++;
      if (d.rcode === 3) a.nx++;
    }
    for (const h of r.http) {
      const a = de(h.cliente);
      a.http++;
      if (h.status !== null && h.status >= 400) a.erros++;
    }
    return [...por.values()].sort((x, y) => (y.conexoes + y.dns + y.http) - (x.conexoes + x.dns + x.http));
  }, [r]);

  const f = ti.factual;
  return (
    <div className="bloco">
      <h2>{f.titulo}</h2>
      <div className="suave">{f.subtitulo}</div>
      <ul className="lista">
        {linhas.slice(0, MOSTRAR).map((a) => {
          const partes: string[] = [];
          if (a.conexoes) {
            let p = f.conexoes(a.conexoes, a.destinos.size);
            if (a.sem) p += `, ${f.semResposta(a.sem)}`;
            if (a.recusadas) p += `, ${f.recusadas(a.recusadas)}`;
            partes.push(p);
          }
          if (a.dns) partes.push(f.dns(a.dns, a.dnsSem, a.nx));
          if (a.http) partes.push(f.http(a.http, a.erros));
          if (a.enviados) partes.push(f.enviou(tamanho(a.enviados)));
          return <li key={a.host}><b className="mono">{rotulo(a.host, nomes)}</b> {partes.join("; ")}.</li>;
        })}
      </ul>
      {linhas.length > MOSTRAR && <div className="fraco">{f.mais(linhas.length - MOSTRAR)}</div>}
    </div>
  );
}

// ---------- página: cobertura ----------

const CLASSE_STATUS: Record<Status, string> = { detectada: "st-detectada", observavel: "st-observavel", nao_observavel: "st-fora" };

export function Cobertura() {
  const ti = useTi();
  const { idioma } = useTextos();
  const [filtro, setFiltro] = useState<Status | "todas">("todas");
  const [termo, setTermo] = useState("");
  const [aberta, setAberta] = useState<TecnicaMitre | null>(null);

  const contagem = useMemo(() => {
    const c: Record<Status, number> = { detectada: 0, observavel: 0, nao_observavel: 0 };
    for (const t of MITRE.tecnicas) c[status(t)]++;
    return c;
  }, []);

  const q = termo.trim().toLowerCase();
  const visivel = (t: TecnicaMitre) => {
    const casa = !q || t.id.toLowerCase().includes(q) || t.nome.toLowerCase().includes(q)
      || subtecnicas(t.id).some((s) => s.id.toLowerCase().includes(q) || s.nome.toLowerCase().includes(q));
    const st = filtro === "todas" || status(t) === filtro || subtecnicas(t.id).some((s) => status(s) === filtro);
    return casa && st;
  };

  const totalDefesas = Object.keys(MITRE.defesas).length;

  return (
    <>
      <div className="suave">{ti.cobertura.subtitulo}</div>
      <div className="cartoes">
        {(["detectada", "observavel", "nao_observavel"] as const).map((s) => (
          <button key={s} className={`cartao cartao-botao ${filtro === s ? "marcado" : ""}`} onClick={() => setFiltro(filtro === s ? "todas" : s)}>
            <div className="rotulo"><i className={`marca-status ${CLASSE_STATUS[s]}`} /> {ti.cobertura[s]}</div>
            <div className={`valor ${s === "detectada" ? "destaque" : ""}`}>{numero(contagem[s], idioma)}</div>
          </button>
        ))}
        <div className="cartao">
          <div className="rotulo">ATT&CK Enterprise</div>
          <div className="valor">{ti.cobertura.tecnicas(numero(MITRE.tecnicas.length, idioma))}</div>
        </div>
      </div>
      <div className="fraco">{ti.cobertura.explicacao}</div>

      <div className="barra-tabela">
        <input placeholder={ti.cobertura.filtro} value={termo} onChange={(e) => setTermo(e.target.value)} />
        <span className="fraco">{ti.cobertura.versoes(MITRE.versao_attack, MITRE.versao_d3fend)}</span>
      </div>

      {aberta && <DetalheTecnica t={aberta} fechar={() => setAberta(null)} />}

      <div className="rolagem matriz">
        {MITRE.taticas.map((tat) => {
          const tecnicas = MITRE.tecnicas.filter((t) => !t.sub && t.taticas.includes(tat.fase) && visivel(t));
          return (
            <div key={tat.id} className="coluna-tatica">
              <div className="cabeca-tatica" title={tat.id}>{tat.nome}<span className="fraco"> {tecnicas.length}</span></div>
              {tecnicas.map((t) => {
                const subs = subtecnicas(t.id);
                return (
                  <button key={t.id} className={`celula ${CLASSE_STATUS[status(t)]} ${aberta?.id === t.id ? "aberta" : ""}`} onClick={() => setAberta(t)} title={`${t.id} ${t.nome}`}>
                    <span className="mono">{t.id}</span> {t.nome}
                    {subs.length > 0 && (
                      <span className="subs">{subs.map((s) => <i key={s.id} className={`marca-status ${CLASSE_STATUS[status(s)]}`} title={`${s.id} ${s.nome}`} />)}</span>
                    )}
                  </button>
                );
              })}
            </div>
          );
        })}
      </div>

      <div className="bloco">
        <h2>{ti.cobertura.d3fendTitulo}</h2>
        <p className="suave">{ti.cobertura.d3fendResumo(D3FEND_IMPLEMENTADAS.size, totalDefesas)}</p>
        <MatrizD3fend />
      </div>

      <div className="fraco atribuicao">{MITRE.atribuicao}</div>
    </>
  );
}

/**
 * Matriz do D3FEND como no site oficial: uma coluna por tática defensiva, as
 * contramedidas agrupadas pela categoria-mãe, e as que o Panthera Wire aplica
 * em destaque.
 */
function MatrizD3fend() {
  const ti = useTi();
  const [soAplicadas, setSoAplicadas] = useState(false);

  const colunas = useMemo(() => ORDEM_D3FEND.map((tatica) => {
    const daTatica = Object.entries(MITRE.defesas).filter(([, d]) => d.tatica === tatica);
    const grupos = new Map<string, string[]>();
    for (const [id, d] of daTatica) {
      if (id !== d.grupo) grupos.set(d.grupo, [...(grupos.get(d.grupo) ?? []), id]);
      else if (!grupos.has(id)) grupos.set(id, []);
    }
    const ordenados = [...grupos.entries()]
      .map(([grupo, ids]) => ({ grupo, ids: ids.sort((a, b) => MITRE.defesas[a].nome.localeCompare(MITRE.defesas[b].nome)) }))
      .sort((a, b) => MITRE.defesas[a.grupo].nome.localeCompare(MITRE.defesas[b.grupo].nome));
    return { tatica, total: daTatica.length, aplicadas: daTatica.filter(([id]) => D3FEND_IMPLEMENTADAS.has(id)).length, grupos: ordenados };
  }), []);

  return (
    <>
      <label className="marcar" style={{ margin: "4px 0 10px" }}>
        <input type="checkbox" checked={soAplicadas} onChange={(e) => setSoAplicadas(e.target.checked)} />
        {ti.cobertura.soAplicadas}
      </label>
      <div className="rolagem matriz matriz-d3">
        {colunas.map(({ tatica, total, aplicadas, grupos }) => (
          <div key={tatica} className="coluna-tatica">
            <div className="cabeca-tatica cabeca-d3">
              <span>{ti.d3fendTaticas[tatica] ?? tatica}</span>
              <span className="fraco">{total}</span>
              {aplicadas > 0 && <span className="selo suspeita">{ti.cobertura.aplicadas(aplicadas)}</span>}
            </div>
            {grupos.map(({ grupo, ids }) => {
              const visiveis = soAplicadas ? ids.filter((id) => D3FEND_IMPLEMENTADAS.has(id)) : ids;
              const categoriaAplicada = D3FEND_IMPLEMENTADAS.has(grupo);
              if (soAplicadas && visiveis.length === 0 && !categoriaAplicada) return null;
              const temAplicada = categoriaAplicada || ids.some((id) => D3FEND_IMPLEMENTADAS.has(id));
              return (
                <div key={grupo} className={`grupo-d3 ${temAplicada ? "com-aplicada" : ""}`}>
                  <a className={`titulo-grupo-d3 ${categoriaAplicada ? "aplicada" : ""}`} href={urlDefesa(grupo)} target="_blank" rel="noreferrer noopener">
                    {categoriaAplicada && <ShieldCheck size={12} />}
                    <span>{MITRE.defesas[grupo].nome}</span>
                    <span className="mono fraco">{grupo}</span>
                  </a>
                  {visiveis.map((id) => {
                    const aplicada = D3FEND_IMPLEMENTADAS.has(id);
                    return (
                      <a key={id} className={`item-d3 ${aplicada ? "aplicada" : ""}`} href={urlDefesa(id)} target="_blank" rel="noreferrer noopener" title={`${id} ${MITRE.defesas[id].nome}`}>
                        {aplicada && <ShieldCheck size={11} />}
                        <span>{MITRE.defesas[id].nome}</span>
                      </a>
                    );
                  })}
                </div>
              );
            })}
          </div>
        ))}
      </div>
      <div className="legenda">
        <span><i style={{ background: "var(--rosa)" }} /> {ti.cobertura.implementada}</span>
      </div>
    </>
  );
}

function DetalheTecnica({ t, fechar }: { t: TecnicaMitre; fechar: () => void }) {
  const ti = useTi();
  const st = status(t);
  const regras = regrasDe(t.id);
  const subs = subtecnicas(t.id);
  return (
    <div className={`bloco detalhe-tecnica ${CLASSE_STATUS[st]}`}>
      <div className="alerta-topo">
        <span className={`selo ${st === "detectada" ? "suspeita" : ""}`}>{ti.cobertura[st]}{detectadaViaSub(t) && ` · ${ti.cobertura.viaSub}`}</span>
        <h3><span className="mono">{t.id}</span> {t.nome}</h3>
        <a className="alerta-hora" href={urlTecnica(t.id)} target="_blank" rel="noreferrer noopener">{ti.cobertura.verNaMitre} <ExternalLink size={12} /></a>
        <button className="link" onClick={fechar}>×</button>
      </div>
      <div className="tecnicas">
        {t.taticas.map((f) => <span key={f} className="selo">{MITRE.taticas.find((x) => x.fase === f)?.nome ?? f}</span>)}
      </div>
      <p className="suave">
        {t.rede.length ? <><b>{ti.cobertura.componentes}:</b> {t.rede.join(", ")}</> : t.estrategia ? ti.cobertura.semPegada : ti.cobertura.semEstrategia}
      </p>
      {regras.length > 0 && (
        <p><b>{ti.cobertura.regras}:</b> {regras.map((r) => ti.regras[r.regra]?.nome ?? r.regra).join(" · ")}</p>
      )}
      {subs.length > 0 && (
        <div>
          <div className="fraco">{ti.cobertura.subtecnicas}</div>
          <div className="tecnicas">
            {subs.map((s) => (
              <a key={s.id} className={`chip-sub ${CLASSE_STATUS[status(s)]}`} href={urlTecnica(s.id)} target="_blank" rel="noreferrer noopener">
                <i className={`marca-status ${CLASSE_STATUS[status(s)]}`} /> {s.id} {s.nome}
              </a>
            ))}
          </div>
        </div>
      )}
      <Contramedidas tecnica={t.id} implementa={[...new Set(regras.flatMap((r) => r.d3fend))]} />
    </div>
  );
}
