import { useMemo, useState, type ReactNode } from "react";
import { AlertTriangle, KeyRound } from "lucide-react";
import { RCODES, useTextos } from "./idiomas";
import { dataHora, duracao, hora, numero, ponta, tamanho } from "./formatos";
import type { Contagem, Fluxo, Host, Relatorio } from "./tipos";

/** Quantas linhas uma tabela desenha de cada vez. */
const LINHAS_VISIVEIS = 500;

export interface Contexto {
  r: Relatorio;
  /** Primeiro nome conhecido de cada IP (DNS, SNI, HTTP, DHCP). */
  nomes: Map<string, string>;
  segundos: number;
  /** A captura original, para reler (anonimizar). */
  arquivo: File;
}

// ---------- peças comuns ----------

function Ip({ ip, nomes }: { ip: string; nomes: Map<string, string> }) {
  const nome = nomes.get(ip);
  return (
    <span className="mono" title={nome ? `${ip} · ${nome}` : ip}>
      {ip}
      {nome && <span className="fraco"> · {nome}</span>}
    </span>
  );
}

interface Coluna<T> {
  titulo: string;
  render: (linha: T) => ReactNode;
  numerica?: boolean;
}

function Tabela<T>({ linhas, total, colunas, busca }: {
  linhas: T[];
  total: number;
  colunas: Coluna<T>[];
  busca: (linha: T) => string;
}) {
  const { t, idioma } = useTextos();
  const [termo, setTermo] = useState("");
  const indice = useMemo(() => linhas.map((l) => busca(l).toLowerCase()), [linhas, busca]);
  const filtradas = useMemo(() => {
    const q = termo.trim().toLowerCase();
    return q ? linhas.filter((_, i) => indice[i].includes(q)) : linhas;
  }, [linhas, indice, termo]);
  const visiveis = filtradas.slice(0, LINHAS_VISIVEIS);

  return (
    <div className="bloco">
      <div className="barra-tabela">
        <input placeholder={t.filtrar} value={termo} onChange={(e) => setTermo(e.target.value)} />
        <span className="fraco">
          {t.mostrando(numero(visiveis.length, idioma), numero(termo ? filtradas.length : total, idioma))}
        </span>
      </div>
      <div className="rolagem">
        <table>
          <thead>
            <tr>{colunas.map((c) => <th key={c.titulo} className={c.numerica ? "num" : ""}>{c.titulo}</th>)}</tr>
          </thead>
          <tbody>
            {visiveis.map((l, i) => (
              <tr key={i}>
                {colunas.map((c) => <td key={c.titulo} className={c.numerica ? "num" : ""}>{c.render(l)}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
        {visiveis.length === 0 && <div className="vazio">{t.nada}</div>}
      </div>
    </div>
  );
}

/** Barras horizontais de série única: magnitude, sem legenda, valor ao lado. */
function Barras({ itens, valor, rotulo }: {
  itens: Contagem[];
  valor: (c: Contagem) => number;
  rotulo: (c: Contagem) => string;
}) {
  const { t } = useTextos();
  const max = Math.max(1, ...itens.map(valor));
  const principais = itens.slice(0, 8);
  const resto = itens.slice(8);
  const linhas = resto.length
    ? [...principais, resto.reduce((a, c) => ({ ...a, pacotes: a.pacotes + c.pacotes, bytes: a.bytes + c.bytes, fluxos: a.fluxos + c.fluxos }),
        { nome: t.visao.outros, pacotes: 0, bytes: 0, fluxos: 0 })]
    : principais;
  return (
    <div className="barras">
      {linhas.map((c) => (
        <div key={c.nome} className="barra-linha" title={`${c.nome}: ${rotulo(c)}`}>
          <span className="barra-nome">{c.nome}</span>
          <span className="barra-trilho">
            <span className="barra-valor" style={{ width: `${Math.max(1, (valor(c) / max) * 100)}%` }} />
          </span>
          <span className="barra-numero">{rotulo(c)}</span>
        </div>
      ))}
    </div>
  );
}

// ---------- páginas ----------

export function VisaoGeral({ r, nomes, segundos }: Contexto) {
  const { t, idioma } = useTextos();
  const c = r.captura;
  const dominios = useMemo(() => new Set(r.dns.map((d) => d.consulta)).size, [r]);
  const externos = useMemo(() => r.hosts.filter((h) => h.escopo === "externo")
    .sort((a, b) => b.fluxos_recebidos - a.fluxos_recebidos).slice(0, 10), [r]);

  return (
    <>
      <div className="cartoes">
        <Cartao rotulo={t.visao.pacotes} valor={numero(c.pacotes, idioma)} />
        <Cartao rotulo={t.visao.volume} valor={tamanho(c.bytes)} />
        <Cartao rotulo={t.visao.duracao} valor={duracao(c.fim_us - c.inicio_us)} />
        <Cartao rotulo={t.visao.hosts} valor={numero(r.total_hosts, idioma)} />
        <Cartao rotulo={t.visao.fluxos} valor={numero(r.total_fluxos, idioma)} />
        <Cartao rotulo={t.visao.dominios} valor={numero(dominios, idioma)} destaque />
      </div>

      <div className="suave">
        {t.visao.periodo}: {dataHora(c.inicio_us, idioma)} → {dataHora(c.fim_us, idioma)}
        {" · "}{t.visao.formato}: {c.formato} ({c.enlaces.join(", ")})
        {" · "}{t.visao.lidoEm(`${segundos.toFixed(1)} s`)}
      </div>

      <Avisos r={r} />

      <div className="grade-2">
        <div className="bloco">
          <h2>{t.visao.protocolos}</h2>
          <Barras itens={r.protocolos} valor={(p) => p.bytes} rotulo={(p) => tamanho(p.bytes)} />
        </div>
        <div className="bloco">
          <h2>{t.visao.aplicacoes}</h2>
          <Barras itens={r.aplicacoes} valor={(p) => p.fluxos} rotulo={(p) => t.visao.nFluxos(p.fluxos, numero(p.fluxos, idioma))} />
        </div>
      </div>

      <div className="grade-2">
        <div className="bloco">
          <h2>{t.visao.topHosts}</h2>
          <table>
            <tbody>
              {r.hosts.slice(0, 10).map((h) => (
                <tr key={h.ip}>
                  <td><Ip ip={h.ip} nomes={nomes} /></td>
                  <td><span className="selo">{t.escopos[h.escopo]}</span></td>
                  <td className="num">{tamanho(h.bytes_enviados + h.bytes_recebidos)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="bloco">
          <h2>{t.visao.destinosExternos}</h2>
          <table>
            <tbody>
              {externos.map((h) => (
                <tr key={h.ip}>
                  <td><Ip ip={h.ip} nomes={nomes} /></td>
                  <td className="num">{numero(h.fluxos_recebidos, idioma)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {externos.length === 0 && <div className="vazio">{t.nada}</div>}
        </div>
      </div>
    </>
  );
}

function Cartao({ rotulo, valor, destaque }: { rotulo: string; valor: string; destaque?: boolean }) {
  return (
    <div className="cartao">
      <div className="rotulo">{rotulo}</div>
      <div className={`valor ${destaque ? "destaque" : ""}`}>{valor}</div>
    </div>
  );
}

function Avisos({ r }: { r: Relatorio }) {
  const { t, idioma } = useTextos();
  const c = r.captura;
  if (c.avisos.length === 0 && c.nao_decodificados === 0) return null;
  return (
    <div className="bloco aviso">
      {c.avisos.map((a) => (
        <div key={a.codigo}>
          <AlertTriangle size={14} /> {t.avisos[a.codigo] ?? a.codigo}
          {a.offset !== undefined && a.codigo !== "arquivo_truncado" && ` ${t.parouEm(numero(a.offset, idioma))}`}
        </div>
      ))}
      {c.nao_decodificados > 0 && (
        <div><AlertTriangle size={14} /> {t.visao.naoDecodificados(numero(c.nao_decodificados, idioma))}</div>
      )}
    </div>
  );
}

type Evento = { ts: number; tipo: "DNS" | "HTTP" | "TLS" | "DHCP"; texto: string; destaque?: boolean };

export function LinhaDoTempo({ r, nomes }: Contexto) {
  const { t } = useTextos();
  const rotulo = (ip: string) => nomes.get(ip) ? `${ip} (${nomes.get(ip)})` : ip;
  const eventos = useMemo(() => {
    const e: Evento[] = [];
    for (const d of r.dns) {
      const resp = d.rcode !== null && d.rcode !== 0 ? RCODES[d.rcode] ?? `RCODE ${d.rcode}` : d.respostas.slice(0, 3).join(", ");
      e.push({ ts: d.ts_us, tipo: "DNS", texto: t.linha.dns(rotulo(d.cliente), d.consulta, d.tipo, resp), destaque: d.rcode === 3 });
    }
    for (const h of r.http) {
      e.push({ ts: h.ts_us, tipo: "HTTP", texto: t.linha.http(rotulo(h.cliente), h.metodo, `${h.host ?? h.servidor}${h.caminho}`, h.status ? String(h.status) : "") });
    }
    for (const s of r.tls) {
      e.push({ ts: s.ts_us, tipo: "TLS", texto: t.linha.tls(rotulo(s.cliente), s.sni ?? s.servidor, s.versao ?? "") });
    }
    for (const d of r.dhcp) {
      e.push({ ts: d.ts_us, tipo: "DHCP", texto: t.linha.dhcp(d.nome_host ?? d.mac, d.tipo, d.ip ?? "") });
    }
    return e.sort((a, b) => a.ts - b.ts);
  }, [r, t, nomes]);

  return (
    <Tabela
      linhas={eventos}
      total={eventos.length}
      busca={(e) => `${e.tipo} ${e.texto}`}
      colunas={[
        { titulo: t.col.hora, render: (e) => <span className="mono">{hora(e.ts)}</span> },
        { titulo: t.col.tipo, render: (e) => <span className={`selo ${e.destaque ? "suspeita" : ""}`}>{e.tipo}</span> },
        { titulo: t.col.evento, render: (e) => e.texto },
      ]}
    />
  );
}

export function Fluxos({ r, nomes }: Contexto) {
  const { t, idioma } = useTextos();
  return (
    <Tabela<Fluxo>
      linhas={r.fluxos}
      total={r.total_fluxos}
      busca={(f) => `${f.protocolo} ${f.origem}:${f.porta_origem} ${f.destino}:${f.porta_destino} ${f.aplicacao ?? ""} ${nomes.get(f.destino) ?? ""} ${t.estados[f.estado]}`}
      colunas={[
        { titulo: t.col.inicio, render: (f) => <span className="mono">{hora(f.inicio_us)}</span> },
        { titulo: t.col.protocolo, render: (f) => f.protocolo },
        { titulo: t.col.origem, render: (f) => <span className="mono">{ponta(f.origem, f.porta_origem)}</span> },
        { titulo: t.col.destino, render: (f) => (
          <span className="mono" title={nomes.get(f.destino)}>
            {ponta(f.destino, f.porta_destino)}
            {nomes.get(f.destino) && <span className="fraco"> · {nomes.get(f.destino)}</span>}
          </span>
        ) },
        { titulo: t.col.aplicacao, render: (f) => f.aplicacao && (
          <span className={f.aplicacao_por_porta ? "fraco" : ""} title={f.aplicacao_por_porta ? t.porPorta : undefined}>
            {f.aplicacao}{f.aplicacao_por_porta && "?"}
          </span>
        ) },
        { titulo: t.col.estado, render: (f) => (
          <span className={`selo ${f.estado === "recusada" || f.estado === "sem_resposta" ? "andamento" : ""}`}>{t.estados[f.estado]}</span>
        ) },
        { titulo: t.col.pacotes, numerica: true, render: (f) => numero(f.pacotes_ida + f.pacotes_volta, idioma) },
        { titulo: t.col.bytes, numerica: true, render: (f) => tamanho(f.bytes_ida + f.bytes_volta) },
        { titulo: t.col.duracao, numerica: true, render: (f) => duracao(f.fim_us - f.inicio_us) },
      ]}
    />
  );
}

export function Hosts({ r }: Contexto) {
  const { t, idioma } = useTextos();
  return (
    <Tabela<Host>
      linhas={r.hosts}
      total={r.total_hosts}
      busca={(h) => `${h.ip} ${h.nomes.join(" ")} ${h.mac ?? ""} ${t.escopos[h.escopo]}`}
      colunas={[
        { titulo: t.col.ip, render: (h) => <span className="mono">{h.ip}</span> },
        { titulo: t.col.escopo, render: (h) => <span className="selo">{t.escopos[h.escopo]}</span> },
        { titulo: t.col.nomes, render: (h) => h.nomes.join(", ") },
        { titulo: t.col.mac, render: (h) => <span className="mono">{h.mac}</span> },
        { titulo: t.col.enviados, numerica: true, render: (h) => tamanho(h.bytes_enviados) },
        { titulo: t.col.recebidos, numerica: true, render: (h) => tamanho(h.bytes_recebidos) },
        { titulo: t.col.conexoes, numerica: true, render: (h) => numero(h.fluxos_iniciados, idioma) },
      ]}
    />
  );
}

export function Dns({ r }: Contexto) {
  const { t } = useTextos();
  return (
    <Tabela
      linhas={r.dns}
      total={r.total_dns}
      busca={(d) => `${d.cliente} ${d.consulta} ${d.tipo} ${d.respostas.join(" ")} ${d.rcode !== null ? RCODES[d.rcode] ?? "" : ""}`}
      colunas={[
        { titulo: t.col.hora, render: (d) => <span className="mono">{hora(d.ts_us)}</span> },
        { titulo: t.col.cliente, render: (d) => <span className="mono">{d.cliente}</span> },
        { titulo: t.col.consulta, render: (d) => <span className="mono">{d.consulta}</span> },
        { titulo: t.col.tipo, render: (d) => d.tipo },
        { titulo: t.col.resposta, render: (d) => d.rcode === null
          ? <span className="fraco">{t.semResposta}</span>
          : d.rcode !== 0
            ? <span className="selo suspeita">{RCODES[d.rcode] ?? d.rcode}</span>
            : <span className="mono">{d.respostas.join(", ")}</span> },
      ]}
    />
  );
}

export function Tls({ r, nomes }: Contexto) {
  const { t } = useTextos();
  return (
    <Tabela
      linhas={r.tls}
      total={r.total_tls}
      busca={(s) => `${s.cliente} ${s.servidor} ${s.sni ?? ""} ${s.versao ?? ""} ${s.alpn.join(" ")}`}
      colunas={[
        { titulo: t.col.hora, render: (s) => <span className="mono">{hora(s.ts_us)}</span> },
        { titulo: t.col.cliente, render: (s) => <span className="mono">{s.cliente}</span> },
        { titulo: t.col.servidor, render: (s) => <Ip ip={ponta(s.servidor, s.porta)} nomes={nomes} /> },
        { titulo: t.col.sni, render: (s) => <span className="mono">{s.sni}</span> },
        { titulo: t.col.versao, render: (s) => s.versao ?? <span className="fraco">{s.versao_oferecida}</span> },
        { titulo: t.col.alpn, render: (s) => s.alpn.join(", ") },
      ]}
    />
  );
}

export function Http({ r }: Contexto) {
  const { t } = useTextos();
  return (
    <Tabela
      linhas={r.http}
      total={r.total_http}
      busca={(h) => `${h.cliente} ${h.servidor} ${h.metodo} ${h.host ?? ""}${h.caminho} ${h.status ?? ""} ${h.tipo_conteudo ?? ""} ${h.user_agent ?? ""}`}
      colunas={[
        { titulo: t.col.hora, render: (h) => <span className="mono">{hora(h.ts_us)}</span> },
        { titulo: t.col.cliente, render: (h) => <span className="mono">{h.cliente}</span> },
        { titulo: t.col.metodo, render: (h) => h.metodo },
        { titulo: t.col.url, render: (h) => (
          <span className="mono quebra">
            {h.host ?? h.servidor}{h.caminho}
            {h.autorizacao && <span className="selo suspeita"><KeyRound size={12} /> {t.credencial(h.autorizacao)}</span>}
          </span>
        ) },
        { titulo: t.col.status, render: (h) => h.status ?? "" },
        { titulo: t.col.conteudo, render: (h) => h.tipo_conteudo && `${h.tipo_conteudo}${h.tamanho !== null ? ` · ${tamanho(h.tamanho)}` : ""}` },
        { titulo: t.col.userAgent, render: (h) => <span className="fraco quebra">{h.user_agent}</span> },
      ]}
    />
  );
}
