// Aba Mapa: de onde são os IPs externos da captura, por país e por ASN. A
// consulta é local; a base vai junto com o site ou é carregada pela pessoa.

import { useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, FileUp, List as ListIcon, X } from "lucide-react";
import { useTextos, type Idioma } from "./idiomas";
import { TEXTOS_INTELIGENCIA } from "./textos-inteligencia";
import { numero, tamanho } from "./formatos";
import { basesEmbutidas, carregarPropria, localizar, proprias, type Base, type Local } from "./geo";
import desenho from "./mapa-paises.json";
import type { Contexto } from "./paginas";
import type { Host, Relatorio } from "./tipos";

const MOSTRAR_ASN = 50;
const MOSTRAR_IPS = 200;
/** Acima disso a tela alerta. Valor de bom senso, não medido. */
const DEFASAGEM_DIAS = 90;
/** Antes disso o relógio de quem capturou estava errado ou zerado. */
const DATA_MINIMA_US = Date.UTC(1995, 0, 1) * 1000;

interface LinhaIp {
  host: Host;
  local: Local;
  alertas: number;
  bytes: number;
}

interface Agregado {
  chave: string;
  nome: string;
  ips: LinhaIp[];
  enviados: number;
  recebidos: number;
  alertas: number;
}

function nomePais(codigo: string, idioma: Idioma): string {
  try {
    return new Intl.DisplayNames([idioma], { type: "region" }).of(codigo) ?? codigo;
  } catch {
    return codigo;
  }
}

function agregar(linhas: LinhaIp[], chave: (l: LinhaIp) => string | null, nome: (k: string, l: LinhaIp) => string): Agregado[] {
  const m = new Map<string, Agregado>();
  for (const l of linhas) {
    const k = chave(l);
    if (!k) continue;
    let a = m.get(k);
    if (!a) {
      a = { chave: k, nome: nome(k, l), ips: [], enviados: 0, recebidos: 0, alertas: 0 };
      m.set(k, a);
    }
    a.ips.push(l);
    // Do ponto de vista da rede analisada: o que o IP externo recebeu foi
    // enviado para ele.
    a.enviados += l.host.bytes_recebidos;
    a.recebidos += l.host.bytes_enviados;
    a.alertas += l.alertas;
  }
  return [...m.values()].sort((x, y) => y.enviados + y.recebidos - x.enviados - x.recebidos);
}

function analisar(r: Relatorio, bases: Base[], idioma: Idioma) {
  const alertasPorIp = new Map<string, number>();
  for (const a of r.alertas) {
    for (const ip of new Set([a.host, a.alvo_ip])) {
      if (ip) alertasPorIp.set(ip, (alertasPorIp.get(ip) ?? 0) + 1);
    }
  }
  const externos = r.hosts.filter((h) => h.escopo === "externo");
  const linhas: LinhaIp[] = externos.map((host) => ({
    host,
    local: localizar(host.ip, bases),
    alertas: alertasPorIp.get(host.ip) ?? 0,
    bytes: host.bytes_enviados + host.bytes_recebidos,
  }));
  const paises = agregar(linhas, (l) => l.local.pais ?? null, (k) => nomePais(k, idioma));
  const asns = agregar(
    linhas,
    (l) => (l.local.asn ? String(l.local.asn) : null),
    (k, l) => l.local.organizacao ?? `AS${k}`,
  );
  const cidades = linhas.filter((l) => l.local.lat !== undefined && l.local.lon !== undefined);
  return {
    linhas,
    paises,
    asns,
    cidades,
    semLocal: linhas.filter((l) => !l.local.pais).length,
    semGeografia: r.hosts.length - externos.length,
  };
}

/** Mesma projeção de scripts/gerar_mapa.py. */
function projetar(lon: number, lat: number): [number, number] {
  const l = (lon * Math.PI) / 180;
  const p = (lat * Math.PI) / 180;
  const p2 = p * p;
  const p4 = p2 * p2;
  const x = l * (0.8707 - 0.131979 * p2 + p4 * (-0.013791 + p4 * (0.003971 * p2 - 0.001529 * p4)));
  const y = p * (1.007226 + p2 * (0.015085 + p4 * (-0.044475 + 0.028874 * p2 - 0.005916 * p4)));
  return [desenho.largura / 2 + x * desenho.escala, (desenho.yNorte - y) * desenho.escala];
}

export function Mapa({ r, nomes, verPacotes }: Contexto) {
  const { t, idioma } = useTextos();
  const ti = TEXTOS_INTELIGENCIA[idioma];
  const tm = ti.mapa;
  const [embutidas, setEmbutidas] = useState<Base[] | null>(null);
  const [falhaBase, setFalhaBase] = useState(false);
  const [versao, setVersao] = useState(0);
  const [lendoPropria, setLendoPropria] = useState(false);
  const [falhaPropria, setFalhaPropria] = useState(false);
  const [selecionado, setSelecionado] = useState<string | null>(null);
  const seletor = useRef<HTMLInputElement>(null);

  useEffect(() => {
    let vivo = true;
    basesEmbutidas()
      .then((b) => { if (vivo) setEmbutidas(b); })
      .catch(() => { if (vivo) setFalhaBase(true); });
    return () => { vivo = false; };
  }, []);

  const bases = useMemo(() => [...proprias.map((p) => p.base), ...(embutidas ?? [])], [embutidas, versao]);
  const dados = useMemo(() => (bases.length ? analisar(r, bases, idioma) : null), [r, bases, idioma]);

  async function escolher(arquivo: File) {
    setLendoPropria(true);
    setFalhaPropria(false);
    try {
      await carregarPropria(arquivo);
      setVersao((v) => v + 1);
    } catch {
      setFalhaPropria(true);
    }
    setLendoPropria(false);
  }

  const pais = dados?.paises.find((p) => p.chave === selecionado) ?? null;
  const maior = Math.max(1, ...(dados?.paises.map((p) => p.enviados + p.recebidos) ?? []));
  const intensidade = (a: Agregado) => 25 + 75 * (Math.log(1 + a.enviados + a.recebidos) / Math.log(1 + maior));
  const porCodigo = new Map(dados?.paises.map((p) => [p.chave, p]));
  const dataBase = (b: Base) => (b.gerada ? new Date(b.gerada * 1000).toISOString().slice(0, 7) : "");
  const rotuloIp = (ip: string) => (nomes.get(ip) ? `${ip} (${nomes.get(ip)})` : ip);
  const inicioUs = r.captura.inicio_us;
  const capturaDatada = inicioUs >= DATA_MINIMA_US;
  const defasagemDias = capturaDatada
    ? Math.max(0, ...bases.filter((b) => b.gerada).map((b) => Math.abs(inicioUs / 1e6 - b.gerada) / 86400))
    : 0;
  const dica = (p: Agregado) => `${p.nome}: ${tm.resumoIps(p.ips.length, numero(p.ips.length, idioma))} · ${tm.enviado} ${tamanho(p.enviados)} · ${tm.recebido} ${tamanho(p.recebidos)}`;

  return (
    <>
      <div className="bloco aviso-mapa">
        <AlertTriangle size={15} />
        <span className="suave">{tm.limite}</span>
      </div>

      {falhaBase && bases.length === 0 && <div className="aviso-erro"><AlertTriangle size={15} /> {tm.semBase}</div>}
      {!falhaBase && bases.length === 0 && <div className="bloco suave">{tm.carregando}</div>}

      {dados && (
        <>
          <div className="cartoes">
            <div className="cartao"><div className="rotulo">{tm.paises}</div><div className="valor">{numero(dados.paises.length, idioma)}</div></div>
            <div className="cartao"><div className="rotulo">{tm.organizacoes}</div><div className="valor">{numero(dados.asns.length, idioma)}</div></div>
            <div className="cartao"><div className="rotulo">{tm.ipsExternos}</div><div className="valor">{numero(dados.linhas.length, idioma)}</div></div>
            <div className="cartao"><div className="rotulo">{tm.semLocal}</div><div className="valor">{numero(dados.semLocal, idioma)}</div></div>
            <div className="cartao"><div className="rotulo">{tm.semGeografia}</div><div className="valor">{numero(dados.semGeografia, idioma)}</div></div>
          </div>

          {dados.linhas.length > 0 && !capturaDatada && <div className="suave mapa-datas">{tm.capturaSemData}</div>}
          {dados.linhas.length > 0 && capturaDatada && (
            <div className="suave mapa-datas">
              {tm.datas(new Date(inicioUs / 1000).toISOString().slice(0, 7), bases.map((b) => `${b.tipo} ${dataBase(b)}`).join(", "))}
            </div>
          )}
          {dados.linhas.length > 0 && defasagemDias > DEFASAGEM_DIAS && (
            <div className="bloco aviso-mapa defasagem">
              <AlertTriangle size={15} />
              <span>{tm.defasagem(Math.round(defasagemDias / 30.44))}</span>
            </div>
          )}

          {dados.linhas.length === 0 && (
            <div className="bloco destaque-rosa">
              <h2>{tm.nenhumExterno}</h2>
              <div className="suave">{tm.nenhumExternoPorque}</div>
            </div>
          )}

          {dados.linhas.length === 0 && r.hosts.length > 0 && (
            <div className="bloco">
              <h2>{tm.enderecos} <span className="fraco">{numero(r.hosts.length, idioma)}</span></h2>
              <div className="rolagem">
                <table>
                  <thead>
                    <tr><th>{t.col.ip}</th><th>{tm.escopo}</th><th /></tr>
                  </thead>
                  <tbody>
                    {r.hosts.slice(0, MOSTRAR_IPS).map((h) => (
                      <tr key={h.ip}>
                        <td className="mono quebra">{rotuloIp(h.ip)}</td>
                        <td><span className="selo">{t.escopos[h.escopo]}</span></td>
                        <td><button className="link" onClick={() => verPacotes({ ips: [h.ip], portas: [] })}>{t.pacotes.ver}</button></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {dados.linhas.length > 0 && (
          <div className="bloco mapa-bloco">
            <svg className="mapa-mundi" viewBox={`0 0 ${desenho.largura} ${desenho.altura}`} role="img" aria-label={tm.titulo}>
              {desenho.paises.map(({ c, d }) => {
                const p = porCodigo.get(c);
                return (
                  <path
                    key={c}
                    d={d}
                    className={`mapa-pais ${p ? "com-trafego" : ""} ${p?.alertas ? "com-alerta" : ""} ${selecionado === c ? "selecionado" : ""}`}
                    style={p ? { fill: `color-mix(in srgb, var(--rosa) ${intensidade(p)}%, var(--painel-2))` } : undefined}
                    onClick={p ? () => setSelecionado(selecionado === c ? null : c) : undefined}
                  >
                    {p && <title>{dica(p)}</title>}
                  </path>
                );
              })}
              {desenho.pontos.filter(({ c }) => porCodigo.has(c)).map(({ c, x, y }) => {
                const p = porCodigo.get(c)!;
                return (
                  <g key={c} className="mapa-ponto" onClick={() => setSelecionado(selecionado === c ? null : c)}>
                    {/* Área de clique maior que a marca. */}
                    <circle cx={x} cy={y} r={10} fill="transparent" />
                    <circle
                      cx={x}
                      cy={y}
                      r={4}
                      className={`mapa-pais com-trafego ${p.alertas ? "com-alerta" : ""} ${selecionado === c ? "selecionado" : ""}`}
                      style={{ fill: `color-mix(in srgb, var(--rosa) ${intensidade(p)}%, var(--painel-2))` }}
                    />
                    <title>{dica(p)}</title>
                  </g>
                );
              })}
              {dados.cidades.map((l) => {
                const [x, y] = projetar(l.local.lon!, l.local.lat!);
                return (
                  <circle key={l.host.ip} cx={x} cy={y} r={2.5} className={`mapa-cidade ${l.alertas ? "com-alerta" : ""}`}>
                    <title>{`${l.host.ip} · ${[l.local.cidade, l.local.pais].filter(Boolean).join(", ")}`}</title>
                  </circle>
                );
              })}
            </svg>
            <div className="legenda">
              <span><span className="mapa-escala" /> {tm.legendaVolume}</span>
              <span><span className="mapa-chave-alerta" /> {tm.legendaAlerta}</span>
              {dados.cidades.length > 0 && <span><span className="mapa-chave-cidade" /> {tm.legendaCidade}</span>}
            </div>
          </div>
          )}

          {pais && (
            <div className="bloco">
              <div className="mapa-detalhe-topo">
                <h2>{pais.nome} <span className="fraco">{numero(pais.ips.length, idioma)}</span></h2>
                <button onClick={() => verPacotes({ ips: pais.ips.slice(0, 50).map((l) => l.host.ip), portas: [] })}>
                  <ListIcon size={15} /> {t.pacotes.ver}
                </button>
                <button aria-label={tm.fechar} title={tm.fechar} onClick={() => setSelecionado(null)}><X size={15} /></button>
              </div>
              <div className="rolagem">
                <table>
                  <thead>
                    <tr>
                      <th>{t.col.ip}</th><th>{tm.cidade}</th><th>{tm.organizacao}</th>
                      <th className="num">{tm.enviado}</th><th className="num">{tm.recebido}</th><th className="num">{tm.alertas}</th><th />
                    </tr>
                  </thead>
                  <tbody>
                    {[...pais.ips].sort((a, b) => b.bytes - a.bytes).slice(0, MOSTRAR_IPS).map((l) => (
                      <tr key={l.host.ip}>
                        <td className="mono quebra">{rotuloIp(l.host.ip)}</td>
                        <td>{l.local.cidade ?? ""}</td>
                        <td>{l.local.asn ? `AS${l.local.asn} ${l.local.organizacao ?? ""}` : ""}</td>
                        <td className="num">{tamanho(l.host.bytes_recebidos)}</td>
                        <td className="num">{tamanho(l.host.bytes_enviados)}</td>
                        <td className="num">{l.alertas ? <span className="selo suspeita">{numero(l.alertas, idioma)}</span> : ""}</td>
                        <td><button className="link" onClick={() => verPacotes({ ips: [l.host.ip], portas: [] })}>{t.pacotes.ver}</button></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {pais.ips.length > MOSTRAR_IPS && <div className="fraco">{tm.mostrandoPrimeiros(numero(MOSTRAR_IPS, idioma))}</div>}
            </div>
          )}

          <TabelaAgregada
            titulo={tm.paises}
            linhas={dados.paises}
            aoClicar={(a) => setSelecionado(a.chave)}
            selecionado={selecionado}
            idioma={idioma}
            rotulos={tm}
          />
          <TabelaAgregada
            titulo={tm.organizacoes}
            linhas={dados.asns.slice(0, MOSTRAR_ASN)}
            prefixo="AS"
            idioma={idioma}
            rotulos={tm}
          />
        </>
      )}

      <div className="bloco mapa-base">
        <h2>{tm.baseTitulo}</h2>
        <ul className="lista">
          {embutidas?.map((b) => <li key={b.tipo} className="mono">{b.tipo} · {dataBase(b)}</li>)}
          {proprias.map((p) => <li key={p.base.tipo} className="mono">{p.nome} · {p.base.tipo} · {dataBase(p.base)}</li>)}
        </ul>
        <div className="suave">{tm.baseExplicacao}</div>
        {falhaPropria && <div className="aviso-erro"><AlertTriangle size={15} /> {tm.basePropriaFalha}</div>}
        <div className="acoes-linha">
          <button disabled={lendoPropria} onClick={() => seletor.current?.click()}>
            <FileUp size={15} /> {lendoPropria ? tm.lendoBase : tm.carregarBase}
          </button>
          <input
            ref={seletor}
            type="file"
            accept=".mmdb,.gz"
            hidden
            onChange={(e) => {
              const f = e.target.files?.[0];
              e.target.value = "";
              if (f) void escolher(f);
            }}
          />
        </div>
        {/* Crédito exigido pela licença da base embutida. */}
        <div className="fraco mapa-credito">
          <a href="https://db-ip.com" target="_blank" rel="noreferrer noopener">IP Geolocation by DB-IP</a>
          {" · "}{tm.creditoMapa}
        </div>
      </div>
    </>
  );
}

function TabelaAgregada({ titulo, linhas, aoClicar, selecionado, prefixo, idioma, rotulos: tm }: {
  titulo: string;
  linhas: Agregado[];
  aoClicar?: (a: Agregado) => void;
  selecionado?: string | null;
  prefixo?: string;
  idioma: Idioma;
  rotulos: (typeof TEXTOS_INTELIGENCIA)["pt"]["mapa"];
}) {
  if (linhas.length === 0) return null;
  return (
    <div className="bloco">
      <h2>{titulo}</h2>
      <div className="rolagem">
        <table>
          <thead>
            <tr>
              <th>{titulo}</th><th className="num">{tm.ips}</th><th className="num">{tm.enviado}</th><th className="num">{tm.recebido}</th><th className="num">{tm.alertas}</th>
            </tr>
          </thead>
          <tbody>
            {linhas.map((a) => (
              <tr key={a.chave} className={selecionado === a.chave ? "linha-selecionada" : ""}>
                <td>
                  {aoClicar ? <button className="link" onClick={() => aoClicar(a)}>{a.nome}</button> : a.nome}
                  {prefixo && <span className="fraco mono"> {prefixo}{a.chave}</span>}
                </td>
                <td className="num">{numero(a.ips.length, idioma)}</td>
                <td className="num">{tamanho(a.enviados)}</td>
                <td className="num">{tamanho(a.recebidos)}</td>
                <td className="num">{a.alertas ? <span className="selo suspeita">{numero(a.alertas, idioma)}</span> : ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
