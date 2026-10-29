import { useEffect, useRef, useState } from "react";
import { ChevronDown, ChevronRight, Filter, X } from "lucide-react";
import { useTextos } from "./idiomas";
import { numero, tamanho } from "./formatos";
import type { FiltroPacotes, MensagemPacotes, Pacote, Relatorio, ResultadoPacotes } from "./tipos";

const POR_PAGINA = 1000;
const PROTOCOLOS = ["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "TLS", "DHCP"];

/** Linhas de 16 bytes: deslocamento, hexadecimal e ASCII. */
function linhasHex(hex: string): string[] {
  const bytes = hex.match(/../g)?.map((h) => parseInt(h, 16)) ?? [];
  const linhas: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const fatia = bytes.slice(i, i + 16);
    const h = fatia.map((b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(47, " ");
    const a = fatia.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
    linhas.push(`${i.toString(16).padStart(4, "0")}  ${h}  ${a}`);
  }
  return linhas;
}

export function Pacotes({ r, arquivo, filtroInicial, limparFiltro }: {
  r: Relatorio;
  arquivo: File;
  filtroInicial: Partial<FiltroPacotes> | null;
  limparFiltro: () => void;
}) {
  const { t, idioma } = useTextos();
  const tp = t.pacotes;
  const [ip, setIp] = useState("");
  const [porta, setPorta] = useState("");
  const [texto, setTexto] = useState("");
  const [protocolo, setProtocolo] = useState("");
  const [filtro, setFiltro] = useState<FiltroPacotes>({ ips: [], portas: [], pular: 0, limite: POR_PAGINA, ...filtroInicial });
  const [resultado, setResultado] = useState<ResultadoPacotes | null>(null);
  const [lidos, setLidos] = useState(0);
  const [escolhido, setEscolhido] = useState<Pacote | null>(null);
  const worker = useRef<Worker | null>(null);

  useEffect(() => {
    setFiltro({ ips: [], portas: [], pular: 0, limite: POR_PAGINA, ...filtroInicial });
  }, [filtroInicial]);

  useEffect(() => {
    worker.current?.terminate();
    setResultado(null);
    setEscolhido(null);
    setLidos(0);
    const w = new Worker(new URL("./pacotes.worker.ts", import.meta.url), { type: "module" });
    worker.current = w;
    w.onmessage = (e: MessageEvent<MensagemPacotes>) => {
      const m = e.data;
      if (m.tipo === "progresso") setLidos(m.lidos);
      else if (m.tipo === "concluido") {
        w.terminate();
        setResultado(m.resultado);
      } else {
        w.terminate();
        setResultado({ pacotes: [], encontrados: 0, tem_mais: false, erro: null });
      }
    };
    w.postMessage({ arquivo, filtro });
    return () => w.terminate();
  }, [arquivo, filtro]);

  function aplicar() {
    limparFiltro();
    setFiltro({
      ips: ip.trim() ? [ip.trim()] : [],
      portas: porta.trim() && /^\d+$/.test(porta.trim()) ? [Number(porta.trim())] : [],
      protocolo: protocolo || undefined,
      texto: texto.trim() || undefined,
      pular: 0,
      limite: POR_PAGINA,
    });
  }

  const inicio = r.captura.inicio_us;
  const partes = filtro.ips.length === 2
    ? [tp.filtroFluxo(`${filtro.ips[0]}:${filtro.portas[0] ?? ""}`, `${filtro.ips[1]}:${filtro.portas[1] ?? ""}`)]
    : [filtro.ips[0], filtro.portas[0] && `${tp.porta} ${filtro.portas[0]}`];
  const descricaoFiltro = [...partes, filtro.protocolo, filtro.texto && `"${filtro.texto}"`].filter(Boolean).join(" · ") || null;

  return (
    <>
      <div className="barra-tabela">
        <input placeholder={tp.buscar} value={texto} onChange={(e) => setTexto(e.target.value)} onKeyDown={(e) => e.key === "Enter" && aplicar()} style={{ maxWidth: 280 }} />
        <select value={protocolo} onChange={(e) => setProtocolo(e.target.value)} aria-label={t.col.protocolo}>
          <option value="">{tp.todosProtocolos}</option>
          {PROTOCOLOS.map((p) => <option key={p} value={p}>{p}</option>)}
        </select>
        <input placeholder={tp.ip} value={ip} onChange={(e) => setIp(e.target.value)} onKeyDown={(e) => e.key === "Enter" && aplicar()} style={{ maxWidth: 220 }} />
        <input placeholder={tp.porta} value={porta} onChange={(e) => setPorta(e.target.value)} onKeyDown={(e) => e.key === "Enter" && aplicar()} style={{ maxWidth: 110, minWidth: 90 }} />
        <button onClick={aplicar}><Filter size={14} /> {tp.filtrar}</button>
        {descricaoFiltro && (
          <span className="selo suspeita">
            {descricaoFiltro}
            <button className="link" onClick={() => { limparFiltro(); setIp(""); setPorta(""); setTexto(""); setProtocolo(""); setFiltro({ ips: [], portas: [], pular: 0, limite: POR_PAGINA }); }}>
              <X size={12} />
            </button>
          </span>
        )}
        {resultado && (
          <span className="fraco">
            {tp.mostrando(numero(filtro.pular + 1, idioma), numero(filtro.pular + resultado.pacotes.length, idioma), resultado.tem_mais)}
          </span>
        )}
      </div>

      {!resultado && (
        <div className="leitura">
          <span className="suave">{tp.lendo} · {tamanho(lidos)} / {tamanho(arquivo.size)}</span>
          <div className="progresso"><span style={{ width: `${(lidos / Math.max(1, arquivo.size)) * 100}%` }} /></div>
        </div>
      )}

      {resultado && resultado.pacotes.length === 0 && <div className="vazio">{tp.nenhum}</div>}

      {resultado && resultado.pacotes.length > 0 && (
        <div className="pacotes">
          <div className="bloco rolagem lista-pacotes">
            <table>
              <thead>
                <tr>
                  <th className="num">{tp.col.numero}</th><th className="num">{tp.col.tempo}</th><th>{t.col.origem}</th>
                  <th>{t.col.destino}</th><th>{t.col.protocolo}</th><th className="num">{tp.col.tamanho}</th><th>{tp.col.info}</th>
                </tr>
              </thead>
              <tbody>
                {resultado.pacotes.map((p) => (
                  <tr key={p.numero} className={`clicavel ${escolhido?.numero === p.numero ? "escolhido" : ""}`} onClick={() => setEscolhido(p)}>
                    <td className="num mono">{p.numero}</td>
                    <td className="num mono">{((p.ts_us - inicio) / 1e6).toFixed(6)}</td>
                    <td className="mono">{p.origem}</td>
                    <td className="mono">{p.destino}</td>
                    <td><span className="selo">{p.protocolo}</span></td>
                    <td className="num">{p.tamanho}</td>
                    <td className="mono info-pacote">{p.info}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="acoes-linha">
              {filtro.pular > 0 && (
                <button onClick={() => setFiltro({ ...filtro, pular: Math.max(0, filtro.pular - POR_PAGINA) })}>{tp.anteriores}</button>
              )}
              {resultado.tem_mais && (
                <button onClick={() => setFiltro({ ...filtro, pular: filtro.pular + POR_PAGINA })}>{tp.proximos}</button>
              )}
            </div>
          </div>

          <div className="bloco detalhe-pacote">
            {!escolhido && <div className="vazio">{tp.escolha}</div>}
            {escolhido && (
              <>
                <h3>{tp.titulo(escolhido.numero, escolhido.tamanho, escolhido.capturado)}</h3>
                {escolhido.camadas.map((c, i) => <CamadaVisivel key={i} nome={c.nome} campos={c.campos} />)}
                <h3>{tp.bytes}</h3>
                <pre className="codigo hex">{linhasHex(escolhido.bytes).join("\n")}</pre>
                {escolhido.capturado * 2 > escolhido.bytes.length && <div className="fraco">{tp.bytesCortados}</div>}
                <div className="fraco">{tp.aviso}</div>
              </>
            )}
          </div>
        </div>
      )}
    </>
  );
}

function CamadaVisivel({ nome, campos }: { nome: string; campos: { nome: string; valor: string }[] }) {
  const [aberta, setAberta] = useState(true);
  return (
    <div className="camada">
      <button className="link camada-titulo" onClick={() => setAberta(!aberta)}>
        {aberta ? <ChevronDown size={14} /> : <ChevronRight size={14} />} {nome}
      </button>
      {aberta && (
        <table>
          <tbody>
            {campos.map((c, i) => (
              <tr key={i}><td className="fraco campo-nome">{c.nome}</td><td className="mono">{c.valor}</td></tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
