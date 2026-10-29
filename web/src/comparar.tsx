import { useMemo, useRef, useState, type DragEvent } from "react";
import { AlertTriangle, FileUp, X } from "lucide-react";
import { useTextos } from "./idiomas";
import { TEXTOS_INTELIGENCIA } from "./textos-inteligencia";
import { numero, tamanho } from "./formatos";
import { comparar, type Novidade } from "./diferencas";
import type { Contexto } from "./paginas";
import type { MensagemLeitura, Relatorio } from "./tipos";

const MOSTRAR = 30;

type Referencia =
  | { fase: "inicio" }
  | { fase: "lendo"; arquivo: File; lidos: number }
  | { fase: "pronto"; arquivo: File; r: Relatorio }
  | { fase: "falha"; arquivo: File };

// A referência sobrevive à troca de página enquanto o incidente for o mesmo.
let guardada: { incidente: Relatorio; ref: Referencia } | null = null;

export function Comparar({ r, nomes, verPacotes }: Contexto) {
  const { t, idioma } = useTextos();
  const tc = TEXTOS_INTELIGENCIA[idioma].comparar;
  const ti = TEXTOS_INTELIGENCIA[idioma];
  const [ref, setRefEstado] = useState<Referencia>(guardada?.incidente === r ? guardada.ref : { fase: "inicio" });
  const [arrastando, setArrastando] = useState(false);
  const seletor = useRef<HTMLInputElement>(null);
  const worker = useRef<Worker | null>(null);

  function setRef(x: Referencia) {
    guardada = { incidente: r, ref: x };
    setRefEstado(x);
  }

  function encerrar() {
    worker.current?.terminate();
    worker.current = null;
  }

  function abrir(arquivo: File) {
    encerrar();
    setRef({ fase: "lendo", arquivo, lidos: 0 });
    const w = new Worker(new URL("./leitura.worker.ts", import.meta.url), { type: "module" });
    worker.current = w;
    w.onmessage = (e: MessageEvent<MensagemLeitura>) => {
      const m = e.data;
      if (m.tipo === "progresso") {
        setRef({ fase: "lendo", arquivo, lidos: m.lidos });
      } else {
        encerrar();
        if (m.tipo === "concluido" && m.relatorio.captura.pacotes > 0) setRef({ fase: "pronto", arquivo, r: m.relatorio });
        else setRef({ fase: "falha", arquivo });
      }
    };
    w.postMessage({ arquivo });
  }

  function soltar(e: DragEvent) {
    e.preventDefault();
    setArrastando(false);
    const f = e.dataTransfer.files[0];
    if (f) abrir(f);
  }

  const d = useMemo(() => (ref.fase === "pronto" ? comparar(r, ref.r) : null), [r, ref]);
  const rotulo = (ip: string) => (nomes.get(ip) ? `${ip} (${nomes.get(ip)})` : ip);

  const zona = (
    <div
      className={`zona ${arrastando ? "ativa" : ""}`}
      onClick={() => seletor.current?.click()}
      onDragOver={(e) => { e.preventDefault(); setArrastando(true); }}
      onDragLeave={() => setArrastando(false)}
      onDrop={soltar}
    >
      <FileUp size={30} />
      <p>{tc.arraste}</p>
      <input
        ref={seletor}
        type="file"
        accept=".pcap,.pcapng,.cap"
        hidden
        onChange={(e) => {
          const f = e.target.files?.[0];
          e.target.value = "";
          if (f) abrir(f);
        }}
      />
    </div>
  );

  return (
    <>
      <div className="bloco">
        <h2>{tc.titulo}</h2>
        <div className="suave">{tc.explicacao}</div>
      </div>

      {(ref.fase === "inicio" || ref.fase === "falha") && (
        <>
          {ref.fase === "falha" && <div className="aviso-erro"><AlertTriangle size={15} /> {tc.falha}</div>}
          {zona}
        </>
      )}

      {ref.fase === "lendo" && (
        <div className="bloco leitura">
          <h2>{tc.lendo}</h2>
          <div className="progresso">
            <span style={{ width: `${(ref.lidos / Math.max(1, ref.arquivo.size)) * 100}%` }} />
          </div>
          <div className="leitura-rodape">
            <span className="suave">{tamanho(ref.lidos)} / {tamanho(ref.arquivo.size)}</span>
            <button onClick={() => { encerrar(); setRef({ fase: "inicio" }); }}><X size={15} /> {t.cancelar}</button>
          </div>
        </div>
      )}

      {ref.fase === "pronto" && d && (
        <>
          <div className="barra-tabela">
            <span className="mono suave">{tc.referencia(ref.arquivo.name, tamanho(ref.arquivo.size))}</span>
            <button onClick={() => seletor.current?.click()}><FileUp size={15} /> {tc.trocar}</button>
            <input
              ref={seletor}
              type="file"
              accept=".pcap,.pcapng,.cap"
              hidden
              onChange={(e) => {
                const f = e.target.files?.[0];
                e.target.value = "";
                if (f) abrir(f);
              }}
            />
          </div>

          <div className="cartoes">
            <div className="cartao">
              <div className="rotulo">{tc.novidades}</div>
              <div className={`valor ${d.total ? "destaque" : ""}`}>{numero(d.total, idioma)}</div>
            </div>
            {d.categorias.map((c) => (
              <div key={c.chave} className="cartao">
                <div className="rotulo">{tc.categorias[c.chave]}</div>
                <div className="valor">{numero(c.itens.length, idioma)}</div>
              </div>
            ))}
          </div>

          {d.truncado && <div className="bloco aviso">{tc.truncado}</div>}
          {d.total === 0 && <div className="bloco suave">{tc.nada}</div>}

          {d.alertas.length > 0 && (
            <div className="bloco">
              <h2>{tc.categorias.alertas} <span className="fraco">{d.alertas.length}</span></h2>
              <ul className="lista">
                {d.alertas.map((a) => (
                  <li key={a.id}>
                    {ti.regras[a.regra]?.titulo({ h: rotulo(a.host), alvo: a.alvo ?? "", p: a.parametros }) ?? a.regra}
                    {" "}<span className="fraco">{rotulo(a.host)}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {d.categorias.filter((c) => c.itens.length).map((c) => (
            <div key={c.chave} className="bloco">
              <h2>{tc.categorias[c.chave]} <span className="fraco">{c.itens.length}</span></h2>
              <ListaNovidades itens={c.itens} mono={c.chave !== "userAgents"} rotulo={rotulo} verPacotes={verPacotes} rotuloPacotes={t.pacotes.ver} mais={tc.mais} subdominios={tc.subdominios} />
            </div>
          ))}
        </>
      )}
    </>
  );
}

function ListaNovidades({ itens, mono, rotulo, verPacotes, rotuloPacotes, mais, subdominios }: {
  itens: Novidade[];
  mono: boolean;
  rotulo: (ip: string) => string;
  verPacotes: Contexto["verPacotes"];
  rotuloPacotes: string;
  mais: (n: number) => string;
  subdominios: (n: number) => string;
}) {
  const { idioma } = useTextos();
  return (
    <ul className="lista novidades">
      {itens.slice(0, MOSTRAR).map((x) => (
        <li key={x.valor}>
          <span className={mono ? "mono quebra" : "quebra"}>{x.valor}</span>
          {x.nome && <span className="suave"> ({x.nome})</span>}
          {x.subdominios && <span className="suave"> ({subdominios(x.subdominios)})</span>}
          <span className="fraco">
            {" "}· {numero(x.vezes, idioma)}×
            {x.quem.length > 0 && !(x.quem.length === 1 && x.quem[0] === x.valor) && ` · ${x.quem.slice(0, 3).map(rotulo).join(", ")}${x.quem.length > 3 ? "…" : ""}`}
          </span>
          {x.filtro && <button className="link" onClick={() => verPacotes(x.filtro!)}>{rotuloPacotes}</button>}
        </li>
      ))}
      {itens.length > MOSTRAR && <li className="fraco">{mais(itens.length - MOSTRAR)}</li>}
    </ul>
  );
}
