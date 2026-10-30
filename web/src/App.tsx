import { useEffect, useMemo, useRef, useState, type DragEvent } from "react";
import {
  Activity, AlertTriangle, BookOpen, Clock, Download, FileUp, GitCompare, Globe, Languages, LayoutDashboard, LayoutGrid, Lock, Map as IconeMapa, Play,
  List, Network, Server, ShieldCheck, X,
} from "lucide-react";
import { ContextoIdioma, IDIOMAS, TEXTOS, idiomaInicial, salvarIdioma, type Idioma, type Textos } from "./idiomas";
import { numero, tamanho } from "./formatos";
import { Dns, Fluxos, Hosts, Http, LinhaDoTempo, Tls, VisaoGeral, type Contexto } from "./paginas";
import { Alertas, Cobertura, Historia } from "./inteligencia";
import { Exportar } from "./exportar";
import { Pacotes } from "./pacotes";
import { Comparar } from "./comparar";
import { Replay } from "./replay";
import { Mapa } from "./mapa";
import type { MensagemLeitura, Relatorio } from "./tipos";
import AvisoAtualizacao from "./AvisoAtualizacao";

const LOGO = `${import.meta.env.BASE_URL}pantera.webp`;

type Pagina = keyof Textos["menu"];

const MENU: { chave: Pagina; icone: typeof Activity; pronta: boolean }[] = [
  { chave: "abrir", icone: FileUp, pronta: true },
  { chave: "historia", icone: BookOpen, pronta: true },
  { chave: "visaoGeral", icone: LayoutDashboard, pronta: true },
  { chave: "alertas", icone: AlertTriangle, pronta: true },
  { chave: "linhaDoTempo", icone: Clock, pronta: true },
  { chave: "fluxos", icone: Activity, pronta: true },
  { chave: "pacotes", icone: List, pronta: true },
  { chave: "hosts", icone: Server, pronta: true },
  { chave: "mapa", icone: IconeMapa, pronta: true },
  { chave: "dns", icone: Globe, pronta: true },
  { chave: "tls", icone: Lock, pronta: true },
  { chave: "http", icone: Network, pronta: true },
  { chave: "replay", icone: Play, pronta: true },
  { chave: "comparar", icone: GitCompare, pronta: true },
  { chave: "exportar", icone: Download, pronta: true },
  { chave: "cobertura", icone: LayoutGrid, pronta: true },
];

/** Páginas que não dependem de uma captura aberta. */
const SEM_CAPTURA: Pagina[] = ["abrir", "cobertura"];

const PAGINAS: Partial<Record<Pagina, (c: Contexto) => JSX.Element>> = {
  historia: Historia,
  visaoGeral: VisaoGeral,
  alertas: Alertas,
  linhaDoTempo: LinhaDoTempo,
  fluxos: Fluxos,
  hosts: Hosts,
  mapa: Mapa,
  dns: Dns,
  tls: Tls,
  http: Http,
  replay: Replay,
  comparar: Comparar,
  exportar: Exportar,
};

type Estado =
  | { fase: "inicio" }
  | { fase: "lendo"; arquivo: File; lidos: number; pacotes: number }
  | { fase: "pronto"; arquivo: File; relatorio: Relatorio; segundos: number }
  | { fase: "falha"; arquivo: File; codigo: string };

export default function App() {
  const [idioma, setIdioma] = useState<Idioma>(idiomaInicial);
  const [estado, setEstado] = useState<Estado>({ fase: "inicio" });
  const [pagina, setPagina] = useState<Pagina>("abrir");
  const [arrastando, setArrastando] = useState(false);
  const [filtroPacotes, setFiltroPacotes] = useState<{ ips: string[]; portas: number[] } | null>(null);
  const seletor = useRef<HTMLInputElement>(null);
  const worker = useRef<Worker | null>(null);
  const conteudo = useRef<HTMLElement>(null);
  const t = TEXTOS[idioma];

  useEffect(() => {
    salvarIdioma(idioma);
  }, [idioma]);
  // Sem retorno: em navegadores novos scrollTo devolve uma Promise, e o
  // React trataria isso como função de limpeza.
  useEffect(() => {
    conteudo.current?.scrollTo(0, 0);
  }, [pagina]);

  function encerrarLeitura() {
    worker.current?.terminate();
    worker.current = null;
  }

  function abrir(arquivo: File) {
    encerrarLeitura();
    setPagina("historia");
    setEstado({ fase: "lendo", arquivo, lidos: 0, pacotes: 0 });
    const w = new Worker(new URL("./leitura.worker.ts", import.meta.url), { type: "module" });
    worker.current = w;
    w.onmessage = (e: MessageEvent<MensagemLeitura>) => {
      const m = e.data;
      if (m.tipo === "progresso") {
        setEstado({ fase: "lendo", arquivo, lidos: m.lidos, pacotes: m.pacotes });
      } else if (m.tipo === "concluido") {
        encerrarLeitura();
        // Sem nenhum pacote, não há o que mostrar: é um arquivo inválido.
        if (m.relatorio.captura.pacotes === 0) {
          setEstado({ fase: "falha", arquivo, codigo: m.erro?.codigo ?? "formato_desconhecido" });
        } else {
          setEstado({ fase: "pronto", arquivo, relatorio: m.relatorio, segundos: m.segundos });
        }
      } else {
        encerrarLeitura();
        setEstado({ fase: "falha", arquivo, codigo: "" });
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

  function cancelar() {
    encerrarLeitura();
    setEstado({ fase: "inicio" });
    setPagina("abrir");
  }

  const nomes = useMemo(() => {
    const m = new Map<string, string>();
    if (estado.fase === "pronto") {
      for (const h of estado.relatorio.hosts) if (h.nomes.length) m.set(h.ip, h.nomes[0]);
    }
    return m;
  }, [estado]);

  const pronto = estado.fase === "pronto";
  const Pagina = PAGINAS[pagina];

  return (
    <ContextoIdioma.Provider value={{ t, idioma }}>
      <div className="app">
        <header className="topo">
          <a href={import.meta.env.BASE_URL} className="marca">
            <img src={LOGO} alt="" />
            <div>
              <div className="nome">PANTHERA WIRE</div>
              <div className="lema">See beyond the packets.</div>
            </div>
          </a>
          {estado.fase !== "inicio" && (
            <span className="topo-arquivo mono" title={estado.arquivo.name}>
              {estado.arquivo.name} · {tamanho(estado.arquivo.size)}
            </span>
          )}
          <span className="topo-privacidade">
            <ShieldCheck size={15} /> {t.privacidadeTopo}
          </span>
          <label className="seletor-idioma" title={t.idioma}>
            <Languages size={15} />
            <select aria-label={t.idioma} value={idioma} onChange={(e) => setIdioma(e.target.value as Idioma)}>
              {IDIOMAS.map(({ codigo, nome }) => <option key={codigo} value={codigo}>{nome}</option>)}
            </select>
          </label>
        </header>

        <div className="corpo">
          <nav className="menu">
            {MENU.map(({ chave, icone: Icone, pronta }) => {
              const avulsa = SEM_CAPTURA.includes(chave);
              const ativa = (pronto || avulsa) && pagina === chave;
              const disponivel = pronta && (pronto || avulsa);
              return (
                <a
                  key={chave}
                  className={ativa ? "active" : disponivel ? "" : "desativado"}
                  onClick={() => disponivel && setPagina(chave)}
                >
                  <Icone size={16} /> {t.menu[chave]}
                  {!pronta && <span className="em-breve">{t.emBreve}</span>}
                </a>
              );
            })}
          </nav>

          <main className="conteudo" ref={conteudo}>
            {pagina === "cobertura" && (
              <>
                <div className="cabecalho">
                  <h1>{t.menu[pagina]}</h1>
                  {pronto && (
                    <div className="acoes">
                      <button onClick={() => setPagina("historia")}><BookOpen size={15} /> {t.menu.historia}</button>
                    </div>
                  )}
                </div>
                <Cobertura />
              </>
            )}

            {!SEM_CAPTURA.includes(pagina) && estado.fase === "pronto" && (Pagina || pagina === "pacotes") && (
              <>
                <div className="cabecalho">
                  <h1>{t.menu[pagina]}</h1>
                  <div className="acoes">
                    <button onClick={() => setPagina("abrir")}><FileUp size={15} /> {t.abrirOutra}</button>
                  </div>
                </div>
                {pagina === "pacotes" ? (
                  <Pacotes r={estado.relatorio} arquivo={estado.arquivo} filtroInicial={filtroPacotes} limparFiltro={() => setFiltroPacotes(null)} />
                ) : Pagina && (
                  <Pagina
                    r={estado.relatorio}
                    nomes={nomes}
                    segundos={estado.segundos}
                    arquivo={estado.arquivo}
                    verPacotes={(f: { ips: string[]; portas: number[] }) => {
                      setFiltroPacotes(f);
                      setPagina("pacotes");
                    }}
                  />
                )}
              </>
            )}

            {!SEM_CAPTURA.includes(pagina) && estado.fase === "lendo" && (
              <div className="bloco leitura">
                <h2>{t.lendo}</h2>
                <div className="progresso">
                  <span style={{ width: `${(estado.lidos / Math.max(1, estado.arquivo.size)) * 100}%` }} />
                </div>
                <div className="leitura-rodape">
                  <span className="suave">
                    {t.lendoDetalhe(tamanho(estado.lidos), tamanho(estado.arquivo.size), numero(estado.pacotes, idioma))}
                  </span>
                  <button onClick={cancelar}><X size={15} /> {t.cancelar}</button>
                </div>
              </div>
            )}

            {(pagina === "abrir" || (!SEM_CAPTURA.includes(pagina) && (estado.fase === "inicio" || estado.fase === "falha"))) && (
              <>
                <div className="cabecalho">
                  <div>
                    <h1>{t.abrirCaptura}</h1>
                    <div className="suave">{t.subtitulo}</div>
                  </div>
                </div>

                {estado.fase === "falha" && (
                  <div className="aviso-erro">
                    <AlertTriangle size={15} /> {t.falha} {t.avisos[estado.codigo] ?? ""}
                  </div>
                )}

                <div
                  className={`zona ${arrastando ? "ativa" : ""}`}
                  onClick={() => seletor.current?.click()}
                  onDragOver={(e) => { e.preventDefault(); setArrastando(true); }}
                  onDragLeave={() => setArrastando(false)}
                  onDrop={soltar}
                >
                  <FileUp size={34} />
                  <p>{t.arraste[0]}<b>pcap</b>{t.arraste[1]}<b>pcapng</b>{t.arraste[2]}</p>
                  <p className="fraco">{t.capturasGrandes}</p>
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
                    <div className="rotulo">{t.cartaoPrivacidade}</div>
                    <div className="valor destaque">{t.valorPrivacidade}</div>
                  </div>
                  <div className="cartao">
                    <div className="rotulo">{t.cartaoFormatos}</div>
                    <div className="valor">pcap · pcapng</div>
                  </div>
                  <div className="cartao">
                    <div className="rotulo">{t.cartaoExportacao}</div>
                    <div className="valor">JSON · CSV · STIX</div>
                  </div>
                </div>
              </>
            )}
          </main>
        </div>
        <AvisoAtualizacao />
      </div>
    </ContextoIdioma.Provider>
  );
}
