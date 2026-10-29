import { useEffect, useRef, useState, type DragEvent } from "react";
import {
  Activity, AlertTriangle, Clock, Download, FileUp, Globe, Languages, LayoutDashboard, Lock, Network, Server,
  ShieldCheck,
} from "lucide-react";
import { ContextoIdioma, IDIOMAS, TEXTOS, idiomaInicial, salvarIdioma, type Idioma, type Textos } from "./idiomas";

const LOGO = `${import.meta.env.BASE_URL}pantera.webp`;

const MENU: { chave: keyof Textos["menu"]; icone: typeof Activity }[] = [
  { chave: "visaoGeral", icone: LayoutDashboard },
  { chave: "alertas", icone: AlertTriangle },
  { chave: "linhaDoTempo", icone: Clock },
  { chave: "fluxos", icone: Activity },
  { chave: "hosts", icone: Server },
  { chave: "dns", icone: Globe },
  { chave: "tls", icone: Lock },
  { chave: "http", icone: Network },
  { chave: "exportar", icone: Download },
];

function tamanho(bytes: number): string {
  const unidades = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = bytes;
  while (v >= 1024 && i < unidades.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${unidades[i]}`;
}

export default function App() {
  const [idioma, setIdioma] = useState<Idioma>(idiomaInicial);
  const [arquivo, setArquivo] = useState<File | null>(null);
  const [arrastando, setArrastando] = useState(false);
  const seletor = useRef<HTMLInputElement>(null);
  const t = TEXTOS[idioma];

  useEffect(() => salvarIdioma(idioma), [idioma]);

  function soltar(e: DragEvent) {
    e.preventDefault();
    setArrastando(false);
    const f = e.dataTransfer.files[0];
    if (f) setArquivo(f);
  }

  return (
    <ContextoIdioma.Provider value={t}>
      <div className="app">
        <header className="topo">
          <a href={import.meta.env.BASE_URL} className="marca">
            <img src={LOGO} alt="" />
            <div>
              <div className="nome">PANTHERA WIRE</div>
              <div className="lema">See beyond the packets.</div>
            </div>
          </a>
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
            {MENU.map(({ chave, icone: Icone }, i) => (
              <a key={chave} className={i === 0 ? "active" : arquivo ? "" : "desativado"}>
                <Icone size={16} /> {t.menu[chave]}
              </a>
            ))}
          </nav>

          <main className="conteudo">
            <div className="cabecalho">
              <div>
                <h1>{t.abrirCaptura}</h1>
                <div className="suave">{t.subtitulo}</div>
              </div>
            </div>

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
                onChange={(e) => setArquivo(e.target.files?.[0] ?? null)}
              />
            </div>

            {arquivo && (
              <div className="bloco destaque-rosa">
                <div className="mono">{arquivo.name}</div>
                <div className="suave">{tamanho(arquivo.size)}</div>
                <p className="fraco">{t.emBreve}</p>
              </div>
            )}

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
          </main>
        </div>
      </div>
    </ContextoIdioma.Provider>
  );
}
