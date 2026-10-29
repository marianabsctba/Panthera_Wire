import { useRef, useState, type DragEvent } from "react";
import {
  Activity, AlertTriangle, Clock, Download, FileUp, Globe, LayoutDashboard, Lock, Network, Server, ShieldCheck,
} from "lucide-react";

const LOGO = `${import.meta.env.BASE_URL}pantera.webp`;

const MENU = [
  { rotulo: "Visão geral", icone: LayoutDashboard },
  { rotulo: "Alertas", icone: AlertTriangle },
  { rotulo: "Linha do tempo", icone: Clock },
  { rotulo: "Fluxos", icone: Activity },
  { rotulo: "Hosts", icone: Server },
  { rotulo: "DNS", icone: Globe },
  { rotulo: "TLS", icone: Lock },
  { rotulo: "HTTP", icone: Network },
  { rotulo: "Exportar", icone: Download },
];

function tamanho(bytes: number): string {
  const unidades = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = bytes;
  while (v >= 1024 && i < unidades.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${unidades[i]}`;
}

export default function App() {
  const [arquivo, setArquivo] = useState<File | null>(null);
  const [arrastando, setArrastando] = useState(false);
  const seletor = useRef<HTMLInputElement>(null);

  function soltar(e: DragEvent) {
    e.preventDefault();
    setArrastando(false);
    const f = e.dataTransfer.files[0];
    if (f) setArquivo(f);
  }

  return (
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
          <ShieldCheck size={15} /> Sua captura não sai deste navegador
        </span>
      </header>

      <div className="corpo">
        <nav className="menu">
          {MENU.map(({ rotulo, icone: Icone }, i) => (
            <a key={rotulo} className={i === 0 ? "active" : arquivo ? "" : "desativado"}>
              <Icone size={16} /> {rotulo}
            </a>
          ))}
        </nav>

        <main className="conteudo">
          <div className="cabecalho">
            <div>
              <h1>Abrir captura</h1>
              <div className="suave">Entenda o que aconteceu na rede sem ler pacote por pacote.</div>
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
            <p>Arraste um arquivo <b>pcap</b> ou <b>pcapng</b> aqui, ou clique para escolher.</p>
            <p className="fraco">Capturas de vários GB são lidas aos poucos, sem travar a página.</p>
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
              <p className="fraco">A leitura de capturas chega na próxima versão.</p>
            </div>
          )}

          <div className="cartoes">
            <div className="cartao">
              <div className="rotulo">Privacidade</div>
              <div className="valor destaque">100% local</div>
            </div>
            <div className="cartao">
              <div className="rotulo">Formatos</div>
              <div className="valor">pcap · pcapng</div>
            </div>
            <div className="cartao">
              <div className="rotulo">Exportação</div>
              <div className="valor">JSON · CSV · STIX</div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
