import { useEffect, useMemo, useRef, useState } from "react";
import { Copy, Download, FileJson, FileSpreadsheet, Network, ShieldCheck, TriangleAlert } from "lucide-react";
import { useTextos } from "./idiomas";
import { TEXTOS_INTELIGENCIA } from "./textos-inteligencia";
import { hora, numero, tamanho } from "./formatos";
import { baixar, bundleStix, csvIocs, iocs } from "./stix";
import type { Contexto } from "./paginas";
import type { Alerta, MensagemAnonimizacao, OpcoesAnonimizacao, RelatorioAnonimizacao } from "./tipos";

type Fase =
  | { tipo: "parado" }
  | { tipo: "rodando"; lidos: number }
  | { tipo: "pronto"; arquivo: Blob; relatorio: RelatorioAnonimizacao; tabela: string; chave: string }
  | { tipo: "falha" };

function chaveAleatoria(): string {
  const b = crypto.getRandomValues(new Uint8Array(16));
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function Opcao({ nome, valor, atual, mudar, titulo, descricao }: {
  nome: string; valor: string; atual: string; mudar: (v: string) => void; titulo: string; descricao: string;
}) {
  return (
    <label className={`opcao ${atual === valor ? "marcada" : ""}`}>
      <input type="radio" name={nome} checked={atual === valor} onChange={() => mudar(valor)} />
      <span><b>{titulo}</b><span className="suave">{descricao}</span></span>
    </label>
  );
}

export function Exportar({ r, nomes, arquivo }: Contexto) {
  const { idioma } = useTextos();
  const ti = TEXTOS_INTELIGENCIA[idioma];
  const tx = ti.exportar;

  const [enderecos, setEnderecos] = useState<OpcoesAnonimizacao["enderecos"]>("internos");
  const [conteudo, setConteudo] = useState<OpcoesAnonimizacao["conteudo"]>("cabecalhos");
  const [manterFabricante, setManterFabricante] = useState(false);
  const [deslocar, setDeslocar] = useState(false);
  const [dominios, setDominios] = useState("");
  const [usarChave, setUsarChave] = useState(false);
  const [chave, setChave] = useState("");
  const [chaveErrada, setChaveErrada] = useState(false);
  const [copiada, setCopiada] = useState(false);
  const [fase, setFase] = useState<Fase>({ tipo: "parado" });
  const worker = useRef<Worker | null>(null);

  useEffect(() => () => worker.current?.terminate(), []);

  const base = arquivo.name.replace(/\.(pcapng|pcap|cap)$/i, "");
  const listaIocs = useMemo(() => iocs(r), [r]);

  function gerar() {
    const chaveUsada = usarChave ? chave.trim().toLowerCase() : chaveAleatoria();
    if (!/^[0-9a-f]{32}$/.test(chaveUsada)) {
      setChaveErrada(true);
      return;
    }
    setChaveErrada(false);
    const opcoes: OpcoesAnonimizacao = {
      chave: chaveUsada,
      enderecos,
      conteudo,
      manter_fabricante: manterFabricante,
      deslocar_horarios: deslocar,
      // O que a análise já sabe que é nome da rede.
      nomes_internos: r.hosts.filter((h) => h.escopo === "interno").flatMap((h) => h.nomes),
      dominios_internos: dominios.split(/[,\s]+/).map((d) => d.trim()).filter(Boolean),
    };
    worker.current?.terminate();
    const w = new Worker(new URL("./anonimizacao.worker.ts", import.meta.url), { type: "module" });
    worker.current = w;
    setFase({ tipo: "rodando", lidos: 0 });
    w.onmessage = (e: MessageEvent<MensagemAnonimizacao>) => {
      const m = e.data;
      if (m.tipo === "progresso") setFase({ tipo: "rodando", lidos: m.lidos });
      else if (m.tipo === "concluido") {
        w.terminate();
        setFase({ tipo: "pronto", arquivo: m.arquivo, relatorio: m.relatorio, tabela: m.tabela, chave: chaveUsada });
      } else {
        w.terminate();
        setFase({ tipo: "falha" });
      }
    };
    w.postMessage({ arquivo, opcoes, nome: `${base}.anonimizado.pcapng` });
  }

  const rotulo = (ip: string) => (nomes.get(ip) ? `${ip} (${nomes.get(ip)})` : ip);
  const dados = (a: Alerta) => ({ h: rotulo(a.host), alvo: a.alvo ?? "", p: a.parametros });
  const titulo = (a: Alerta) => ti.regras[a.regra]?.titulo(dados(a)) ?? a.regra;
  const frase = (a: Alerta) => ti.regras[a.regra]?.frase(dados(a)) ?? a.regra;

  function exportarStix() {
    const c = r.historia.cadeias[0];
    const resumo = c
      ? ti.historia.pacienteZero(rotulo(c.host), c.passos.length, new Set(c.passos.map((p) => p.fase)).size,
          hora(c.inicio_us).slice(0, 8), hora(c.fim_us).slice(0, 8))
      : ti.historia.semSuspeitas;
    const bundle = bundleStix(r, arquivo.name, { titulo, frase, resumo });
    baixar(JSON.stringify(bundle, null, 2), `${base}.stix.json`, "application/stix+json");
  }

  return (
    <>
      <div className="bloco formulario-anon">
        <h2>{tx.anonimizarTitulo}</h2>
        <p className="suave">{tx.anonimizarSubtitulo}</p>

        <fieldset className="opcoes">
          <legend>{tx.enderecos}</legend>
          {(["internos", "todos", "nenhum"] as const).map((v) => (
            <Opcao key={v} nome="enderecos" valor={v} atual={enderecos} mudar={(x) => setEnderecos(x as typeof enderecos)}
              titulo={tx.enderecosOpcoes[v][0]} descricao={tx.enderecosOpcoes[v][1]} />
          ))}
        </fieldset>

        <fieldset className="opcoes">
          <legend>{tx.conteudo}</legend>
          {(["cabecalhos", "protocolos"] as const).map((v) => (
            <Opcao key={v} nome="conteudo" valor={v} atual={conteudo} mudar={(x) => setConteudo(x as typeof conteudo)}
              titulo={tx.conteudoOpcoes[v][0]} descricao={tx.conteudoOpcoes[v][1]} />
          ))}
        </fieldset>

        <label className="marcar">
          <input type="checkbox" checked={manterFabricante} onChange={(e) => setManterFabricante(e.target.checked)} />
          {tx.manterFabricante}
        </label>
        <label className="marcar">
          <input type="checkbox" checked={deslocar} onChange={(e) => setDeslocar(e.target.checked)} />
          {tx.deslocarHorarios}
        </label>
        <label className="campo">
          <span className="suave">{tx.dominiosInternos}</span>
          <input value={dominios} placeholder={tx.dominiosExemplo} onChange={(e) => setDominios(e.target.value)} />
        </label>
        <label className="marcar">
          <input type="checkbox" checked={usarChave} onChange={(e) => setUsarChave(e.target.checked)} />
          {tx.usarChave}
        </label>
        {usarChave && (
          <input className="mono" value={chave} placeholder={tx.chaveExemplo} maxLength={32} onChange={(e) => setChave(e.target.value)} />
        )}
        {chaveErrada && <div className="aviso-erro">{tx.chaveInvalida}</div>}

        <div>
          <button className="principal" disabled={fase.tipo === "rodando"} onClick={gerar}>
            <ShieldCheck size={15} /> {tx.gerar}
          </button>
        </div>

        {fase.tipo === "rodando" && (
          <div className="leitura">
            <span className="suave">{tx.gerando} · {tamanho(fase.lidos)} / {tamanho(arquivo.size)}</span>
            <div className="progresso"><span style={{ width: `${(fase.lidos / Math.max(1, arquivo.size)) * 100}%` }} /></div>
          </div>
        )}
        {fase.tipo === "falha" && <div className="aviso-erro">{tx.falha}</div>}

        {fase.tipo === "pronto" && (
          <div className="bloco destaque-rosa resultado-anon">
            <h3>{tx.pronto}</h3>
            <p>
              {tx.resumo(numero(fase.relatorio.pacotes, idioma), numero(fase.relatorio.enderecos_trocados, idioma),
                numero(fase.relatorio.macs_trocados, idioma), numero(fase.relatorio.nomes_mascarados, idioma))}
            </p>
            <p className="suave">
              {tx.removidos(numero(fase.relatorio.pacotes_cortados, idioma), numero(fase.relatorio.pacotes_removidos, idioma),
                tamanho(fase.relatorio.bytes_removidos))}
            </p>
            <h3><TriangleAlert size={15} /> {tx.riscosTitulo}</h3>
            <ul className="lista">
              {fase.relatorio.riscos.map((c) => <li key={c}>{tx.riscos[c] ?? c}</li>)}
            </ul>
            <p className="suave">{tx.riscosAviso}</p>
            <div className="acoes-linha">
              <button className="principal" onClick={() => baixar(fase.arquivo, `${base}.anonimizado.pcapng`)}>
                <Download size={15} /> {tx.baixarCaptura} · {tamanho(fase.arquivo.size)}
              </button>
              <button onClick={() => baixar(fase.tabela, `${base}.correspondencia.csv`, "text/csv")} title={tx.tabelaAviso}>
                <FileSpreadsheet size={15} /> {tx.baixarTabela}
              </button>
              <button onClick={async () => {
                await navigator.clipboard.writeText(fase.chave);
                setCopiada(true);
                setTimeout(() => setCopiada(false), 2000);
              }} title={tx.chaveAviso}>
                <Copy size={15} /> {copiada ? tx.chaveCopiada : tx.copiarChave}
              </button>
            </div>
            <p className="fraco">{tx.tabelaAviso} {tx.chaveAviso}</p>
          </div>
        )}
      </div>

      <div className="bloco">
        <h2>{tx.analiseTitulo}</h2>
        <p className="suave">{tx.analiseSubtitulo} {tx.iocs(listaIocs.length)}.</p>
        <div className="cartoes exportacoes">
          <button className="cartao cartao-botao" onClick={() => baixar(JSON.stringify(r, null, 2), `${base}.panthera.json`, "application/json")}>
            <div className="rotulo"><FileJson size={15} /> {tx.json[0]}</div>
            <div className="suave">{tx.json[1]}</div>
          </button>
          <button className="cartao cartao-botao" onClick={() => baixar(csvIocs(r), `${base}.iocs.csv`, "text/csv")}>
            <div className="rotulo"><FileSpreadsheet size={15} /> {tx.csv[0]}</div>
            <div className="suave">{tx.csv[1]}</div>
          </button>
          <button className="cartao cartao-botao" onClick={exportarStix}>
            <div className="rotulo"><Network size={15} /> {tx.stix[0]}</div>
            <div className="suave">{tx.stix[1]}</div>
          </button>
        </div>
      </div>
    </>
  );
}
