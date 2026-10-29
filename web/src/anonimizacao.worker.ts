/// <reference lib="webworker" />
// Anonimiza a captura em blocos, fora da thread da interface. A saída vai
// para o armazenamento local do navegador (OPFS), então arquivos de GB não
// precisam caber na memória. Sem OPFS, a saída vira um Blob em partes.

import iniciar, { Anonimizacao } from "./nucleo-gerado/panthera_wire_wasm.js";
import type { ErroCaptura, MensagemAnonimizacao, OpcoesAnonimizacao } from "./tipos";

const BLOCO = 8 * 1024 * 1024;

interface Gravador {
  escrever(b: Uint8Array): void;
  fechar(): Promise<Blob>;
}

async function abrirSaida(nome: string): Promise<Gravador> {
  try {
    const raiz = await navigator.storage.getDirectory();
    const arquivo = await raiz.getFileHandle(nome, { create: true });
    const acesso = await arquivo.createSyncAccessHandle();
    acesso.truncate(0);
    let pos = 0;
    return {
      escrever(b) {
        acesso.write(b, { at: pos });
        pos += b.byteLength;
      },
      async fechar() {
        acesso.flush();
        acesso.close();
        return arquivo.getFile();
      },
    };
  } catch {
    const partes: Uint8Array[] = [];
    return {
      escrever(b) {
        partes.push(b);
      },
      async fechar() {
        return new Blob(partes, { type: "application/octet-stream" });
      },
    };
  }
}

function enviar(m: MensagemAnonimizacao) {
  postMessage(m);
}

self.onmessage = async (e: MessageEvent<{ arquivo: File; opcoes: OpcoesAnonimizacao; nome: string }>) => {
  const { arquivo, opcoes, nome } = e.data;
  try {
    await iniciar();
    const anon = new Anonimizacao(JSON.stringify(opcoes));
    const saida = await abrirSaida(nome);
    let erro: ErroCaptura | null = null;

    for (let pos = 0; pos < arquivo.size; pos += BLOCO) {
      const bloco = new Uint8Array(await arquivo.slice(pos, pos + BLOCO).arrayBuffer());
      try {
        saida.escrever(anon.alimentar(bloco));
      } catch (falha) {
        erro = JSON.parse(String(falha));
        break;
      }
      enviar({ tipo: "progresso", lidos: Math.min(pos + BLOCO, arquivo.size), total: arquivo.size });
    }

    saida.escrever(anon.finalizar());
    const relatorio = JSON.parse(anon.relatorio());
    const tabela = anon.tabela();
    anon.free();
    enviar({ tipo: "concluido", arquivo: await saida.fechar(), relatorio, tabela, erro });
  } catch (falha) {
    enviar({ tipo: "falha", mensagem: String(falha) });
  }
};
