/// <reference lib="webworker" />
// Relê a captura procurando os pacotes que passam no filtro. Para assim que
// tem o bastante: abrir os primeiros pacotes de um arquivo de GB é rápido.

import iniciar, { Pacotes } from "./nucleo-gerado/panthera_wire_wasm.js";
import type { FiltroPacotes, MensagemPacotes } from "./tipos";

const BLOCO = 8 * 1024 * 1024;

function enviar(m: MensagemPacotes) {
  postMessage(m);
}

self.onmessage = async (e: MessageEvent<{ arquivo: File; filtro: FiltroPacotes }>) => {
  const { arquivo, filtro } = e.data;
  try {
    await iniciar();
    const lista = new Pacotes(JSON.stringify(filtro));
    for (let pos = 0; pos < arquivo.size; pos += BLOCO) {
      const bloco = new Uint8Array(await arquivo.slice(pos, pos + BLOCO).arrayBuffer());
      const continuar = lista.alimentar(bloco);
      enviar({ tipo: "progresso", lidos: Math.min(pos + BLOCO, arquivo.size), total: arquivo.size });
      if (!continuar) break;
    }
    const resultado = JSON.parse(lista.finalizar());
    lista.free();
    enviar({ tipo: "concluido", resultado });
  } catch (falha) {
    enviar({ tipo: "falha", mensagem: String(falha) });
  }
};
