/// <reference lib="webworker" />
// Lê a captura em blocos, fora da thread da interface. O arquivo nunca é
// carregado inteiro: cada bloco é lido do disco, entregue ao núcleo e descartado.

import iniciar, { Leitura } from "./nucleo-gerado/panthera_wire_wasm.js";
import type { ErroCaptura, MensagemLeitura } from "./tipos";

const BLOCO = 8 * 1024 * 1024;

function enviar(m: MensagemLeitura) {
  postMessage(m);
}

self.onmessage = async (e: MessageEvent<{ arquivo: File }>) => {
  const { arquivo } = e.data;
  const inicio = performance.now();
  try {
    await iniciar();
    const leitura = new Leitura();
    let erro: ErroCaptura | null = null;

    for (let pos = 0; pos < arquivo.size; pos += BLOCO) {
      const bloco = new Uint8Array(await arquivo.slice(pos, pos + BLOCO).arrayBuffer());
      try {
        const p = JSON.parse(leitura.alimentar(bloco));
        enviar({ tipo: "progresso", lidos: Math.min(pos + BLOCO, arquivo.size), total: arquivo.size, ...p });
      } catch (falha) {
        // Erro de formato: o que já foi lido continua valendo.
        erro = JSON.parse(String(falha));
        break;
      }
    }

    const relatorio = JSON.parse(leitura.finalizar());
    leitura.free();
    enviar({ tipo: "concluido", relatorio, erro, segundos: (performance.now() - inicio) / 1000 });
  } catch (falha) {
    enviar({ tipo: "falha", mensagem: String(falha) });
  }
};
