import { createHash } from "node:crypto";
import { readdirSync, statSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

/**
 * Gera o service worker do modo offline depois do build, com a lista de
 * todos os arquivos publicados (incluindo o worker de leitura e o núcleo
 * WASM). A versão do cache é o hash dessa lista: mudou um arquivo, muda o
 * cache.
 */
function offline(): Plugin {
  let base = "/";
  let saida = "dist";
  return {
    name: "panthera-offline",
    apply: "build",
    configResolved(c) {
      base = c.base;
      saida = c.build.outDir;
    },
    closeBundle() {
      const arquivos: string[] = [];
      const percorrer = (dir: string) => {
        for (const nome of readdirSync(dir)) {
          const caminho = join(dir, nome);
          if (statSync(caminho).isDirectory()) percorrer(caminho);
          else arquivos.push(relative(saida, caminho).split("\\").join("/"));
        }
      };
      percorrer(saida);
      const lista = ["", ...arquivos.filter((a) => a !== "sw.js").sort()].map((a) => base + a);
      const versao = createHash("sha256").update(lista.join("\n")).digest("hex").slice(0, 16);
      writeFileSync(join(saida, "sw.js"), servico(versao, base, lista));
    },
  };
}

function servico(versao: string, base: string, lista: string[]): string {
  return `// Gerado no build. Guarda o site inteiro para funcionar sem internet.
const VERSAO = "panthera-wire-${versao}";
const BASE = ${JSON.stringify(base)};
const ARQUIVOS = ${JSON.stringify(lista)};

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(VERSAO).then((c) => c.addAll(ARQUIVOS)));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys()
      .then((chaves) => Promise.all(chaves.filter((k) => k !== VERSAO).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

// A versão nova só assume quando a pessoa pede.
self.addEventListener("message", (e) => {
  if (e.data === "atualizar") self.skipWaiting();
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET" || new URL(req.url).origin !== location.origin) return;
  e.respondWith((async () => {
    const guardado = await caches.match(req, { ignoreSearch: true });
    if (guardado) return guardado;
    if (req.mode === "navigate") {
      const inicio = await caches.match(BASE);
      if (inicio) return inicio;
    }
    return fetch(req);
  })());
});
`;
}

// No GitHub Pages o site fica em /Panthera_Wire/.
export default defineConfig({
  base: "/Panthera_Wire/",
  plugins: [react(), offline()],
  worker: { format: "es" },
  build: { outDir: "dist", sourcemap: false, target: "es2022" },
});
