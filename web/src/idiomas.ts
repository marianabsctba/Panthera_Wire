import { createContext, useContext } from "react";

export type Idioma = "pt" | "en" | "es";

export const IDIOMAS: { codigo: Idioma; nome: string }[] = [
  { codigo: "pt", nome: "Português" },
  { codigo: "en", nome: "English" },
  { codigo: "es", nome: "Español" },
];

const pt = {
  privacidadeTopo: "Sua captura não sai deste navegador",
  idioma: "Idioma",
  menu: {
    visaoGeral: "Visão geral",
    alertas: "Alertas",
    linhaDoTempo: "Linha do tempo",
    fluxos: "Fluxos",
    hosts: "Hosts",
    dns: "DNS",
    tls: "TLS",
    http: "HTTP",
    exportar: "Exportar",
  },
  abrirCaptura: "Abrir captura",
  subtitulo: "Entenda o que aconteceu na rede sem ler pacote por pacote.",
  arraste: ["Arraste um arquivo ", " ou ", " aqui, ou clique para escolher."],
  capturasGrandes: "Capturas de vários GB são lidas aos poucos, sem travar a página.",
  emBreve: "A leitura de capturas chega na próxima versão.",
  cartaoPrivacidade: "Privacidade",
  valorPrivacidade: "100% local",
  cartaoFormatos: "Formatos",
  cartaoExportacao: "Exportação",
};

export type Textos = typeof pt;

const en: Textos = {
  privacidadeTopo: "Your capture never leaves this browser",
  idioma: "Language",
  menu: {
    visaoGeral: "Overview",
    alertas: "Alerts",
    linhaDoTempo: "Timeline",
    fluxos: "Flows",
    hosts: "Hosts",
    dns: "DNS",
    tls: "TLS",
    http: "HTTP",
    exportar: "Export",
  },
  abrirCaptura: "Open capture",
  subtitulo: "Understand what happened on the network without reading packet by packet.",
  arraste: ["Drop a ", " or ", " file here, or click to choose."],
  capturasGrandes: "Multi-GB captures are read in chunks, without freezing the page.",
  emBreve: "Capture reading arrives in the next version.",
  cartaoPrivacidade: "Privacy",
  valorPrivacidade: "100% local",
  cartaoFormatos: "Formats",
  cartaoExportacao: "Export",
};

const es: Textos = {
  privacidadeTopo: "Tu captura no sale de este navegador",
  idioma: "Idioma",
  menu: {
    visaoGeral: "Resumen",
    alertas: "Alertas",
    linhaDoTempo: "Línea de tiempo",
    fluxos: "Flujos",
    hosts: "Hosts",
    dns: "DNS",
    tls: "TLS",
    http: "HTTP",
    exportar: "Exportar",
  },
  abrirCaptura: "Abrir captura",
  subtitulo: "Entiende lo que pasó en la red sin leer paquete por paquete.",
  arraste: ["Arrastra un archivo ", " o ", " aquí, o haz clic para elegir."],
  capturasGrandes: "Las capturas de varios GB se leen por partes, sin congelar la página.",
  emBreve: "La lectura de capturas llega en la próxima versión.",
  cartaoPrivacidade: "Privacidad",
  valorPrivacidade: "100% local",
  cartaoFormatos: "Formatos",
  cartaoExportacao: "Exportación",
};

export const TEXTOS: Record<Idioma, Textos> = { pt, en, es };

const CHAVE = "panthera-wire.idioma";

/** Idioma salvo pela pessoa; senão o do navegador; senão inglês. */
export function idiomaInicial(): Idioma {
  try {
    const salvo = localStorage.getItem(CHAVE);
    if (salvo === "pt" || salvo === "en" || salvo === "es") return salvo;
  } catch { /* armazenamento bloqueado */ }
  const prefixo = navigator.language.slice(0, 2).toLowerCase();
  return prefixo === "pt" || prefixo === "es" ? prefixo : "en";
}

export function salvarIdioma(idioma: Idioma) {
  try { localStorage.setItem(CHAVE, idioma); } catch { /* armazenamento bloqueado */ }
  document.documentElement.lang = idioma === "pt" ? "pt-BR" : idioma;
}

export const ContextoIdioma = createContext<Textos>(pt);
export const useTextos = () => useContext(ContextoIdioma);
