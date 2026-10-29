import { useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";
import { useTextos } from "./idiomas";

/**
 * Registra o service worker que deixa o site funcionando offline. Quando sai
 * uma versão nova, ela fica esperando e a pessoa escolhe a hora de trocar:
 * uma análise em andamento nunca é interrompida.
 */
export default function AvisoAtualizacao() {
  const { t } = useTextos();
  const [esperando, setEsperando] = useState<ServiceWorker | null>(null);

  useEffect(() => {
    if (!import.meta.env.PROD || !("serviceWorker" in navigator)) return;
    let recarregou = false;
    navigator.serviceWorker.addEventListener("controllerchange", () => {
      if (!recarregou) {
        recarregou = true;
        location.reload();
      }
    });
    navigator.serviceWorker.register(`${import.meta.env.BASE_URL}sw.js`).then((reg) => {
      // Só é "atualização" se já havia uma versão controlando a página.
      const avisar = (sw: ServiceWorker | null) => {
        if (sw && navigator.serviceWorker.controller) setEsperando(sw);
      };
      avisar(reg.waiting);
      reg.addEventListener("updatefound", () => {
        const novo = reg.installing;
        novo?.addEventListener("statechange", () => {
          if (novo.state === "installed") avisar(novo);
        });
      });
    }).catch(() => { /* sem offline, o site continua funcionando */ });
  }, []);

  if (!esperando) return null;
  return (
    <div className="atualizacao">
      <span>{t.atualizacao.nova}</span>
      <button className="principal" onClick={() => esperando.postMessage("atualizar")}>
        <RefreshCw size={14} /> {t.atualizacao.atualizar}
      </button>
    </div>
  );
}
