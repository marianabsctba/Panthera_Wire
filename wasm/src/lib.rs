//! Ponte entre o núcleo e o worker do navegador. Recebe blocos do arquivo e
//! devolve progresso e relatório como JSON.

#![forbid(unsafe_code)]

use panthera_wire_nucleo::Analise;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Leitura {
    analise: Option<Analise>,
}

#[wasm_bindgen]
impl Leitura {
    #[wasm_bindgen(constructor)]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Leitura {
        Leitura { analise: Some(Analise::new()) }
    }

    /// Processa um bloco. Devolve o progresso em JSON; em caso de erro de
    /// formato, lança o erro em JSON (`{"codigo": ..., "offset": ...}`).
    pub fn alimentar(&mut self, bloco: &[u8]) -> Result<String, JsValue> {
        let analise = self.analise.as_mut().ok_or_else(|| JsValue::from_str("{\"codigo\":\"leitura_encerrada\"}"))?;
        match analise.alimentar(bloco) {
            Ok(p) => Ok(serde_json::to_string(&p).unwrap_or_default()),
            Err(e) => Err(JsValue::from_str(&serde_json::to_string(&e).unwrap_or_default())),
        }
    }

    /// Encerra a leitura e devolve o relatório completo em JSON.
    pub fn finalizar(&mut self) -> Result<String, JsValue> {
        let analise = self.analise.take().ok_or_else(|| JsValue::from_str("{\"codigo\":\"leitura_encerrada\"}"))?;
        Ok(serde_json::to_string(&analise.finalizar()).unwrap_or_default())
    }
}
