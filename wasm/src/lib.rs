//! Ponte entre o núcleo e o worker do navegador. Recebe blocos do arquivo e
//! devolve progresso e relatório como JSON.

#![forbid(unsafe_code)]

use panthera_wire_nucleo::anonimizador::{Anonimizador, Opcoes};
use panthera_wire_nucleo::Analise;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Anonimizacao {
    a: Option<Anonimizador>,
    tabela: String,
    relatorio: String,
}

#[wasm_bindgen]
impl Anonimizacao {
    /// `opcoes` em JSON (ver `Opcoes` no núcleo).
    #[wasm_bindgen(constructor)]
    pub fn new(opcoes: &str) -> Result<Anonimizacao, JsValue> {
        let op: Opcoes = serde_json::from_str(opcoes).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let a = Anonimizador::new(op).map_err(JsValue::from_str)?;
        Ok(Anonimizacao { a: Some(a), tabela: String::new(), relatorio: String::new() })
    }

    /// Processa um bloco e devolve os bytes novos da captura anonimizada.
    pub fn alimentar(&mut self, bloco: &[u8]) -> Result<Vec<u8>, JsValue> {
        let a = self.a.as_mut().ok_or_else(|| JsValue::from_str("{\"codigo\":\"leitura_encerrada\"}"))?;
        a.alimentar(bloco).map_err(|e| JsValue::from_str(&serde_json::to_string(&e).unwrap_or_default()))
    }

    /// Encerra: devolve o resto da saída. O relatório e a tabela ficam
    /// disponíveis em `relatorio()` e `tabela()`.
    pub fn finalizar(&mut self) -> Result<Vec<u8>, JsValue> {
        let a = self.a.take().ok_or_else(|| JsValue::from_str("{\"codigo\":\"leitura_encerrada\"}"))?;
        self.tabela = a.tabela();
        let (resto, relatorio) = a.finalizar();
        self.relatorio = serde_json::to_string(&relatorio).unwrap_or_default();
        Ok(resto)
    }

    pub fn relatorio(&self) -> String {
        self.relatorio.clone()
    }

    pub fn tabela(&self) -> String {
        self.tabela.clone()
    }
}

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
