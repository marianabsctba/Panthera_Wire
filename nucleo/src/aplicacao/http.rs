use crate::bytes::texto_limpo;

pub enum MensagemHttp {
    Requisicao {
        metodo: String,
        caminho: String,
        host: Option<String>,
        user_agent: Option<String>,
        /// Só o esquema (Basic, Bearer...). O valor nunca é guardado.
        autorizacao: Option<String>,
    },
    Resposta {
        status: u16,
        tipo_conteudo: Option<String>,
        tamanho: Option<u64>,
        servidor: Option<String>,
    },
}

const METODOS: [&str; 9] = ["GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE"];

/// Teste barato, feito em todo segmento TCP, antes de tentar ler de verdade.
pub fn parece_http(c: &[u8]) -> bool {
    c.starts_with(b"HTTP/1.") || METODOS.iter().any(|m| c.len() > m.len() && c.starts_with(m.as_bytes()) && c[m.len()] == b' ')
}

pub fn ler(c: &[u8]) -> Option<MensagemHttp> {
    let cabecalho = &c[..c.len().min(16 * 1024)];
    let mut linhas = cabecalho.split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let primeira = linhas.next()?;

    let mut campos: Vec<(String, &[u8])> = Vec::new();
    for linha in linhas {
        if linha.is_empty() || campos.len() >= 100 {
            break;
        }
        if let Some(p) = linha.iter().position(|&b| b == b':') {
            let nome = String::from_utf8_lossy(&linha[..p]).trim().to_ascii_lowercase();
            campos.push((nome, trim(&linha[p + 1..])));
        }
    }
    let campo = |nome: &str, maximo: usize| {
        campos.iter().find(|(n, _)| n == nome).map(|(_, v)| texto_limpo(v, maximo))
    };

    if let Some(resto) = primeira.strip_prefix(b"HTTP/1.") {
        let status = std::str::from_utf8(resto.get(2..5)?).ok()?.parse().ok()?;
        return Some(MensagemHttp::Resposta {
            status,
            tipo_conteudo: campo("content-type", 128),
            tamanho: campo("content-length", 20).and_then(|v| v.parse().ok()),
            servidor: campo("server", 128),
        });
    }

    let mut partes = primeira.splitn(3, |&b| b == b' ');
    let metodo = std::str::from_utf8(partes.next()?).ok()?;
    if !METODOS.contains(&metodo) {
        return None;
    }
    let caminho = texto_limpo(partes.next()?, 1024);
    if !partes.next()?.starts_with(b"HTTP/") {
        return None;
    }
    Some(MensagemHttp::Requisicao {
        metodo: metodo.into(),
        caminho,
        host: campo("host", 255),
        user_agent: campo("user-agent", 512),
        autorizacao: campo("authorization", 64).and_then(|v| v.split_whitespace().next().map(str::to_owned)),
    })
}

fn trim(b: &[u8]) -> &[u8] {
    let inicio = b.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(b.len());
    let fim = b.iter().rposition(|c| !c.is_ascii_whitespace()).map_or(inicio, |p| p + 1);
    &b[inicio..fim]
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn requisicao_sem_guardar_senha() {
        let c = b"GET /admin HTTP/1.1\r\nHost: intranet.local\r\nAuthorization: Basic YWRtaW46c2VuaGE=\r\n\r\n";
        assert!(parece_http(c));
        let Some(MensagemHttp::Requisicao { host, autorizacao, caminho, .. }) = ler(c) else { panic!() };
        assert_eq!(host.as_deref(), Some("intranet.local"));
        assert_eq!(caminho, "/admin");
        assert_eq!(autorizacao.as_deref(), Some("Basic"));
    }

    #[test]
    fn resposta() {
        let c = b"HTTP/1.1 200 OK\r\nContent-Type: application/x-msdownload\r\nContent-Length: 2048\r\n\r\nMZ";
        let Some(MensagemHttp::Resposta { status, tamanho, .. }) = ler(c) else { panic!() };
        assert_eq!((status, tamanho), (200, Some(2048)));
    }
}
