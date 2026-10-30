// Geolocalização local: lê bases no formato MMDB dentro do navegador. Nenhum
// IP sai daqui. O arquivo pode vir de quem usa a ferramenta, então é tratado
// como entrada hostil: todo acesso é verificado e os laços têm limite.

const MARCA = [0xab, 0xcd, 0xef, 0x4d, 0x61, 0x78, 0x4d, 0x69, 0x6e, 0x64, 0x2e, 0x63, 0x6f, 0x6d];
const BUSCA_MARCA = 128 * 1024;
const MAX_DESCOMPACTADO = 1024 * 1024 * 1024;
const MAX_PROFUNDIDADE = 16;
const MAX_ITENS = 100_000;

export interface Local {
  pais?: string;
  cidade?: string;
  lat?: number;
  lon?: number;
  asn?: number;
  organizacao?: string;
}

type Valor = string | number | boolean | Uint8Array | Valor[] | { [k: string]: Valor } | null;

const utf8 = new TextDecoder();

export class Base {
  readonly tipo: string;
  /** Data de geração da base, em segundos desde 1970. */
  readonly gerada: number;
  private readonly bits: number;
  private readonly nos: number;
  private readonly tamanhoRegistro: number;
  private readonly inicioDados: number;
  private readonly noV4: number;
  private readonly memo = new Map<number, Local>();

  constructor(private readonly b: Uint8Array) {
    const fim = acharMetadados(b);
    if (fim < 0) throw new Error("sem metadados");
    const meta = new Decodificador(b, fim).valor(fim, 0)[0] as Record<string, Valor>;
    this.nos = Number(meta?.node_count);
    this.tamanhoRegistro = Number(meta?.record_size);
    this.bits = Number(meta?.ip_version) === 6 ? 128 : 32;
    this.tipo = String(meta?.database_type ?? "");
    this.gerada = Number(meta?.build_epoch ?? 0);
    if (!Number.isSafeInteger(this.nos) || this.nos <= 0 || ![24, 28, 32].includes(this.tamanhoRegistro)) {
      throw new Error("metadados inválidos");
    }
    const arvore = (this.nos * this.tamanhoRegistro * 2) / 8;
    this.inicioDados = arvore + 16;
    if (this.inicioDados > b.length) throw new Error("árvore maior que o arquivo");
    // Base IPv6: os endereços IPv4 ficam depois de 96 bits zero.
    let no = 0;
    if (this.bits === 128) for (let i = 0; i < 96 && no < this.nos; i++) no = this.registro(no, 0);
    this.noV4 = no;
  }

  private registro(no: number, lado: number): number {
    const b = this.b;
    const t = this.tamanhoRegistro;
    const p = no * (t / 4);
    if (t === 24) {
      const o = p + lado * 3;
      return (b[o] << 16) | (b[o + 1] << 8) | b[o + 2];
    }
    if (t === 32) {
      const o = p + lado * 4;
      return b[o] * 0x1000000 + ((b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]);
    }
    // 28 bits: o byte do meio guarda os 4 bits altos dos dois lados.
    const meio = b[p + 3];
    if (lado === 0) return ((meio >> 4) * 0x1000000) + ((b[p] << 16) | (b[p + 1] << 8) | b[p + 2]);
    return ((meio & 0x0f) * 0x1000000) + ((b[p + 4] << 16) | (b[p + 5] << 8) | b[p + 6]);
  }

  buscar(ip: string): Local | null {
    const bytes = bytesDoIp(ip);
    if (!bytes || (bytes.length === 16 && this.bits === 32)) return null;
    let no = bytes.length === 4 ? this.noV4 : 0;
    const total = bytes.length * 8;
    for (let i = 0; i < total && no < this.nos; i++) {
      no = this.registro(no, (bytes[i >> 3] >> (7 - (i & 7))) & 1);
    }
    if (no <= this.nos) return null;
    const conhecido = this.memo.get(no);
    if (conhecido) return conhecido;
    const pos = no - this.nos + this.inicioDados - 16;
    try {
      const local = extrair(new Decodificador(this.b, this.inicioDados).valor(pos, 0)[0]);
      this.memo.set(no, local);
      return local;
    } catch {
      return null;
    }
  }
}

function acharMetadados(b: Uint8Array): number {
  const limite = Math.max(0, b.length - BUSCA_MARCA);
  for (let i = b.length - MARCA.length; i >= limite; i--) {
    if (MARCA.every((v, j) => b[i + j] === v)) return i + MARCA.length;
  }
  return -1;
}

class Decodificador {
  private itens = 0;
  constructor(private readonly b: Uint8Array, private readonly base: number) {}

  /** Devolve o valor e a posição logo depois dele. */
  valor(pos: number, nivel: number): [Valor, number] {
    if (nivel > MAX_PROFUNDIDADE || ++this.itens > MAX_ITENS) throw new Error("estrutura grande demais");
    const b = this.b;
    if (pos < 0 || pos >= b.length) throw new Error("fora do arquivo");
    const controle = b[pos++];
    let tipo = controle >> 5;

    if (tipo === 1) {
      const t = (controle >> 3) & 3;
      const v = controle & 7;
      const extras = t + 1;
      if (pos + extras > b.length) throw new Error("fora do arquivo");
      let alvo = t === 3 ? 0 : v;
      for (let i = 0; i < extras; i++) alvo = alvo * 256 + b[pos + i];
      alvo += [0, 2048, 526336, 0][t];
      return [this.valor(this.base + alvo, nivel + 1)[0], pos + extras];
    }

    if (tipo === 0) {
      if (pos >= b.length) throw new Error("fora do arquivo");
      tipo = b[pos++] + 7;
    }

    let tam = controle & 31;
    if (tam >= 29) {
      const extras = tam - 28;
      if (pos + extras > b.length) throw new Error("fora do arquivo");
      let v = 0;
      for (let i = 0; i < extras; i++) v = v * 256 + b[pos + i];
      pos += extras;
      tam = v + [29, 285, 65821][extras - 1];
    }

    if (tipo === 7) {
      const m: Record<string, Valor> = Object.create(null);
      for (let i = 0; i < tam; i++) {
        const [k, p1] = this.valor(pos, nivel + 1);
        const [v, p2] = this.valor(p1, nivel + 1);
        m[String(k)] = v;
        pos = p2;
      }
      return [m, pos];
    }
    if (tipo === 11) {
      const a: Valor[] = [];
      for (let i = 0; i < tam; i++) {
        const [v, p] = this.valor(pos, nivel + 1);
        a.push(v);
        pos = p;
      }
      return [a, pos];
    }
    if (tipo === 14) return [tam !== 0, pos];

    if (pos + tam > b.length) throw new Error("fora do arquivo");
    const fim = pos + tam;
    const vista = new DataView(b.buffer, b.byteOffset);
    switch (tipo) {
      case 2: return [utf8.decode(b.subarray(pos, fim)), fim];
      case 3: if (tam !== 8) throw new Error("double inválido"); return [vista.getFloat64(pos), fim];
      case 4: return [b.subarray(pos, fim), fim];
      case 15: if (tam !== 4) throw new Error("float inválido"); return [vista.getFloat32(pos), fim];
      case 5: case 6: case 8: case 9: case 10: {
        let v = 0;
        for (let i = pos; i < fim; i++) v = v * 256 + b[i];
        return [v, fim];
      }
      default: throw new Error("tipo desconhecido");
    }
  }
}

function extrair(v: Valor): Local {
  const m = (v ?? {}) as Record<string, any>;
  const local: Local = {};
  const pais = m.country?.iso_code ?? m.country_code;
  if (typeof pais === "string") local.pais = pais.toUpperCase();
  if (typeof m.city?.names?.en === "string") local.cidade = m.city.names.en;
  if (typeof m.location?.latitude === "number" && typeof m.location?.longitude === "number") {
    local.lat = m.location.latitude;
    local.lon = m.location.longitude;
  }
  if (typeof m.autonomous_system_number === "number") local.asn = m.autonomous_system_number;
  if (typeof m.autonomous_system_organization === "string") local.organizacao = m.autonomous_system_organization;
  return local;
}

export function bytesDoIp(ip: string): number[] | null {
  if (!ip.includes(":")) {
    const p = ip.split(".");
    if (p.length !== 4 || !p.every((x) => /^\d{1,3}$/.test(x) && Number(x) <= 255)) return null;
    return p.map(Number);
  }
  const partes = ip.split("::");
  if (partes.length > 2) return null;
  const grupo = (s: string) => (s ? s.split(":") : []);
  const esq = grupo(partes[0]);
  const dir = partes.length === 2 ? grupo(partes[1]) : [];
  const faltam = 8 - esq.length - dir.length;
  if (faltam < 0 || (partes.length === 1 && faltam !== 0)) return null;
  const grupos = [...esq, ...Array<string>(faltam).fill("0"), ...dir];
  const saida: number[] = [];
  for (const g of grupos) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    const n = parseInt(g, 16);
    saida.push(n >> 8, n & 255);
  }
  return saida;
}

/** Aceita a base como veio ou comprimida com gzip, com limite de tamanho. */
async function abrirBase(dados: Uint8Array): Promise<Base> {
  if (dados[0] !== 0x1f || dados[1] !== 0x8b) return new Base(dados);
  const leitor = new Blob([dados]).stream().pipeThrough(new DecompressionStream("gzip")).getReader();
  const blocos: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await leitor.read();
    if (done) break;
    total += value.length;
    if (total > MAX_DESCOMPACTADO) {
      await leitor.cancel();
      throw new Error("base grande demais");
    }
    blocos.push(value);
  }
  const saida = new Uint8Array(total);
  let pos = 0;
  for (const b of blocos) {
    saida.set(b, pos);
    pos += b.length;
  }
  return new Base(saida);
}

// As bases do site carregam uma vez só, na primeira vez que a aba abre.
let embutidas: Promise<Base[]> | null = null;

export function basesEmbutidas(): Promise<Base[]> {
  embutidas ??= Promise.all(
    ["pais", "asn"].map(async (nome) => {
      const resposta = await fetch(`${import.meta.env.BASE_URL}geo/${nome}.mmdb.gz`);
      if (!resposta.ok) throw new Error(`HTTP ${resposta.status}`);
      return abrirBase(new Uint8Array(await resposta.arrayBuffer()));
    }),
  ).catch((falha) => {
    embutidas = null;
    throw falha;
  });
  return embutidas;
}

// A base carregada pela pessoa fica só na memória desta aba do navegador.
export const proprias: { nome: string; base: Base }[] = [];

export async function carregarPropria(arquivo: File): Promise<void> {
  const base = await abrirBase(new Uint8Array(await arquivo.arrayBuffer()));
  const ok = /city|country|asn|isp|enterprise|ipinfo/i.test(base.tipo);
  if (!ok) throw new Error("tipo de base desconhecido");
  const i = proprias.findIndex((p) => p.base.tipo === base.tipo);
  if (i >= 0) proprias.splice(i, 1);
  proprias.push({ nome: arquivo.name, base });
}

/** Junta o que cada base sabe do IP. A primeira que responde um campo vale. */
export function localizar(ip: string, bases: Base[]): Local {
  const local: Local = {};
  for (const b of bases) {
    const achado = b.buscar(ip);
    if (achado) for (const [k, v] of Object.entries(achado)) if ((local as any)[k] === undefined) (local as any)[k] = v;
  }
  return local;
}
