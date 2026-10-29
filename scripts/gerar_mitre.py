"""Gera web/src/mitre.json a partir dos dados oficiais da MITRE.

Entradas (baixadas à parte, fora do Git):
  enterprise-attack.json  github.com/mitre-attack/attack-stix-data
  d3fend.json             d3fend.mitre.org/ontologies/d3fend.json

    python -I scripts/gerar_mitre.py <pasta com os dois arquivos>

Para cada técnica do ATT&CK Enterprise (ativas, sem revogadas ou obsoletas):
  - táticas, se é subtécnica e de quem;
  - componentes de dados de rede que a própria MITRE associa à detecção dela
    (via estratégias de detecção e analíticas);
  - contramedidas D3FEND, inferidas como o D3FEND faz: a técnica produz ou usa
    um artefato digital, e a defesa analisa, filtra, isola... esse artefato ou
    um mais genérico que o contém.
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

COMPONENTES_DE_REDE = {
    "Network Traffic Content",
    "Network Traffic Flow",
    "Network Connection Creation",
    "Network Share Access",
}

# Propriedades da ontologia que ligam uma técnica ofensiva a um artefato.
# Ficam de fora as que não dizem nada sobre o artefato (rótulos, textos...).
NAO_RELACOES = {"d3f:attack-id", "d3f:d3fend-id", "d3f:definition", "d3f:pref-label", "d3f:kb-article",
                "d3f:synonym", "d3f:enables", "d3f:kb-reference", "d3f:d3fend-comment"}


def lista(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def carregar_attack(caminho):
    objetos = json.loads(caminho.read_text(encoding="utf-8"))["objects"]
    por_id = {o["id"]: o for o in objetos}
    versao = next(o.get("x_mitre_version") for o in objetos if o["type"] == "x-mitre-collection")

    taticas = []
    matriz = next(o for o in objetos if o["type"] == "x-mitre-matrix")
    for i, ref in enumerate(matriz["tactic_refs"]):
        t = por_id[ref]
        taticas.append({"id": t["external_references"][0]["external_id"], "nome": t["name"],
                        "fase": t["x_mitre_shortname"], "ordem": i})

    ativas = {o["id"]: o for o in objetos
              if o["type"] == "attack-pattern" and not o.get("revoked") and not o.get("x_mitre_deprecated")}

    componentes = defaultdict(set)
    com_estrategia = set()
    for r in objetos:
        if r["type"] != "relationship" or r["relationship_type"] != "detects" or r["target_ref"] not in ativas:
            continue
        com_estrategia.add(r["target_ref"])
        estrategia = por_id[r["source_ref"]]
        for ref in estrategia.get("x_mitre_analytic_refs", []):
            for fonte in por_id.get(ref, {}).get("x_mitre_log_source_references", []):
                comp = por_id.get(fonte["x_mitre_data_component_ref"])
                if comp:
                    componentes[r["target_ref"]].add(comp["name"])

    tecnicas = []
    for stix_id, o in ativas.items():
        ext = next(e["external_id"] for e in o["external_references"] if e.get("source_name") == "mitre-attack")
        tecnicas.append({
            "id": ext,
            "nome": o["name"],
            "taticas": [k["phase_name"] for k in o.get("kill_chain_phases", []) if k["kill_chain_name"] == "mitre-attack"],
            "sub": bool(o.get("x_mitre_is_subtechnique")),
            "rede": sorted(componentes[stix_id] & COMPONENTES_DE_REDE),
            "estrategia": stix_id in com_estrategia,
        })
    tecnicas.sort(key=lambda t: [int(p) if p.isdigit() else p for p in t["id"].replace("T", "").split(".")])
    return versao, taticas, tecnicas


def carregar_d3fend(caminho):
    grafo = json.loads(caminho.read_text(encoding="utf-8"))["@graph"]
    por_id = {n["@id"]: n for n in grafo}

    versao = None
    for n in grafo:
        if "owl:versionInfo" in n:
            versao = n["owl:versionInfo"]
            break

    # Hierarquia de classes (para "mesmo artefato ou um caso particular dele").
    pais = defaultdict(set)
    for n in grafo:
        for sc in lista(n.get("rdfs:subClassOf")):
            alvo = sc.get("@id", "") if isinstance(sc, dict) else ""
            if alvo.startswith("d3f:"):
                pais[n["@id"]].add(alvo)

    def ancestrais(classe):
        vistos, pilha = set(), [classe]
        while pilha:
            c = pilha.pop()
            if c in vistos:
                continue
            vistos.add(c)
            pilha.extend(pais.get(c, ()))
        return vistos

    def artefatos(n):
        achados = set()
        for chave, valor in n.items():
            if chave.startswith("d3f:") and chave not in NAO_RELACOES:
                for v in lista(valor):
                    if isinstance(v, dict) and v.get("@id", "").startswith("d3f:"):
                        achados.add(v["@id"])
        for sc in lista(n.get("rdfs:subClassOf")):
            restricao = por_id.get(sc.get("@id")) if isinstance(sc, dict) else None
            if restricao and restricao.get("@type") == "owl:Restriction":
                alvo = (restricao.get("owl:someValuesFrom") or {}).get("@id", "")
                prop = (restricao.get("owl:onProperty") or {}).get("@id", "")
                if alvo.startswith("d3f:") and prop not in NAO_RELACOES:
                    achados.add(alvo)
        return achados

    def tatica_defensiva(classe):
        # A tática (Detect, Harden, Isolate...) costuma estar só na defesa-mãe.
        for c in [classe, *sorted(ancestrais(classe) - {classe})]:
            habilita = (por_id.get(c, {}).get("d3f:enables") or {})
            if isinstance(habilita, dict) and habilita.get("@id"):
                return habilita["@id"].replace("d3f:", "")
        return None

    defesas = {}
    artefatos_defesa = {}
    for n in grafo:
        d3 = n.get("d3f:d3fend-id")
        if not isinstance(d3, str):
            continue
        defesas[d3] = {"nome": n.get("rdfs:label", d3), "tatica": tatica_defensiva(n["@id"]),
                       "classe": n["@id"].replace("d3f:", "")}
        a = artefatos(n)
        if a:
            artefatos_defesa[d3] = a

    # Indexa: artefato -> defesas que lidam com ele.
    defesas_por_artefato = defaultdict(set)
    for d3, arts in artefatos_defesa.items():
        for a in arts:
            defesas_por_artefato[a].add(d3)

    mapeamento = {}
    for n in grafo:
        att = n.get("d3f:attack-id")
        if not isinstance(att, str) or not att.startswith("T"):
            continue
        # Subtécnicas herdam os artefatos da técnica-mãe (T1568.002 de T1568).
        arts = set(artefatos(n))
        for anc in ancestrais(n["@id"]):
            no = por_id.get(anc, {})
            if anc != n["@id"] and isinstance(no.get("d3f:attack-id"), str):
                arts |= artefatos(no)
        encontradas = set()
        for a in arts:
            for anc in ancestrais(a):
                encontradas |= defesas_por_artefato.get(anc, set())
        if encontradas:
            mapeamento[att] = sorted(encontradas)

    # Categoria de cada contramedida: a defesa-mãe mais alta da hierarquia
    # (ex.: D3-PHDURA fica em D3-NTA, Network Traffic Analysis). Quem não tem
    # mãe é a própria categoria.
    id_da_classe = {v["classe"]: d for d, v in defesas.items()}
    for d, v in defesas.items():
        maes = [id_da_classe[a.replace("d3f:", "")] for a in ancestrais("d3f:" + v["classe"])
                if a.replace("d3f:", "") in id_da_classe and a != "d3f:" + v["classe"]]
        maes = [m for m in maes if m.startswith("D3-")]
        # A mais alta é a que não tem nenhuma outra mãe acima dela na lista.
        topo = [m for m in maes
                if not any(id_da_classe.get(a.replace("d3f:", "")) in maes
                           for a in ancestrais("d3f:" + defesas[m]["classe"]) if a != "d3f:" + defesas[m]["classe"])]
        v["grupo"] = sorted(topo)[0] if topo else d

    # Todas as contramedidas (D3-*) vão para o site; os algoritmos de apoio
    # (D3A-*) ficam de fora porque não são técnicas defensivas.
    return versao, {d: v for d, v in sorted(defesas.items()) if d.startswith("D3-")}, mapeamento


def main():
    pasta = Path(sys.argv[1])
    versao_attack, taticas, tecnicas = carregar_attack(pasta / "enterprise-attack.json")
    versao_d3fend, defesas, mapeamento = carregar_d3fend(pasta / "d3fend.json")
    for t in tecnicas:
        t["d3fend"] = mapeamento.get(t["id"], [])

    saida = {
        "atribuicao": "MITRE ATT&CK® e MITRE D3FEND™, © The MITRE Corporation. Reproduzido conforme os termos de uso da MITRE.",
        "versao_attack": versao_attack,
        "versao_d3fend": versao_d3fend,
        "taticas": taticas,
        "tecnicas": tecnicas,
        "defesas": defesas,
    }
    destino = Path(__file__).resolve().parent.parent / "web" / "src" / "mitre.json"
    destino.write_text(json.dumps(saida, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")

    com_rede = sum(1 for t in tecnicas if t["rede"])
    com_d3 = sum(1 for t in tecnicas if t["d3fend"])
    print(f"ATT&CK {versao_attack}: {len(tecnicas)} técnicas, {com_rede} com pegada de rede, {com_d3} com D3FEND")
    print(f"D3FEND {versao_d3fend}: {len(defesas)} contramedidas")
    print(f"{destino} ({destino.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
