#!/usr/bin/env python3
"""Gera web/src/mapa-paises.json a partir do pacote world-atlas (Natural Earth).

Uso: gerar_mapa.py <pasta com countries-110m.json e countries-50m.json>

Os contornos vêm da resolução 110m, leve o bastante para ir no site. Países
pequenos demais para existir nela (Singapura, Hong Kong, Malta) saem da 50m
como um ponto, porque são justamente lugares comuns em tráfego de internet.
"""

import json
import math
import pathlib
import sys

SAIDA = pathlib.Path(__file__).resolve().parent.parent / "web" / "src" / "mapa-paises.json"

ESCALA = 170.0
LARGURA = 960.0
LAT_NORTE = 84.0
LAT_SUL = -58.0

# ISO 3166-1: código numérico (o que o world-atlas usa) para alfa-2 (o que as
# bases de geolocalização usam).
ISO = dict(item.split(":") for item in """
004:AF 008:AL 010:AQ 012:DZ 016:AS 020:AD 024:AO 028:AG 031:AZ 032:AR 036:AU 040:AT 044:BS 048:BH 050:BD 051:AM
052:BB 056:BE 060:BM 064:BT 068:BO 070:BA 072:BW 074:BV 076:BR 084:BZ 086:IO 090:SB 092:VG 096:BN 100:BG 104:MM
108:BI 112:BY 116:KH 120:CM 124:CA 132:CV 136:KY 140:CF 144:LK 148:TD 152:CL 156:CN 158:TW 162:CX 166:CC 170:CO
174:KM 175:YT 178:CG 180:CD 184:CK 188:CR 191:HR 192:CU 196:CY 203:CZ 204:BJ 208:DK 212:DM 214:DO 218:EC 222:SV
226:GQ 231:ET 232:ER 233:EE 234:FO 238:FK 239:GS 242:FJ 246:FI 248:AX 250:FR 254:GF 258:PF 260:TF 262:DJ 266:GA
268:GE 270:GM 275:PS 276:DE 288:GH 292:GI 296:KI 300:GR 304:GL 308:GD 312:GP 316:GU 320:GT 324:GN 328:GY 332:HT
334:HM 336:VA 340:HN 344:HK 348:HU 352:IS 356:IN 360:ID 364:IR 368:IQ 372:IE 376:IL 380:IT 384:CI 388:JM 392:JP
398:KZ 400:JO 404:KE 408:KP 410:KR 414:KW 417:KG 418:LA 422:LB 426:LS 428:LV 430:LR 434:LY 438:LI 440:LT 442:LU
446:MO 450:MG 454:MW 458:MY 462:MV 466:ML 470:MT 474:MQ 478:MR 480:MU 484:MX 492:MC 496:MN 498:MD 499:ME 500:MS
504:MA 508:MZ 512:OM 516:NA 520:NR 524:NP 528:NL 531:CW 533:AW 534:SX 535:BQ 540:NC 548:VU 554:NZ 558:NI 562:NE
566:NG 570:NU 574:NF 578:NO 580:MP 581:UM 583:FM 584:MH 585:PW 586:PK 591:PA 598:PG 600:PY 604:PE 608:PH 612:PN
616:PL 620:PT 624:GW 626:TL 630:PR 634:QA 638:RE 642:RO 643:RU 646:RW 652:BL 654:SH 659:KN 660:AI 662:LC 663:MF
666:PM 670:VC 674:SM 678:ST 682:SA 686:SN 688:RS 690:SC 694:SL 702:SG 703:SK 704:VN 705:SI 706:SO 710:ZA 716:ZW
724:ES 728:SS 729:SD 732:EH 740:SR 744:SJ 748:SZ 752:SE 756:CH 760:SY 762:TJ 764:TH 768:TG 772:TK 776:TO 780:TT
784:AE 788:TN 792:TR 795:TM 796:TC 798:TV 800:UG 804:UA 807:MK 818:EG 826:GB 831:GG 832:JE 833:IM 834:TZ 840:US
850:VI 854:BF 858:UY 860:UZ 862:VE 876:WF 882:WS 887:YE 894:ZM
""".split())

# Sem código numérico no Natural Earth: usa o código que as bases devolvem.
POR_NOME = {"Kosovo": "XK", "Somaliland": "SO", "N. Cyprus": "CY"}


def projetar(lon, lat):
    """Projeção Natural Earth."""
    l, p = math.radians(lon), math.radians(lat)
    p2 = p * p
    p4 = p2 * p2
    x = l * (0.8707 - 0.131979 * p2 + p4 * (-0.013791 + p4 * (0.003971 * p2 - 0.001529 * p4)))
    y = p * (1.007226 + p2 * (0.015085 + p4 * (-0.044475 + 0.028874 * p2 - 0.005916 * p4)))
    return x, y


_, Y_NORTE = projetar(0, LAT_NORTE)
_, Y_SUL = projetar(0, LAT_SUL)
ALTURA = round((Y_NORTE - Y_SUL) * ESCALA)


def tela(lon, lat):
    x, y = projetar(lon, lat)
    return LARGURA / 2 + x * ESCALA, (Y_NORTE - y) * ESCALA


def arcos(topo):
    sx, sy = topo["transform"]["scale"]
    tx, ty = topo["transform"]["translate"]
    saida = []
    for arco in topo["arcs"]:
        x = y = 0
        pontos = []
        for dx, dy in arco:
            x += dx
            y += dy
            pontos.append((x * sx + tx, y * sy + ty))
        saida.append(pontos)
    return saida


def anel(indices, todos):
    pontos = []
    for i in indices:
        arco = todos[i] if i >= 0 else list(reversed(todos[~i]))
        pontos.extend(arco if not pontos else arco[1:])
    return pontos


def poligonos(geo):
    if geo["type"] == "Polygon":
        return [geo["arcs"]]
    if geo["type"] == "MultiPolygon":
        return geo["arcs"]
    return []


def cortar(pontos, dentro, limite):
    """Corta um anel num meridiano (Sutherland-Hodgman)."""
    saida = []
    for i, atual in enumerate(pontos):
        anterior = pontos[i - 1]
        if dentro(atual) != dentro(anterior):
            t = (limite - anterior[0]) / (atual[0] - anterior[0])
            saida.append((limite, anterior[1] + t * (atual[1] - anterior[1])))
        if dentro(atual):
            saida.append(atual)
    return saida


def sem_antimeridiano(pontos):
    """Rússia e Fiji cruzam o meridiano 180: viram dois anéis, um de cada lado."""
    corrido = [pontos[0]]
    for lon, lat in pontos[1:]:
        ant = corrido[-1][0]
        while lon - ant > 180:
            lon -= 360
        while lon - ant < -180:
            lon += 360
        corrido.append((lon, lat))
    menor = min(v[0] for v in corrido)
    maior = max(v[0] for v in corrido)
    if menor >= -180 and maior <= 180:
        return [pontos]
    limite = 180 if maior > 180 else -180
    volta = -360 if maior > 180 else 360
    fora = (lambda v: v[0] >= limite) if maior > 180 else (lambda v: v[0] <= limite)
    aneis = [cortar(corrido, lambda v: not fora(v), limite)]
    aneis.append([(lon + volta, lat) for lon, lat in cortar(corrido, fora, limite)])
    return [a for a in aneis if len(a) >= 3]


def caminho(pontos):
    inicio = ""
    deltas = []
    ax = ay = None
    for lon, lat in pontos:
        x, y = (round(v, 1) for v in tela(lon, lat))
        if ax is None:
            inicio = f"M{x} {y}"
        elif (x, y) != (ax, ay):
            deltas.append(f"{round(x - ax, 1)} {round(y - ay, 1)}")
        ax, ay = x, y
    # Ilha menor que a resolução do desenho: não tem o que traçar.
    return f"{inicio}l{' '.join(deltas)}z" if deltas else ""


def codigo(geometria):
    nome = geometria.get("properties", {}).get("name", "")
    return POR_NOME.get(nome) or ISO.get(str(geometria.get("id", "")))


def ler(pasta, arquivo):
    topo = json.loads((pasta / arquivo).read_text(encoding="utf-8"))
    return arcos(topo), topo["objects"]["countries"]["geometries"]


def main():
    pasta = pathlib.Path(sys.argv[1])

    todos, geometrias = ler(pasta, "countries-110m.json")
    paises = {}
    for g in geometrias:
        c = codigo(g)
        if not c:
            print("sem código:", g.get("id"), g.get("properties", {}).get("name"))
            continue
        if c == "AQ":
            continue
        for p in poligonos(g):
            for pedaco in sem_antimeridiano(anel(p[0], todos)):
                paises.setdefault(c, []).append(caminho(pedaco))

    todos, geometrias = ler(pasta, "countries-50m.json")
    pontos = {}
    for g in geometrias:
        c = codigo(g)
        if not c or c in paises or c == "AQ" or c in pontos:
            continue
        aneis = [anel(p[0], todos) for p in poligonos(g)]
        if not aneis:
            continue
        maior = max(aneis, key=len)
        lon = sum(v[0] for v in maior) / len(maior)
        lat = sum(v[1] for v in maior) / len(maior)
        x, y = tela(lon, lat)
        pontos[c] = [round(x, 1), round(y, 1)]

    saida = {
        "largura": LARGURA,
        "altura": ALTURA,
        "escala": ESCALA,
        "yNorte": round(Y_NORTE, 6),
        "paises": [{"c": c, "d": "".join(d)} for c, d in sorted(paises.items())],
        "pontos": [{"c": c, "x": v[0], "y": v[1]} for c, v in sorted(pontos.items())],
    }
    SAIDA.write_text(json.dumps(saida, separators=(",", ":")), encoding="utf-8")
    print(f"{len(paises)} contornos, {len(pontos)} pontos, {SAIDA.stat().st_size / 1024:.0f} KB")


if __name__ == "__main__":
    main()
