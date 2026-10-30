#!/usr/bin/env python3
"""Baixa as bases de geolocalização do mês para web/public/geo.

As bases são atualizadas todo mês e não ficam no repositório: entram no site
na hora de publicar. Sem base nenhuma o build falha de propósito, e o site no
ar continua sendo a última versão publicada.
"""

import datetime
import gzip
import pathlib
import urllib.request

DESTINO = pathlib.Path(__file__).resolve().parent.parent / "web" / "public" / "geo"
BASES = {"pais.mmdb.gz": "country", "asn.mmdb.gz": "asn"}
MARCA = b"\xab\xcd\xefMaxMind.com"
MINIMO = 1024 * 1024


def meses():
    hoje = datetime.date.today()
    yield hoje.strftime("%Y-%m")
    # No começo do mês a base nova pode ainda não ter saído.
    yield (hoje.replace(day=1) - datetime.timedelta(days=1)).strftime("%Y-%m")


def baixar(tipo, mes):
    url = f"https://download.db-ip.com/free/dbip-{tipo}-lite-{mes}.mmdb.gz"
    pedido = urllib.request.Request(url, headers={"User-Agent": "panthera-wire-build"})
    with urllib.request.urlopen(pedido, timeout=120) as resposta:
        dados = resposta.read()
    base = gzip.decompress(dados)
    if len(base) < MINIMO or MARCA not in base[-128 * 1024:]:
        raise ValueError(f"{url}: não parece uma base válida")
    return dados


def main():
    DESTINO.mkdir(parents=True, exist_ok=True)
    for nome, tipo in BASES.items():
        ultimo = None
        for mes in meses():
            try:
                dados = baixar(tipo, mes)
            except (OSError, ValueError) as falha:
                ultimo = falha
                continue
            (DESTINO / nome).write_bytes(dados)
            print(f"{nome}: {mes}, {len(dados) / 1024 / 1024:.1f} MB")
            break
        else:
            raise SystemExit(f"não consegui baixar a base {tipo}: {ultimo}")


if __name__ == "__main__":
    main()
