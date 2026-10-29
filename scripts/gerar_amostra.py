"""Gera capturas sintéticas para teste, em pcap e pcapng, sem dependências.

Cenário: uma estação recebe IP por DHCP, baixa um executável por HTTP,
navega por TLS, passa a fazer beaconing a cada 60 s para um domínio estranho,
tenta RDP numa máquina que recusa, varre portas, abre SMB com três servidores,
manda senha em HTTP Basic, consulta domínios gerados por algoritmo, faz túnel
DNS, envia 65 MB para o servidor de comando e baixa uma segunda etapa por curl.
Outra estação fala com o mesmo servidor de comando.

    python scripts/gerar_amostra.py amostras/
    python scripts/gerar_amostra.py --grande 1024 /tmp/   # ~1 GB para teste de desempenho
"""

import argparse
import struct
from pathlib import Path

T0 = 1_761_746_400  # 2025-10-29 14:00 UTC

MAC_ESTACAO = bytes.fromhex("3c52820a0b0c")
MAC_ROTEADOR = bytes.fromhex("001122334455")
MAC_SERVIDOR = bytes.fromhex("0050569a1b2c")
ESTACAO = "10.0.0.5"
ROTEADOR = "10.0.0.1"
DNS_LOCAL = "10.0.0.1"


def ip4(s):
    return bytes(int(p) for p in s.split("."))


def ethernet(origem, destino, tipo, carga):
    return destino + origem + struct.pack("!H", tipo) + carga


def ipv4(origem, destino, protocolo, carga, ttl=64):
    cab = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(carga), 0, 0x4000, ttl, protocolo, 0, ip4(origem), ip4(destino))
    return cab + carga


def udp(po, pd, carga):
    return struct.pack("!HHHH", po, pd, 8 + len(carga), 0) + carga


def tcp(po, pd, flags, carga=b"", seq=1000, ack=0):
    return struct.pack("!HHIIBBHHH", po, pd, seq, ack, 5 << 4, flags, 65535, 0, 0) + carga


SYN, ACK, PSH, FIN, RST = 0x02, 0x10, 0x08, 0x01, 0x04


def nome_dns(n):
    return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\x00"


def dns_consulta(ident, nome, tipo=1):
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + nome_dns(nome) + struct.pack("!HH", tipo, 1)


def dns_resposta(ident, nome, ips, rcode=0):
    cab = struct.pack("!HHHHHH", ident, 0x8180 | rcode, 1, len(ips), 0, 0)
    corpo = nome_dns(nome) + struct.pack("!HH", 1, 1)
    for ip in ips:
        corpo += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ip4(ip)
    return cab + corpo


def dhcp_request(mac, nome, ip):
    corpo = struct.pack("!BBBBIHH", 1, 1, 6, 0, 0x1234, 0, 0x8000) + b"\x00" * 16 + mac + b"\x00" * 10
    corpo += b"\x00" * 192 + struct.pack("!I", 0x63825363)
    corpo += bytes([53, 1, 3]) + bytes([12, len(nome)]) + nome.encode() + bytes([50, 4]) + ip4(ip) + b"\xff"
    return corpo


def client_hello(sni):
    n = sni.encode()
    ext = struct.pack("!HHHBH", 0, len(n) + 5, len(n) + 3, 0, len(n)) + n
    ext += bytes.fromhex("0010000b000908687474702f312e31")  # ALPN http/1.1
    ext += bytes.fromhex("002b0005040304 0303".replace(" ", ""))  # TLS 1.3 e 1.2
    corpo = b"\x03\x03" + b"\x11" * 32 + b"\x00" + bytes.fromhex("000413011302") + b"\x01\x00"
    corpo += struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + struct.pack("!I", len(corpo))[1:] + corpo
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def server_hello():
    ext = bytes.fromhex("002b00020304")
    corpo = b"\x03\x03" + b"\x22" * 32 + b"\x00" + b"\x13\x01" + b"\x00" + struct.pack("!H", len(ext)) + ext
    hs = b"\x02" + struct.pack("!I", len(corpo))[1:] + corpo
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def cenario(desvio=0.0, porta_base=50000):
    """Lista de (segundos desde T0, quadro, tamanho original)."""
    p = []

    def add(t, quadro, original=None):
        p.append((desvio + t, quadro, original or len(quadro)))

    def de_estacao(t, destino_ip, proto, carga, mac_destino=MAC_ROTEADOR, original=None):
        add(t, ethernet(MAC_ESTACAO, mac_destino, 0x0800, ipv4(ESTACAO, destino_ip, proto, carga)), original)

    def para_estacao(t, origem_ip, proto, carga, mac_origem=MAC_ROTEADOR, original=None):
        add(t, ethernet(mac_origem, MAC_ESTACAO, 0x0800, ipv4(origem_ip, ESTACAO, proto, carga, ttl=54)), original)

    def conexao(t, servidor, porta, pedido, resposta, porta_cliente, original_resposta=None):
        de_estacao(t, servidor, 6, tcp(porta_cliente, porta, SYN))
        para_estacao(t + 0.02, servidor, 6, tcp(porta, porta_cliente, SYN | ACK))
        de_estacao(t + 0.021, servidor, 6, tcp(porta_cliente, porta, ACK))
        de_estacao(t + 0.022, servidor, 6, tcp(porta_cliente, porta, PSH | ACK, pedido))
        para_estacao(t + 0.05, servidor, 6, tcp(porta, porta_cliente, PSH | ACK, resposta), original=original_resposta)
        de_estacao(t + 0.06, servidor, 6, tcp(porta_cliente, porta, FIN | ACK))
        para_estacao(t + 0.07, servidor, 6, tcp(porta, porta_cliente, FIN | ACK))

    # DHCP e ARP
    add(0.0, ethernet(MAC_ESTACAO, b"\xff" * 6, 0x0800,
                      ipv4("0.0.0.0", "255.255.255.255", 17, udp(68, 67, dhcp_request(MAC_ESTACAO, "DESKTOP-FIN01", ESTACAO)))))
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + MAC_ESTACAO + ip4(ESTACAO) + b"\x00" * 6 + ip4(ROTEADOR)
    add(0.5, ethernet(MAC_ESTACAO, b"\xff" * 6, 0x0806, arp))

    # Download do executável
    de_estacao(2.0, DNS_LOCAL, 17, udp(porta_base + 1, 53, dns_consulta(0x1001, "update-cdn.xyz")))
    para_estacao(2.01, DNS_LOCAL, 17, udp(53, porta_base + 1, dns_resposta(0x1001, "update-cdn.xyz", ["203.0.113.50"])))
    pedido = b"GET /patch/KB5031.exe HTTP/1.1\r\nHost: update-cdn.xyz\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0)\r\n\r\n"
    resposta = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: application/x-msdownload\r\nContent-Length: 2097152\r\n\r\nMZ\x90\x00"
    conexao(2.1, "203.0.113.50", 80, pedido, resposta, porta_base + 2, original_resposta=1514)

    # Navegação normal
    de_estacao(10.0, DNS_LOCAL, 17, udp(porta_base + 3, 53, dns_consulta(0x1002, "www.google.com")))
    para_estacao(10.01, DNS_LOCAL, 17, udp(53, porta_base + 3, dns_resposta(0x1002, "www.google.com", ["142.250.78.4"])))
    conexao(10.1, "142.250.78.4", 443, client_hello("www.google.com"), server_hello(), porta_base + 4)

    # Domínio que não existe
    de_estacao(15.0, DNS_LOCAL, 17, udp(porta_base + 5, 53, dns_consulta(0x1003, "qx7kz2v9lmw3.info")))
    para_estacao(15.01, DNS_LOCAL, 17, udp(53, porta_base + 5, dns_resposta(0x1003, "qx7kz2v9lmw3.info", [], rcode=3)))

    # Beaconing a cada 60 s
    de_estacao(29.0, DNS_LOCAL, 17, udp(porta_base + 6, 53, dns_consulta(0x1004, "cdn-sync.top")))
    para_estacao(29.01, DNS_LOCAL, 17, udp(53, porta_base + 6, dns_resposta(0x1004, "cdn-sync.top", ["198.51.100.7"])))
    for i in range(10):
        conexao(30.0 + 60 * i, "198.51.100.7", 443, client_hello("cdn-sync.top"), server_hello(), porta_base + 10 + i)

    # Rede interna: ping, RDP recusado e SMB
    icmp = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"abcdefgh"
    de_estacao(40.0, ROTEADOR, 1, icmp)
    para_estacao(40.001, ROTEADOR, 1, struct.pack("!BBHHH", 0, 0, 0, 1, 1) + b"abcdefgh")
    de_estacao(45.0, "10.0.0.30", 6, tcp(porta_base + 30, 3389, SYN), mac_destino=MAC_SERVIDOR)
    add(45.001, ethernet(MAC_SERVIDOR, MAC_ESTACAO, 0x0800, ipv4("10.0.0.30", ESTACAO, 6, tcp(3389, porta_base + 30, RST | ACK))))
    de_estacao(50.0, "10.0.0.20", 6, tcp(porta_base + 31, 445, SYN), mac_destino=MAC_SERVIDOR)
    add(50.001, ethernet(MAC_SERVIDOR, MAC_ESTACAO, 0x0800, ipv4("10.0.0.20", ESTACAO, 6, tcp(445, porta_base + 31, SYN | ACK))))
    de_estacao(50.002, "10.0.0.20", 6, tcp(porta_base + 31, 445, ACK), mac_destino=MAC_SERVIDOR)

    def interno(t, servidor, porta, porta_cliente, recusa=False):
        de_estacao(t, servidor, 6, tcp(porta_cliente, porta, SYN), mac_destino=MAC_SERVIDOR)
        if recusa:
            add(t + 0.001, ethernet(MAC_SERVIDOR, MAC_ESTACAO, 0x0800, ipv4(servidor, ESTACAO, 6, tcp(porta, porta_cliente, RST | ACK))))
        else:
            add(t + 0.001, ethernet(MAC_SERVIDOR, MAC_ESTACAO, 0x0800, ipv4(servidor, ESTACAO, 6, tcp(porta, porta_cliente, SYN | ACK))))
            de_estacao(t + 0.002, servidor, 6, tcp(porta_cliente, porta, ACK), mac_destino=MAC_SERVIDOR)

    # Varredura de portas num servidor interno
    for i, porta in enumerate(range(20, 46)):
        interno(660.0 + i * 0.05, "10.0.0.30", porta, porta_base + 100 + i, recusa=True)

    # SMB para mais dois servidores (movimentação lateral)
    interno(700.0, "10.0.0.21", 445, porta_base + 140)
    interno(701.0, "10.0.0.22", 445, porta_base + 141)

    # Intranet com senha em HTTP Basic
    basic = b"GET /admin HTTP/1.1\r\nHost: intranet.local\r\nAuthorization: Basic YWRtaW46c2VuaGExMjM=\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    de_estacao(720.0, "10.0.0.40", 6, tcp(porta_base + 150, 80, SYN), mac_destino=MAC_SERVIDOR)
    add(720.001, ethernet(MAC_SERVIDOR, MAC_ESTACAO, 0x0800, ipv4("10.0.0.40", ESTACAO, 6, tcp(80, porta_base + 150, SYN | ACK))))
    de_estacao(720.002, "10.0.0.40", 6, tcp(porta_base + 150, 80, PSH | ACK, basic), mac_destino=MAC_SERVIDOR)
    add(720.01, ethernet(MAC_SERVIDOR, MAC_ESTACAO, 0x0800, ipv4("10.0.0.40", ESTACAO, 6,
        tcp(80, porta_base + 150, PSH | ACK, b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>"))))

    # Domínios gerados por algoritmo, que não existem
    for i in range(20):
        nome = "".join("abcdefghijklmnopqrstuvwxyz0123456789"[(i * 7 + k * 13) % 36] for k in range(14)) + ".biz"
        de_estacao(740.0 + i * 0.5, DNS_LOCAL, 17, udp(porta_base + 200 + i, 53, dns_consulta(0x2000 + i, nome)))
        para_estacao(740.01 + i * 0.5, DNS_LOCAL, 17, udp(53, porta_base + 200 + i, dns_resposta(0x2000 + i, nome, [], rcode=3)))

    # Túnel DNS: dados codificados em subdomínios longos, consultas TXT
    for i in range(40):
        rotulo = "".join("0123456789abcdef"[(i * 31 + k * 7) % 16] for k in range(48))
        nome = f"{rotulo}.t.exfil-dns.net"
        de_estacao(760.0 + i * 0.3, DNS_LOCAL, 17, udp(porta_base + 300 + i, 53, dns_consulta(0x3000 + i, nome, tipo=16)))
        para_estacao(760.01 + i * 0.3, DNS_LOCAL, 17, udp(53, porta_base + 300 + i, dns_resposta(0x3000 + i, nome, [])))

    # Exfiltração: 65 MB enviados para o mesmo servidor do beaconing
    pc = porta_base + 400
    de_estacao(800.0, "198.51.100.7", 6, tcp(pc, 443, SYN))
    para_estacao(800.02, "198.51.100.7", 6, tcp(443, pc, SYN | ACK))
    de_estacao(800.021, "198.51.100.7", 6, tcp(pc, 443, PSH | ACK, client_hello("cdn-sync.top")))
    para_estacao(800.05, "198.51.100.7", 6, tcp(443, pc, PSH | ACK, server_hello()))
    for i in range(1000):
        de_estacao(800.1 + i * 0.01, "198.51.100.7", 6, tcp(pc, 443, ACK, b"\x17\x03\x03"), original=65000)
    de_estacao(811.0, "198.51.100.7", 6, tcp(pc, 443, FIN | ACK))

    # Segunda etapa por curl
    pedido = b"GET /stage2.ps1 HTTP/1.1\r\nHost: 203.0.113.50\r\nUser-Agent: curl/8.4.0\r\n\r\n"
    resposta = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 4096\r\n\r\n$c="
    conexao(850.0, "203.0.113.50", 80, pedido, resposta, porta_base + 410)

    # Outra estação falando com o mesmo servidor de comando
    outra = "10.0.0.8"
    mac_outra = bytes.fromhex("3c52820a0b0d")
    for i in range(3):
        po = porta_base + 500 + i
        t = 900.0 + i * 60
        add(t, ethernet(mac_outra, MAC_ROTEADOR, 0x0800, ipv4(outra, "198.51.100.7", 6, tcp(po, 443, SYN))))
        add(t + 0.02, ethernet(MAC_ROTEADOR, mac_outra, 0x0800, ipv4("198.51.100.7", outra, 6, tcp(443, po, SYN | ACK))))
        add(t + 0.03, ethernet(mac_outra, MAC_ROTEADOR, 0x0800, ipv4(outra, "198.51.100.7", 6, tcp(po, 443, PSH | ACK, client_hello("cdn-sync.top")))))

    p.sort(key=lambda x: x[0])
    return p


def escrever_pcap(caminho, pacotes):
    with open(caminho, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for t, quadro, original in pacotes:
            seg = int(t)
            f.write(struct.pack("<IIII", T0 + seg, int(round((t - seg) * 1e6)), len(quadro), original))
            f.write(quadro)


def bloco(tipo, corpo):
    corpo += b"\x00" * (-len(corpo) % 4)
    tam = 12 + len(corpo)
    return struct.pack("<II", tipo, tam) + corpo + struct.pack("<I", tam)


def escrever_pcapng(caminho, pacotes):
    with open(caminho, "wb") as f:
        f.write(bloco(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
        # Interface Ethernet com resolução de nanossegundos (if_tsresol = 9)
        f.write(bloco(1, struct.pack("<HHI", 1, 0, 65535) + struct.pack("<HHB3x", 9, 1, 9) + b"\x00" * 4))
        for t, quadro, original in pacotes:
            ns = int(round((T0 + t) * 1e9))
            corpo = struct.pack("<IIIII", 0, ns >> 32, ns & 0xFFFFFFFF, len(quadro), original) + quadro
            f.write(bloco(6, corpo))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("destino", type=Path)
    ap.add_argument("--grande", type=int, metavar="MB", help="repete o cenário até chegar perto desse tamanho")
    a = ap.parse_args()
    a.destino.mkdir(parents=True, exist_ok=True)

    if a.grande:
        caminho = a.destino / f"grande-{a.grande}mb.pcap"
        alvo = a.grande * 1024 * 1024
        with open(caminho, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            rodada = 0
            while f.tell() < alvo:
                for t, quadro, original in cenario(desvio=rodada * 700.0, porta_base=1024 + (rodada * 64) % 60000):
                    seg = int(t)
                    f.write(struct.pack("<IIII", T0 + seg, int(round((t - seg) * 1e6)), len(quadro), original))
                    f.write(quadro)
                rodada += 1
        print(caminho)
        return

    pacotes = cenario()
    escrever_pcap(a.destino / "exemplo.pcap", pacotes)
    escrever_pcapng(a.destino / "exemplo.pcapng", pacotes)
    print(f"{len(pacotes)} pacotes em {a.destino}")


if __name__ == "__main__":
    main()
