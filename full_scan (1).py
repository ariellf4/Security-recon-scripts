#!/usr/bin/env python3
"""
full_scan.py
============
Reconocimiento COMPLETO/LENTO (version Python de full_scan.sh): los
65535 puertos, deteccion de OS, scripts de vulnerabilidades (NSE
"vuln"), enumeracion web a fondo (nikto + gobuster + whatweb + sslscan),
enumeracion SMB (enum4linux) y, si hay puertos de bases de datos, un
chequeo de banner/version de solo lectura (sin intentar login).

Mismas herramientas externas que full_scan.sh; cambia solo quien las
orquesta (Python + subprocess en vez de bash).

Uso:
    python3 full_scan.py <target_ip>

SOLO para uso autorizado: laboratorios propios, CTF/HTB/THM, o un
pentest con permiso explicito por escrito. Puede tardar bastante.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime

WEB_PORTS_CANDIDATAS = [80, 443, 8080, 8443, 8000, 8888]
DB_PORTS_CANDIDATAS = {
    1433: "Microsoft SQL Server",
    1521: "Oracle DB",
    3306: "MySQL / MariaDB",
    5432: "PostgreSQL",
    5984: "CouchDB",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}


def tool_exists(name):
    return shutil.which(name) is not None


def run_nmap_streaming(cmd):
    """Corre nmap mostrando cada linea en vivo; devuelve toda la salida junta."""
    lineas = []
    proceso = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    for linea in proceso.stdout:
        print(linea, end="")
        lineas.append(linea)
    proceso.wait()
    return "".join(lineas)


def run_quiet(cmd, outfile=None, timeout=1800):
    try:
        if outfile:
            with open(outfile, "w") as fh:
                subprocess.run(
                    cmd, stdout=fh, stderr=subprocess.DEVNULL,
                    timeout=timeout, check=False,
                )
        else:
            subprocess.run(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=timeout, check=False,
            )
    except subprocess.TimeoutExpired:
        print(f"    [!] Timeout corriendo: {' '.join(cmd)}")
    except FileNotFoundError:
        print(f"    [!] No se encontro el binario: {cmd[0]}")


def extract_open_ports(nmap_output):
    ports = []
    for linea in nmap_output.splitlines():
        m = re.match(r"^(\d+)/tcp\s+open\s", linea)
        if m:
            ports.append(int(m.group(1)))
    return ports


def ask_authorization(target):
    print(f"Vas a escanear: {target}")
    respuesta = input(
        "Confirmas que tenes autorizacion explicita para escanear este objetivo? (si/no): "
    ).strip().lower()
    if respuesta not in ("s", "si", "sí", "y", "yes"):
        print("Cancelado.")
        sys.exit(1)


def enumerar_smb(target, outdir):
    if tool_exists("enum4linux"):
        # enum4linux -a: enumeraciones basicas de SMB (sesion nula, usuarios,
        # shares, politica de password, info de dominio). Lectura, no intenta
        # crackear ni probar contrasenas por fuerza bruta.
        print("\n[*] SMB detectado (139/445) -> enum4linux...")
        run_quiet(["enum4linux", "-a", target], outfile=os.path.join(outdir, "enum4linux.txt"))
    else:
        print("[!] Puertos SMB detectados pero enum4linux no esta instalado, se omite.")


def elegir_wordlist():
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    biglist = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
    if os.path.isfile(biglist):
        return biglist
    return wordlist


def enumerar_web(target, puertos_web, outdir):
    wordlist = elegir_wordlist()

    for p in puertos_web:
        proto = "https" if p in (443, 8443) else "http"
        url = f"{proto}://{target}:{p}"
        print(f"\n--- Puerto {p} ({url}) ---")

        if tool_exists("whatweb"):
            # -a 3: agresividad media-alta para identificar mejor CMS/plugins.
            print("    [*] WhatWeb (fingerprint agresivo, -a 3)...")
            run_quiet(["whatweb", "-a", "3", url], outfile=os.path.join(outdir, f"whatweb_{p}.txt"))
        else:
            print("    [!] whatweb no instalado, se omite.")

        if tool_exists("nikto"):
            # Sin -Tuning: corre TODAS las categorias (mas lento que quick_scan).
            print("    [*] Nikto (scan completo, todas las categorias)...")
            run_quiet([
                "nikto", "-h", url, "-timeout", "15",
                "-o", os.path.join(outdir, f"nikto_{p}.txt"),
            ])
        else:
            print("    [!] nikto no instalado, se omite.")

        if tool_exists("gobuster"):
            if os.path.isfile(wordlist):
                # -x: ademas de nombres "pelados", prueba cada uno con estas
                # extensiones (ej /backup.zip). -t 50: mas threads que el quick.
                print(f"    [*] Gobuster dir (wordlist: {wordlist})...")
                run_quiet([
                    "gobuster", "dir", "-u", url, "-w", wordlist,
                    "-t", "50", "-x", "php,html,txt,bak,zip", "-q",
                    "-o", os.path.join(outdir, f"gobuster_dir_{p}.txt"),
                ])
            else:
                print("    [!] No se encontro ninguna wordlist, se omite gobuster.")
        else:
            print("    [!] gobuster no instalado, se omite.")

        if p in (443, 8443):
            if tool_exists("sslscan"):
                # sslscan: protocolos/cifrados soportados + datos del certificado.
                print("    [*] SSLscan (cifrados/certificado)...")
                run_quiet(["sslscan", f"{target}:{p}"], outfile=os.path.join(outdir, f"sslscan_{p}.txt"))
            else:
                print("    [!] sslscan no instalado, se omite.")


def enumerar_db(target, puertos_db, outdir):
    print("\n[*] Puertos de bases de datos detectados:")
    for p in puertos_db:
        print(f"    - Puerto {p} -> {DB_PORTS_CANDIDATAS[p]}")

    # Scripts NSE "*-info": leen el banner/version que el propio servicio
    # entrega al conectarse (igual que -sV para web/ssh/ftp), SIN mandar
    # ninguna credencial. A proposito no usamos scripts de la categoria
    # "auth" que prueban usuario/clave (ej. mysql-empty-password): eso ya
    # es un paso de ataque activo, no de descubrimiento, y queda afuera.
    puertos_csv = ",".join(str(p) for p in puertos_db)
    print("[*] Leyendo banner/version de los servicios de BD detectados (sin intentar login)...")
    run_quiet([
        "nmap", "-Pn", "-sV", "-p", puertos_csv,
        "--script", "mysql-info,ms-sql-info,mongodb-info,redis-info",
        "-oN", os.path.join(outdir, "db_info.txt"),
        target,
    ])
    print("[!] Detalle en db_info.txt. No se probaron credenciales contra ninguna base.")


def main():
    parser = argparse.ArgumentParser(description="Reconocimiento completo de puertos/servicios/vulnerabilidades.")
    parser.add_argument("target", help="IP o host objetivo")
    args = parser.parse_args()
    target = args.target

    if not tool_exists("nmap"):
        print("[-] nmap no esta instalado. Instalalo antes de continuar (apt install nmap).")
        sys.exit(1)

    if os.geteuid() != 0:
        print(f"[!] No estas corriendo como root/sudo. -O y algunos scripts funcionan mejor con privilegios. Se recomienda: sudo python3 {sys.argv[0]} {target}")

    ask_authorization(target)

    inicio = datetime.now()
    timestamp = inicio.strftime("%Y%m%d_%H%M%S")
    outdir = f"recon_full_{target}_{timestamp}"
    os.makedirs(outdir, exist_ok=True)

    print("=" * 50)
    print(f" FULL SCAN (lento) -> Target: {target}")
    print(f" Resultados en: {outdir}")
    print(" Esto puede tardar bastante.")
    print("=" * 50)

    # ---------------------------------------------------------------
    # 1. Nmap completo: todos los puertos + OS + scripts vuln
    # ---------------------------------------------------------------
    print("\n[*] Nmap: los 65535 puertos, version (-sV), OS (-O), scripts default (-sC) y de vulnerabilidades (--script vuln)...")
    nmap_out_path = os.path.join(outdir, "nmap_full.txt")
    salida_nmap = run_nmap_streaming([
        "nmap", "-Pn", "-T4", "-p-", "-sV", "-sC", "-O", "--script", "vuln",
        "-oN", nmap_out_path,
        target,
    ])

    puertos_abiertos = extract_open_ports(salida_nmap)
    if not puertos_abiertos:
        print("[!] No se detectaron puertos abiertos.")
        print(f"[*] Listo. Resultados en: {outdir}")
        return

    print(f"[*] Puertos abiertos: {' '.join(map(str, puertos_abiertos))}")

    # ---------------------------------------------------------------
    # 2. SMB
    # ---------------------------------------------------------------
    if 139 in puertos_abiertos or 445 in puertos_abiertos:
        enumerar_smb(target, outdir)

    # ---------------------------------------------------------------
    # 3. Web
    # ---------------------------------------------------------------
    puertos_web = [p for p in puertos_abiertos if p in WEB_PORTS_CANDIDATAS]
    if puertos_web:
        print(f"\n[*] Puertos web detectados: {puertos_web} -> enumeracion web completa")
        enumerar_web(target, puertos_web, outdir)
    else:
        print("[*] No se detectaron puertos web comunes.")

    # ---------------------------------------------------------------
    # 4. Bases de datos
    # ---------------------------------------------------------------
    puertos_db = [p for p in puertos_abiertos if p in DB_PORTS_CANDIDATAS]
    if puertos_db:
        enumerar_db(target, puertos_db, outdir)

    # ---------------------------------------------------------------
    # 5. Resumen final
    # ---------------------------------------------------------------
    elapsed = (datetime.now() - inicio).total_seconds()
    with open(os.path.join(outdir, "resumen.txt"), "w") as fh:
        fh.write(f"Resumen full_scan - Target: {target}\n")
        fh.write(f"Fecha: {datetime.now()}\n")
        fh.write(f"Duracion: {elapsed:.0f}s\n")
        fh.write(f"Puertos abiertos: {' '.join(map(str, puertos_abiertos))}\n")
        if puertos_web:
            fh.write(f"Puertos web: {puertos_web}\n")
        if puertos_db:
            fh.write(f"Puertos de BD: {puertos_db}\n")

    print(f"\n[*] Listo en {elapsed:.0f}s. Resultados en: {outdir} (ver resumen.txt)")
    print("[*] Revisa especialmente nmap_full.txt (resultados de --script vuln por cada puerto).")


if __name__ == "__main__":
    main()
