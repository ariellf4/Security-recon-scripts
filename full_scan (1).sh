#!/bin/bash
#
# full_scan.sh - Reconocimiento COMPLETO/LENTO: los 65535 puertos,
#                deteccion de OS, scripts de vulnerabilidades (NSE "vuln"),
#                enumeracion web a fondo (nikto + gobuster + whatweb +
#                sslscan), enumeracion SMB (enum4linux) y, si hay puertos
#                de bases de datos, un chequeo de banner/version de
#                solo-lectura (sin intentar login).
#
# Uso:
#   ./full_scan.sh <target_ip>
#
# SOLO para uso autorizado: laboratorios propios, CTF/HTB/THM, o un
# pentest para el que tengas permiso explicito por escrito.
# Puede tardar bastante (minutos a bien largo segun el target y la red).
#
# Requiere (normalmente ya vienen en Kali): nmap
# Opcionales (si no estan, se omite ese paso): nikto, gobuster, whatweb,
# sslscan, enum4linux

set -uo pipefail

# Colores solo para legibilidad en pantalla, no afectan el escaneo.
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

TARGET="${1:-}"

if [[ -z "$TARGET" ]]; then
    echo "Uso: $0 <target_ip>"
    exit 1
fi

if ! command -v nmap &>/dev/null; then
    echo -e "${RED}[-] nmap no esta instalado. Instalalo antes de continuar (apt install nmap).${NC}"
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo -e "${YELLOW}[!] No estas corriendo como root/sudo. -O (deteccion de OS) y algunos scripts funcionan mejor con privilegios. Se recomienda: sudo $0 $TARGET${NC}"
fi

# -----------------------------------------------------------------------
# Confirmacion de autorizacion antes de generar trafico activo contra el
# target (todos los puertos, scripts de vulnerabilidades, fuerza bruta
# de NOMBRES de archivo/directorio via gobuster, etc.)
# -----------------------------------------------------------------------
echo -e "${YELLOW}Vas a escanear: ${TARGET}${NC}"
read -rp "Confirmas que tenes autorizacion explicita para escanear este objetivo? (si/no): " CONFIRM
# ${CONFIRM,,} pasa la respuesta a minusculas; case compara contra cada
# opcion valida (acepta "si", "sí", "s", "y", "yes" en cualquier mayuscula).
case "${CONFIRM,,}" in
    s|si|sí|y|yes) ;;                    # confirmado: seguimos
    *) echo "Cancelado."; exit 1 ;;      # cualquier otra cosa: salimos
esac

START_TIME=$(date +%s)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTDIR="recon_full_${TARGET}_${TIMESTAMP}"
mkdir -p "$OUTDIR"

echo -e "${BLUE}==============================================${NC}"
echo -e "${BLUE} FULL SCAN (lento)${NC}  -> Target: ${GREEN}${TARGET}${NC}"
echo -e "${BLUE} Resultados en:${NC} $OUTDIR"
echo -e "${YELLOW} Esto puede tardar bastante.${NC}"
echo -e "${BLUE}==============================================${NC}"

# ---------------------------------------------------------------------
# 1. Nmap completo
# ---------------------------------------------------------------------
# -Pn               no hace ping previo; asume que el host esta arriba.
# -T4               timing agresivo (igual de rapido que es posible sin
#                   pasar a -T5, que suele generar falsos negativos).
# -p-               escanea TODOS los puertos TCP (1-65535), a diferencia
#                   de quick_scan.sh que solo mira los 1000 mas comunes.
#                   Esto es lo que hace que este scan sea lento.
# -sV               deteccion de version de cada servicio encontrado.
# -sC               scripts NSE de la categoria "default" (chequeos
#                   seguros: banners, titulo de pagina web, etc).
# -O                intenta identificar el sistema operativo del target
#                   analizando particularidades de su stack TCP/IP.
# --script "vuln"   corre todos los scripts NSE de la categoria "vuln":
#                   cada uno chequea una vulnerabilidad conocida puntual
#                   (ej. si responde a Heartbleed, EternalBlue/MS17-010,
#                   etc.) y SOLO reporta si el target parece afectado;
#                   no explota nada, es deteccion.
# -oN / -oG         salida en formato legible y en formato grepable.
echo -e "\n${GREEN}[*]${NC} Nmap: los 65535 puertos, version (-sV), OS (-O), scripts default (-sC) y de vulnerabilidades (--script vuln)..."
nmap -Pn -T4 -p- -sV -sC -O --script "vuln" \
    -oN "$OUTDIR/nmap_full.txt" \
    -oG "$OUTDIR/nmap_full.grep" \
    "$TARGET"

# Extrae los numeros de puerto marcados como "open" en la salida normal.
# Cada puerto aparece en el archivo asi:  80/tcp   open  http    Apache ...
# El patron toma los digitos del inicio de linea (^\d+) solo si a
# continuacion viene "/tcp", espacios y "open" (lookahead de grep -P).
OPEN_PORTS=$(grep -oP '^\d+(?=/tcp\s+open\s)' "$OUTDIR/nmap_full.txt" 2>/dev/null)

if [[ -z "$OPEN_PORTS" ]]; then
    echo -e "${YELLOW}[!] No se detectaron puertos abiertos.${NC}"
    echo -e "${GREEN}[*] Listo.${NC} Resultados en: $OUTDIR"
    exit 0
fi

echo -e "${GREEN}[*]${NC} Puertos abiertos: $(echo "$OPEN_PORTS" | tr '\n' ' ')"

# ---------------------------------------------------------------------
# 2. SMB: si hay 139/445, enumeracion basica con enum4linux
# ---------------------------------------------------------------------
if grep -qx -e 139 -e 445 <<< "$OPEN_PORTS"; then
    if command -v enum4linux &>/dev/null; then
        # enum4linux -a: corre todas las enumeraciones basicas de SMB
        # (sesion nula, lista de usuarios, shares compartidos, politica
        # de contrasenas, info del dominio, etc). Es lectura/enumeracion,
        # no intenta crackear ni fuerza bruta de contrasenas.
        echo -e "\n${GREEN}[*]${NC} SMB detectado (139/445) -> enum4linux..."
        enum4linux -a "$TARGET" > "$OUTDIR/enum4linux.txt" 2>/dev/null
    else
        echo -e "${YELLOW}[!]${NC} Puertos SMB detectados pero enum4linux no esta instalado, se omite."
    fi
fi

# ---------------------------------------------------------------------
# 3. Si hay puertos web -> enumeracion web a fondo
# ---------------------------------------------------------------------
WEB_PORTS=()
for p in 80 443 8080 8443 8000 8888; do
    if grep -qx "$p" <<< "$OPEN_PORTS"; then
        WEB_PORTS+=("$p")
    fi
done

if [[ ${#WEB_PORTS[@]} -gt 0 ]]; then
    echo -e "\n${GREEN}[*]${NC} Puertos web detectados: ${WEB_PORTS[*]} -> enumeracion web completa"

    # Si esta instalado seclists usamos su wordlist mediana (mas cobertura,
    # mas lenta); si no, caemos a la wordlist "common" que trae dirb/gobuster.
    WORDLIST="/usr/share/wordlists/dirb/common.txt"
    BIGLIST="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
    [[ -f "$BIGLIST" ]] && WORDLIST="$BIGLIST"

    for p in "${WEB_PORTS[@]}"; do
        PROTO="http"
        [[ "$p" == "443" || "$p" == "8443" ]] && PROTO="https"
        URL="${PROTO}://${TARGET}:${p}"

        echo -e "\n${BLUE}--- Puerto $p ($URL) ---${NC}"

        if command -v whatweb &>/dev/null; then
            # -a 3: nivel de agresividad medio-alto para identificar mejor
            # CMS/framework/plugins (sigue siendo solo lectura de la pagina).
            echo -e "    ${GREEN}[*]${NC} WhatWeb (fingerprint agresivo, -a 3)..."
            whatweb -a 3 "$URL" > "$OUTDIR/whatweb_${p}.txt" 2>/dev/null
        else
            echo -e "    ${YELLOW}[!]${NC} whatweb no instalado, se omite."
        fi

        if command -v nikto &>/dev/null; then
            # Sin -Tuning: corre TODAS las categorias de chequeos de nikto
            # (incluye las que quick_scan.sh deja afuera), por eso tarda mas.
            # -timeout 15: un poco mas tolerante que el quick scan.
            echo -e "    ${GREEN}[*]${NC} Nikto (scan completo, todas las categorias)..."
            nikto -h "$URL" -timeout 15 -o "$OUTDIR/nikto_${p}.txt" &>/dev/null
        else
            echo -e "    ${YELLOW}[!]${NC} nikto no instalado, se omite."
        fi

        if command -v gobuster &>/dev/null; then
            if [[ -f "$WORDLIST" ]]; then
                # -x php,html,txt,bak,zip: ademas de nombres "pelados"
                # (ej /backup), tambien prueba esos nombres con cada una
                # de estas extensiones (ej /backup.zip, /config.bak).
                # -t 50: mas threads que el quick scan (mas cobertura).
                echo -e "    ${GREEN}[*]${NC} Gobuster dir (wordlist: $WORDLIST)..."
                gobuster dir -u "$URL" -w "$WORDLIST" -t 50 -x php,html,txt,bak,zip -q \
                    -o "$OUTDIR/gobuster_dir_${p}.txt" &>/dev/null
            else
                echo -e "    ${YELLOW}[!]${NC} No se encontro ninguna wordlist, se omite gobuster."
            fi
        else
            echo -e "    ${YELLOW}[!]${NC} gobuster no instalado, se omite."
        fi

        if [[ "$p" == "443" || "$p" == "8443" ]]; then
            if command -v sslscan &>/dev/null; then
                # sslscan: consulta que protocolos (SSLv3, TLS1.0, 1.2, 1.3)
                # y que cifrados soporta el servidor, mas los datos del
                # certificado (emisor, vencimiento, etc). Solo lectura.
                echo -e "    ${GREEN}[*]${NC} SSLscan (cifrados/certificado)..."
                sslscan "$TARGET:$p" > "$OUTDIR/sslscan_${p}.txt" 2>/dev/null
            else
                echo -e "    ${YELLOW}[!]${NC} sslscan no instalado, se omite (nmap_full.txt tambien puede tener ssl-cert/ssl-enum-ciphers via --script vuln)."
            fi
        fi
    done
else
    echo -e "${YELLOW}[*]${NC} No se detectaron puertos web comunes (80/443/8080/8443/8000/8888)."
fi

# ---------------------------------------------------------------------
# 4. Si hay puertos de bases de datos -> banner/version de solo lectura
# ---------------------------------------------------------------------
# Mapeo de puerto default -> motor de base de datos.
declare -A DB_NAMES=(
    [1433]="Microsoft SQL Server"
    [1521]="Oracle DB"
    [3306]="MySQL / MariaDB"
    [5432]="PostgreSQL"
    [5984]="CouchDB"
    [6379]="Redis"
    [9200]="Elasticsearch"
    [11211]="Memcached"
    [27017]="MongoDB"
)

DB_PORTS=()
for p in "${!DB_NAMES[@]}"; do
    if grep -qx "$p" <<< "$OPEN_PORTS"; then
        DB_PORTS+=("$p")
    fi
done

if [[ ${#DB_PORTS[@]} -gt 0 ]]; then
    echo -e "\n${GREEN}[*]${NC} Puertos de bases de datos detectados:"
    for p in "${DB_PORTS[@]}"; do
        echo -e "    - Puerto $p -> ${DB_NAMES[$p]}"
    done

    # Scripts NSE "*-info": se conectan y leen el banner/version que el
    # propio servicio entrega (lo mismo que haria un cliente normal al
    # conectarse), SIN enviar ninguna credencial ni intentar autenticarse.
    # Es el equivalente, para bases de datos, a lo que -sV ya hace para
    # web/ssh/ftp. A proposito no incluimos scripts de la categoria "auth"
    # que prueban usuario/clave (ej. mysql-empty-password): eso ya es un
    # paso de ataque activo, no de descubrimiento, y queda fuera de este
    # script.
    PORTS_CSV=$(IFS=,; echo "${DB_PORTS[*]}")
    echo -e "${GREEN}[*]${NC} Leyendo banner/version de los servicios de BD detectados (sin intentar login)..."
    nmap -Pn -sV -p "$PORTS_CSV" \
        --script "mysql-info,ms-sql-info,mongodb-info,redis-info" \
        -oN "$OUTDIR/db_info.txt" "$TARGET" &>/dev/null
    echo -e "${YELLOW}[!]${NC} Detalle en db_info.txt. No se probaron credenciales contra ninguna base."
fi

# ---------------------------------------------------------------------
# 5. Resumen final
# ---------------------------------------------------------------------
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

{
    echo "Resumen full_scan - Target: $TARGET"
    echo "Fecha: $(date)"
    echo "Duracion: ${ELAPSED}s"
    echo "Puertos abiertos: $(echo "$OPEN_PORTS" | tr '\n' ' ')"
    [[ ${#WEB_PORTS[@]} -gt 0 ]] && echo "Puertos web: ${WEB_PORTS[*]}"
    [[ ${#DB_PORTS[@]} -gt 0 ]] && echo "Puertos de BD: ${DB_PORTS[*]}"
} > "$OUTDIR/resumen.txt"

echo -e "\n${GREEN}[*] Listo en ${ELAPSED}s.${NC} Resultados en: ${BLUE}$OUTDIR${NC} (ver resumen.txt)"
echo -e "${GREEN}[*]${NC} Revisa especialmente nmap_full.txt (resultados de --script vuln por cada puerto)."
