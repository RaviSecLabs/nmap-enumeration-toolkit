#!/usr/bin/env bash
set -euo pipefail
if (( $# != 1 )); then echo "Usage: sudo bash $0 TARGET_IP"; exit 1; fi
TARGET="$1"
DIR="udp_enum_${TARGET}"
mkdir -p "$DIR"
SCRIPT_DIR=/usr/share/nmap/scripts
LOG="$DIR/commands.log"
: > "$LOG"
echo '[+] Discovering top 100 UDP ports (this may take a while)'
printf '%q ' nmap -sU -sV --version-light -Pn -n --top-ports 100 --open -oG "$DIR/udp_discovery.gnmap" -oN "$DIR/udp_discovery.txt" "$TARGET" >> "$LOG"; echo >> "$LOG"
nmap -sU -sV --version-light -Pn -n --top-ports 100 --open -oG "$DIR/udp_discovery.gnmap" -oN "$DIR/udp_discovery.txt" "$TARGET"
# Only confirmed open UDP ports are enumerated; open|filtered remains in discovery report.
mapfile -t PORTS < <(grep -oE '[0-9]+/open/udp' "$DIR/udp_discovery.gnmap" | cut -d/ -f1 | sort -nu || true)
if (( ${#PORTS[@]} == 0 )); then echo '[!] No confirmed open UDP ports. Review udp_discovery.txt for open|filtered results.'; exit 0; fi
prefix() {
 case "$1" in
  53) echo dns;; 67|68) echo dhcp;; 69) echo tftp;; 111) echo rpc;; 123) echo ntp;; 137) echo nbns;; 138) echo netbios;; 161|162) echo snmp;; 500|4500) echo ike;; 514) echo syslog;; 1900) echo upnp;; 2049) echo nfs;; 5353) echo dns;; *) echo udp;;
 esac
}
# Only run scripts explicitly tagged safe, excluding intrusive categories.
allowed() {
 local line
 line=$(grep -m1 -E '^[[:space:]]*categories[[:space:]]*=' "$1" || true)
 [[ "$line" == *'"safe"'* ]] || return 1
 for cat in intrusive brute dos exploit external fuzzer; do
   [[ "$line" != *"\"$cat\""* ]] || return 1
 done
}
for PORT in "${PORTS[@]}"; do
 NAME=$(prefix "$PORT")
 FILE="$DIR/${NAME}${PORT}_udp.txt"
 SCRIPTS=()
 if [[ "$NAME" != udp && -d "$SCRIPT_DIR" ]]; then
  while IFS= read -r -d '' F; do
   if allowed "$F"; then SCRIPTS+=("${F##*/}"); fi
  done < <(find "$SCRIPT_DIR" -maxdepth 1 -type f -name "${NAME}-*.nse" -print0 | sort -z)
 fi
 CMD=(nmap -sU -sV --version-light -Pn -n -v -p "$PORT" -oN "$FILE")
 if (( ${#SCRIPTS[@]} )); then
  LIST=$(IFS=,; echo "${SCRIPTS[*]}")
  CMD+=(--script "$LIST")
 fi
 CMD+=("$TARGET")
 printf '%q ' "${CMD[@]}" >> "$LOG"; echo >> "$LOG"
 echo "[+] UDP $PORT -> $FILE (${#SCRIPTS[@]} scripts)"
 "${CMD[@]}" || echo "[!] Scan for UDP $PORT returned an error; see above."
done
echo "[+] Saved reports to $DIR"

# Restore report ownership when launched through sudo.
if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]]; then
  chown -R -- "$SUDO_USER" "${OUT:-${DIR:-}}"
fi
