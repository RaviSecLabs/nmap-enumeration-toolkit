#!/usr/bin/env bash
set -euo pipefail
MODE="all"
TARGET="${1:-}"
[[ -n "$TARGET" ]] || { echo "Usage: sudo bash $(basename "$0") TARGET_IP [--skip-discovery]"; exit 1; }
[[ -d /usr/share/nmap/scripts ]] || { echo 'NSE scripts folder missing'; exit 1; }
OUT="enum_${MODE}_${TARGET}"
mkdir -p "$OUT"
if [[ "${2:-}" != "--skip-discovery" ]]; then
  echo "[+] Discovering TCP ports..."
  nmap -sS -Pn -n -p- --open -oG "$OUT/discovery.gnmap" -oN "$OUT/discovery.txt" "$TARGET"
else
  SOURCE="enum_${TARGET}/discovery.gnmap"
  [[ -f "$SOURCE" ]] || { echo "Missing $SOURCE; run without --skip-discovery"; exit 1; }
  cp "$SOURCE" "$OUT/discovery.gnmap"
fi
mapfile -t PORTS < <(grep -oE '[0-9]+/open/tcp' "$OUT/discovery.gnmap" | cut -d/ -f1 | sort -nu || true)
((${#PORTS[@]})) || { echo 'No open TCP ports detected'; exit 0; }
service_for_port() {
 case "$1" in
  21) echo ftp;; 22) echo ssh;; 23) echo telnet;; 25|465|587) echo smtp;;
  53) echo dns;; 80|8000|8080|8180|8888) echo http;; 111) echo rpc;;
  139|445) echo smb;; 443|8443) echo http;; 3306) echo mysql;;
  5432) echo pgsql;; 5900|5901) echo vnc;; 2049) echo nfs;;
  110|995) echo pop3;; 143|993) echo imap;; 389|636) echo ldap;;
  6379) echo redis;; 27017) echo mongodb;; 3389) echo rdp;;
  6667|6697) echo irc;; 512|513|514) echo rservices;;
  *) echo tcp;;
 esac
}
# A safe category is a useful screening criterion, not a guarantee of harmlessness.
is_safe() {
 local metadata
 metadata=$(grep -m1 -E '^[[:space:]]*categories[[:space:]]*=' "$1" || true)
 [[ "$metadata" == *'"safe"'* ]] || return 1
 for blocked in intrusive brute dos exploit external fuzzer; do
   [[ "$metadata" != *"\"$blocked\""* ]] || return 1
 done
}
if [[ "$MODE" == all ]]; then
  echo 'WARNING: ALL mode may run password guessing, exploitation, DoS, and intrusive checks.'
  echo 'Only use on an isolated lab target you own or are explicitly authorised to test.'
  read -r -p 'Type RUN-ALL to continue: ' CONFIRM
  [[ "$CONFIRM" == RUN-ALL ]] || { echo 'Cancelled'; exit 1; }
fi
printf 'port\tservice\tavailable\tselected\n' > "$OUT/script_inventory.tsv"
: > "$OUT/commands.log"
for PORT in "${PORTS[@]}"; do
 PREFIX=$(service_for_port "$PORT")
 LABEL="$PREFIX$PORT"
 AVAILABLE=(); SELECTED=()
 if [[ "$PREFIX" != tcp ]]; then
   while IFS= read -r -d '' FILE; do
     NAME="${FILE##*/}"
     AVAILABLE+=("$NAME")
     if [[ "$MODE" == all ]] || is_safe "$FILE"; then SELECTED+=("$NAME"); fi
   done < <(find /usr/share/nmap/scripts -maxdepth 1 -type f -name "$PREFIX-*.nse" -print0 | sort -z)
 fi
 printf '%s\n' "${AVAILABLE[@]}" > "$OUT/${LABEL}_available_scripts.txt"
 printf '%s\n' "${SELECTED[@]}" > "$OUT/${LABEL}_selected_scripts.txt"
 printf '%s\t%s\t%d\t%d\n' "$PORT" "$PREFIX" "${#AVAILABLE[@]}" "${#SELECTED[@]}" >> "$OUT/script_inventory.tsv"
 CMD=(nmap -sV -Pn -n -v -p "$PORT" -oN "$OUT/$LABEL.txt")
 if ((${#SELECTED[@]})); then
   SCRIPTLIST=$(IFS=,; echo "${SELECTED[*]}")
   CMD+=(--script "$SCRIPTLIST")
 fi
 CMD+=("$TARGET")
 printf -v CMDLINE '%q ' "${CMD[@]}"
 echo "$CMDLINE" >> "$OUT/commands.log"
 echo "[+] $PORT/$PREFIX: ${#SELECTED[@]} of ${#AVAILABLE[@]} matching scripts; saving $OUT/$LABEL.txt"
 "${CMD[@]}" || echo "[!] Nmap reported an error for port $PORT; continuing" >&2
done
echo "[+] Done: $OUT"
echo 'Note: A selected script may produce no output or skip itself based on its run conditions.'

# Restore report ownership when launched through sudo.
if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]]; then
  chown -R -- "$SUDO_USER" "${OUT:-${DIR:-}}"
fi
