#!/bin/sh
# Accorde à RustShark les capacités de capture réseau, pour capturer sans sudo.
# Exécuté par dpkg (argument « configure ») et par rpm (argument 1 ou 2) après
# chaque installation ou mise à jour : remplacer le binaire efface ses capacités.
set -e

case "$1" in
    abort-*) exit 0 ;;
esac

BIN=/usr/bin/rustshark
if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw,cap_net_admin=eip "$BIN" \
        || echo "RustShark : setcap a échoué ; la capture demandera sudo." >&2
else
    echo "RustShark : setcap introuvable ; la capture demandera sudo." >&2
fi
exit 0
