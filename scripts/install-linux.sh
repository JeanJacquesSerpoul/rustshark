#!/usr/bin/env bash
# Installe RustShark sous Linux : prérequis, compilation et installation.
#
# Usage : ./scripts/install-linux.sh [options]
#
#   -y, --yes        répond « oui » à toutes les questions
#   --skip-deps      ne vérifie pas les dépendances système ni Rust
#   --build-only     compile le paquet sans l'installer
#   --no-setcap      n'autorise pas la capture sans sudo
#   --prefix DIR     dossier d'installation manuelle (défaut : /usr/local)
#   --uninstall      désinstalle RustShark
#   -h, --help       affiche cette aide
#
# Distributions prises en charge : Debian/Ubuntu (paquet .deb),
# Fedora/openSUSE (paquet .rpm), Arch Linux et dérivées (installation manuelle).
# À lancer en utilisateur normal : sudo n'est demandé que pour les étapes système.

set -euo pipefail

YES=0
SKIP_DEPS=0
BUILD_ONLY=0
NO_SETCAP=0
UNINSTALL=0
PREFIX=/usr/local

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
STATE_FILE="${XDG_DATA_HOME:-$HOME/.local/share}/rustshark/install.env"
# Réglages : identifiant actuel, puis ancien identifiant.
CONFIG_DIRS=(
    "${XDG_CONFIG_HOME:-$HOME/.config}/io.github.jeanjacquesserpoul.rustshark"
    "${XDG_CONFIG_HOME:-$HOME/.config}/com.rustshark.app"
)

if [ -t 1 ]; then
    C_STEP=$'\e[1;36m'; C_OK=$'\e[32m'; C_WARN=$'\e[33m'; C_ERR=$'\e[1;31m'; C_END=$'\e[0m'
else
    C_STEP=""; C_OK=""; C_WARN=""; C_ERR=""; C_END=""
fi

step() { printf '\n%s==> %s%s\n' "$C_STEP" "$1" "$C_END"; }
ok()   { printf '    %s[OK]%s %s\n' "$C_OK" "$C_END" "$1"; }
info() { printf '    %s\n' "$1"; }
warn() { printf '    %s[!]%s %s\n' "$C_WARN" "$C_END" "$1"; }
die()  { printf '\n%s[ERREUR]%s %s\n' "$C_ERR" "$C_END" "$1" >&2; exit 1; }

confirm() {
    [ "$YES" -eq 1 ] && return 0
    local answer
    read -r -p "    $1 [O/n] " answer || answer=""
    [[ -z "$answer" || "$answer" =~ ^([oOyY]|oui|yes)$ ]]
}

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
    case "$1" in
        -y|--yes) YES=1 ;;
        --skip-deps) SKIP_DEPS=1 ;;
        --build-only) BUILD_ONLY=1 ;;
        --no-setcap) NO_SETCAP=1 ;;
        --prefix) shift; PREFIX="${1:?--prefix attend un dossier}" ;;
        --uninstall) UNINSTALL=1 ;;
        -h|--help) usage ;;
        *) die "Option inconnue : $1 (voir --help)" ;;
    esac
    shift
done

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
    [ -n "${SUDO_USER:-}" ] && warn "Lancé avec sudo : Rust sera installé pour root. Préférez un utilisateur normal."
else
    command -v sudo >/dev/null || die "sudo est requis pour installer les dépendances système."
    SUDO="sudo"
fi

# ---------------------------------------------------------------------------
# Détection de la distribution
# ---------------------------------------------------------------------------

PM=""
if command -v apt-get >/dev/null; then PM=apt
elif command -v dnf >/dev/null; then PM=dnf
elif command -v pacman >/dev/null; then PM=pacman
elif command -v zypper >/dev/null; then PM=zypper
fi

case "$PM" in
    apt) BUNDLE=deb ;;
    dnf|zypper) BUNDLE=rpm ;;
    *) BUNDLE="" ;;
esac

# ---------------------------------------------------------------------------
# Dépendances
# ---------------------------------------------------------------------------

install_system_deps() {
    step "Dépendances système (gestionnaire : ${PM:-inconnu})"
    case "$PM" in
        apt)
            $SUDO apt-get update -q
            $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
                build-essential pkg-config curl wget file ca-certificates \
                libwebkit2gtk-4.1-dev libxdo-dev libssl-dev \
                libayatana-appindicator3-dev librsvg2-dev \
                libpcap-dev libcap2-bin
            ;;
        dnf)
            $SUDO dnf install -y \
                gcc gcc-c++ make pkgconf-pkg-config curl wget file rpm-build \
                webkit2gtk4.1-devel openssl-devel libxdo-devel \
                libappindicator-gtk3-devel librsvg2-devel \
                libpcap-devel libcap
            ;;
        pacman)
            $SUDO pacman -Syu --needed --noconfirm \
                base-devel curl wget file openssl \
                webkit2gtk-4.1 xdotool appmenu-gtk-module libappindicator-gtk3 librsvg \
                libpcap libcap
            ;;
        zypper)
            $SUDO zypper -n install -t pattern devel_basis
            $SUDO zypper -n install \
                curl wget file webkit2gtk3-devel libopenssl-devel \
                libappindicator3-1 librsvg-devel libpcap-devel libcap-progs
            ;;
        *)
            warn "Distribution non reconnue : installez vous-même les dépendances Tauri"
            warn "(https://v2.tauri.app/start/prerequisites/#linux) et libpcap."
            confirm "Continuer quand même ?" || exit 1
            ;;
    esac
    ok "Dépendances système"
}

load_cargo_env() {
    # shellcheck disable=SC1091
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
    return 0
}

install_rust_tools() {
    step "Outils Rust"
    load_cargo_env
    if command -v cargo >/dev/null; then
        ok "Rust ($(rustc --version))"
    else
        confirm "Rust est absent. L'installer avec rustup (dans ~/.cargo) ?" || die "Rust est requis."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
        load_cargo_env
        ok "Rust installé"
    fi

    if rustup target list --installed | grep -qx wasm32-unknown-unknown; then
        ok "Cible wasm32-unknown-unknown"
    else
        rustup target add wasm32-unknown-unknown
        ok "Cible wasm32-unknown-unknown ajoutée"
    fi

    if command -v trunk >/dev/null; then
        ok "Trunk ($(trunk --version))"
    else
        info "Installation de Trunk (quelques minutes)…"
        cargo install trunk --locked
        ok "Trunk installé"
    fi

    if cargo tauri --version 2>/dev/null | grep -q ' 2\.'; then
        ok "CLI Tauri ($(cargo tauri --version))"
    else
        info "Installation de la CLI Tauri 2 (quelques minutes)…"
        cargo install tauri-cli --version '^2' --locked
        ok "CLI Tauri installée"
    fi
}

check_keyring() {
    # Les clés API sont rangées via le Secret Service (GNOME Keyring, KWallet…).
    if command -v gnome-keyring-daemon >/dev/null || command -v kwalletd5 >/dev/null \
        || command -v kwalletd6 >/dev/null || command -v keepassxc >/dev/null; then
        ok "Trousseau Secret Service disponible"
    else
        warn "Aucun trousseau Secret Service détecté (gnome-keyring, KWallet, KeePassXC…)."
        warn "RustShark fonctionnera, mais ne pourra pas enregistrer de clé API pour l'IA."
    fi
}

# ---------------------------------------------------------------------------
# Compilation et installation
# ---------------------------------------------------------------------------

build_app() {
    step "Compilation de RustShark (mode release, plusieurs minutes la première fois)"
    load_cargo_env
    # Trunk refuse NO_COLOR=1 (il attend true/false).
    if [ -n "${NO_COLOR:-}" ]; then export NO_COLOR=true; fi
    cd "$ROOT"
    if [ -n "$BUNDLE" ]; then
        cargo tauri build --bundles "$BUNDLE"
    else
        cargo tauri build --no-bundle
    fi
    ok "Compilation terminée"
}

# Fichier le plus récent parmi ceux donnés (noms produits par Tauri, sans espaces).
# shellcheck disable=SC2012
latest() { ls -t "$@" 2>/dev/null | head -n 1; }

write_state() {
    mkdir -p "$(dirname "$STATE_FILE")"
    {
        printf 'METHOD=%q\n' "$1"
        printf 'PKG_NAME=%q\n' "$2"
        printf 'BIN=%q\n' "$3"
        printf 'PREFIX=%q\n' "$PREFIX"
    } > "$STATE_FILE"
}

install_manual() {
    local bin="$PREFIX/bin/rustshark"
    $SUDO install -Dm755 "$TARGET_DIR/release/rustshark" "$bin"
    $SUDO install -Dm644 "$ROOT/src-tauri/icons/128x128.png" "$PREFIX/share/icons/hicolor/128x128/apps/rustshark.png"
    $SUDO install -Dm644 /dev/stdin "$PREFIX/share/applications/rustshark.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=RustShark
GenericName=Analyseur réseau
Comment=Analyseur de trafic réseau pour tous, assisté par IA
Exec=$bin
Icon=rustshark
Terminal=false
Categories=Network;Monitor;Utility;
EOF
    if command -v update-desktop-database >/dev/null; then
        $SUDO update-desktop-database -q "$PREFIX/share/applications" || true
    fi
    INSTALLED_BIN="$bin"
    write_state manual "" "$bin"
}

install_app() {
    local pkg=""
    case "$BUNDLE" in
        deb) pkg="$(latest "$TARGET_DIR"/release/bundle/deb/*.deb)" ;;
        rpm) pkg="$(latest "$TARGET_DIR"/release/bundle/rpm/*.rpm)" ;;
    esac
    if [ "$BUILD_ONLY" -eq 1 ]; then
        step "Compilation terminée, rien n'a été installé"
        ok "${pkg:-$TARGET_DIR/release/rustshark}"
        exit 0
    fi

    step "Installation"
    INSTALLED_BIN=""
    case "$BUNDLE" in
        deb)
            [ -n "$pkg" ] || die "Paquet .deb introuvable."
            $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$pkg"
            write_state deb "$(dpkg-deb -f "$pkg" Package)" /usr/bin/rustshark
            INSTALLED_BIN=/usr/bin/rustshark
            ;;
        rpm)
            [ -n "$pkg" ] || die "Paquet .rpm introuvable."
            if [ "$PM" = dnf ]; then
                $SUDO dnf install -y "$pkg"
            else
                $SUDO zypper -n --no-gpg-checks install "$pkg"
            fi
            write_state rpm "$(rpm -qp --qf '%{NAME}' "$pkg")" /usr/bin/rustshark
            INSTALLED_BIN=/usr/bin/rustshark
            ;;
        *)
            install_manual
            ;;
    esac
    [ -x "$INSTALLED_BIN" ] || die "Binaire introuvable après installation : $INSTALLED_BIN"
    ok "RustShark installé : $INSTALLED_BIN"
}

grant_capture() {
    [ "$NO_SETCAP" -eq 1 ] && return 0
    step "Autorisation de capture réseau"
    info "La capture nécessite les capacités CAP_NET_RAW et CAP_NET_ADMIN."
    info "Les accorder au programme permet de capturer sans lancer RustShark avec sudo"
    info "(tout utilisateur de cette machine pourra alors capturer le trafic)."
    if confirm "Accorder ces capacités à $INSTALLED_BIN ?"; then
        $SUDO setcap cap_net_raw,cap_net_admin=eip "$INSTALLED_BIN"
        # getcap est dans /usr/sbin, absent du PATH des utilisateurs sous Debian.
        local caps
        caps="$( (getcap "$INSTALLED_BIN" || /usr/sbin/getcap "$INSTALLED_BIN" || /sbin/getcap "$INSTALLED_BIN") 2>/dev/null | head -n 1)"
        ok "Capacités accordées (${caps:-vérification impossible})"
    else
        warn "Sans cela, lancez RustShark avec sudo pour capturer en direct."
    fi
}

# ---------------------------------------------------------------------------
# Désinstallation
# ---------------------------------------------------------------------------

uninstall_app() {
    step "Désinstallation de RustShark"
    local METHOD="" PKG_NAME=""
    if [ -f "$STATE_FILE" ]; then
        # shellcheck disable=SC1090
        . "$STATE_FILE"
    elif command -v dpkg-query >/dev/null && dpkg-query -W -f='${Package}\n' 2>/dev/null | grep -qx rust-shark; then
        METHOD=deb; PKG_NAME=rust-shark
    elif command -v rpm >/dev/null && rpm -q rust-shark >/dev/null 2>&1; then
        METHOD=rpm; PKG_NAME=rust-shark
    elif [ -x "$PREFIX/bin/rustshark" ]; then
        METHOD=manual
    fi

    case "$METHOD" in
        deb) $SUDO apt-get remove -y "$PKG_NAME" ;;
        rpm)
            if command -v dnf >/dev/null; then $SUDO dnf remove -y "$PKG_NAME"; else $SUDO zypper -n remove "$PKG_NAME"; fi
            ;;
        manual)
            $SUDO rm -f "$PREFIX/bin/rustshark" \
                "$PREFIX/share/applications/rustshark.desktop" \
                "$PREFIX/share/icons/hicolor/128x128/apps/rustshark.png"
            ;;
        *) warn "Aucune installation de RustShark trouvée." ;;
    esac
    [ -n "$METHOD" ] && ok "RustShark désinstallé"
    rm -f "$STATE_FILE"

    local existing=() dir
    for dir in "${CONFIG_DIRS[@]}"; do
        [ -d "$dir" ] && existing+=("$dir")
    done
    if [ "${#existing[@]}" -gt 0 ] && confirm "Supprimer aussi les réglages et profils d'analyse ?"; then
        rm -rf "${existing[@]}"
        ok "Réglages supprimés"
    fi
    if command -v secret-tool >/dev/null && confirm "Effacer les clés API RustShark du trousseau ?"; then
        secret-tool clear service rustshark 2>/dev/null || true
        ok "Clés API effacées"
    fi
}

# ---------------------------------------------------------------------------

printf 'RustShark — installation Linux\n'
if [ "$UNINSTALL" -eq 1 ]; then
    uninstall_app
    exit 0
fi
if [ "$SKIP_DEPS" -eq 0 ]; then
    install_system_deps
    install_rust_tools
fi
check_keyring
build_app
install_app
grant_capture
printf '\n%sTerminé !%s Lancez RustShark depuis le menu des applications ou avec : %s\n' "$C_OK" "$C_END" "$INSTALLED_BIN"
