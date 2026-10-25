# RustShark 🦈

**Analyseur de trafic réseau pour tous** — l'équivalent de Wireshark, avec une
interface pensée pour les débutants, des explications en langage simple
(français / anglais) et un assistant IA (DeepSeek ou OpenRouter, avec votre
propre clé API).

Construit avec **Rust**, **Tauri 2** et **Leptos 0.8** (WebAssembly).

---

## Fonctionnalités

### Capture et analyse
- **Capture en direct** via Npcap (Windows) ou libpcap (Linux, macOS), chargé
  dynamiquement : l'application démarre même sans Npcap et explique comment
  l'installer.
- **Choix guidé de l'interface** : noms lisibles (« Wi-Fi », « Ethernet »),
  interface recommandée, et une mesure d'activité de 1,5 s qui montre où il y a du trafic.
- **Dissection intégrée** : Ethernet, VLAN, ARP, IPv4, IPv6, TCP, UDP, ICMP/ICMPv6,
  IGMP, DNS, mDNS, LLMNR, NetBIOS, DHCP, HTTP, TLS (SNI, ALPN, version),
  QUIC, NTP, SSDP, SSH, FTP, SMTP, POP3, IMAP, SMB, RDP, STUN, LLDP, STP, EAPOL…
- **Ouverture et enregistrement** de fichiers `.pcap` / `.pcapng` (glisser-déposer accepté).
- **Liste virtualisée** : des centaines de milliers de paquets restent fluides.

### Ergonomie pour débutants
- **Mode Simple** : colonnes « De / Vers / Type / Ce qui se passe », avec des
  couleurs par famille (web sécurisé, DNS, réseau local, problèmes…).
- **Mode Expert** : colonnes techniques comme dans Wireshark.
- **Explication de chaque paquet** en langage simple, avec des conseils
  (« 🔒 chiffré », « ⚠️ non chiffré », « 🌍 transite par Internet »…), l'arbre
  détaillé des couches (bulles d'aide sur les champs) et les octets bruts surlignés.
- **Noms plutôt qu'adresses** : appris passivement (DNS, SNI, HTTP, DHCP),
  sans aucune requête supplémentaire.
- **Filtres rapides** en un clic : Sites visités, Chiffré, Non chiffré,
  Appareils locaux, Internet, Problèmes, Sans bruit de fond.
- **Tableau de bord** : volumes, répartition du trafic, activité dans le temps,
  sites contactés, appareils actifs, noms DNS, conversations.
- **Carte des flux** : qui parle à qui, en trois colonnes (réseau local, cet
  ordinateur, Internet). L'épaisseur des traits suit la quantité de données,
  leur couleur le chiffrement ; un clic sur un appareil ou un flux en donne
  le détail et ouvre les paquets correspondants.
- **Détection automatique** : mots de passe en clair, scans de ports,
  usurpation ARP, chiffrement obsolète, sites HTTP, erreurs DNS, connexions refusées.
- **Aide intégrée** : premiers pas, glossaire, référence des filtres, raccourcis.
- **Thèmes clair et sombre**, interface **bilingue FR/EN** (changement à chaud).

### Mon réseau
Un onglet **Mon réseau**, accessible aussi depuis l'accueil sans lancer de capture :
- **Appareils** : balayage ARP du réseau local, puis identification par mDNS,
  UPnP, NetBIOS et DNS inverse : nom, fabricant (registre IEEE intégré), modèle,
  type deviné (box, téléphone, TV, enceinte, imprimante, NAS…), services annoncés
  (AirPlay, Google Cast…), adresses MAC privées. Analyse des ports ouverts d'un
  appareil, et raccourcis pour voir ou capturer son trafic.
- **Réseau** : Wi-Fi (nom, signal, bande et canal, norme, chiffrement), adresses
  IPv4/IPv6, masque, box, DHCP, serveurs DNS, vitesse de liaison, MTU.
- **Sécurité** : note sur 100 et conseils — chiffrement du Wi-Fi, services ouverts
  sur la box (Telnet, FTP, SMB…), UPnP actif, serveurs DNS, usurpation ARP,
  appareils non identifiés, plus les alertes de la capture en cours.
- **Internet** : adresse publique, opérateur, IPv6, temps de réponse (box,
  Cloudflare, Google, Quad9, serveurs DNS) et test de débit (téléchargement,
  envoi, latence en charge).

Les onglets Appareils, Réseau et Sécurité ne sortent jamais du réseau local.
L'onglet Internet contacte ipinfo.io et Cloudflare, uniquement sur clic.
Diagnostic en ligne de commande : `rustshark --network`.

### Assistant IA

> **Clé API personnelle requise (BYOK, *Bring Your Own Key*)** : RustShark
> n'inclut aucune clé ni abonnement. Pour utiliser l'assistant, créez une clé
> chez [DeepSeek](https://platform.deepseek.com/api_keys) ou
> [OpenRouter](https://openrouter.ai/keys), puis saisissez-la dans
> **Réglages → Intelligence artificielle**. L'usage est facturé par ce
> fournisseur, sur votre compte (OpenRouter propose aussi des modèles gratuits).
> Sans clé, tout le reste de l'application fonctionne normalement.

- **Analyse en conversation** : « Résume ce qui se passe », « Y a-t-il quelque
  chose de suspect ? »… sur toute la capture, les paquets filtrés ou un seul paquet.
  Les réponses arrivent en streaming ; les filtres proposés sont **cliquables**.
- **Générateur de configuration** : décrivez votre objectif (« voir quels sites
  mon PC contacte en arrière-plan ») ; l'IA produit un filtre de capture (BPF)
  et un filtre d'affichage, tous deux validés, les points à surveiller et la
  question à poser à la fin. Les configurations s'enregistrent comme **profils**.
- **Fournisseurs** : DeepSeek (`deepseek-chat`, `deepseek-reasoner`) et
  OpenRouter (des centaines de modèles, dont des gratuits ; liste chargée depuis l'API).
- **Confidentialité** : seul un résumé (statistiques, noms, extrait de paquets)
  est envoyé, uniquement quand vous posez une question. Les IP privées et les
  adresses MAC sont masquées par défaut (`LAN-1`, `MAC-1`…).

### Clés API dans le trousseau sécurisé
Les clés ne sont **jamais** écrites dans un fichier ni renvoyées à l'interface :

| Système | Stockage |
|---|---|
| Windows | Gestionnaire d'identification Windows |
| macOS | Trousseau (Keychain) |
| Linux | Secret Service (GNOME Keyring, KWallet…) |

Dans **Réglages → Intelligence artificielle**, chaque clé peut être supprimée
individuellement, et le bouton **« Tout effacer »** (confirmation en deux clics)
retire en une fois toutes les clés RustShark du trousseau.

---

## Installateurs précompilés

Chaque compilation de la branche `main` produit les installateurs dans l'onglet
[Actions](https://github.com/JeanJacquesSerpoul/rustshark/actions) du dépôt
(artefacts `rustshark-Windows`, `rustshark-Linux`, `rustshark-macOS`) :
`.msi` / `.exe` pour Windows, `.deb` / `.rpm` / `.AppImage` pour Linux,
`.dmg` pour macOS (Apple Silicon).

Ils ne sont **pas signés** : Windows (SmartScreen) et macOS (Gatekeeper)
affichent un avertissement à la première ouverture. Sous macOS, passez par
*Réglages → Confidentialité et sécurité → Ouvrir quand même*.

### Vérifier un téléchargement

Chaque artefact contient un fichier `SHA256SUMS-<système>.txt` :

```bash
sha256sum -c SHA256SUMS-Linux.txt                 # Linux
shasum -a 256 -c SHA256SUMS-macOS.txt             # macOS
```

```powershell
Get-FileHash .\RustShark_0.1.0_x64-setup.exe      # Windows : comparer avec le fichier
```

Chaque fichier porte aussi une **attestation de provenance** GitHub, qui prouve
qu'il a été compilé par la CI de ce dépôt à partir de son code source :

```bash
gh attestation verify RustShark_0.1.0_amd64.deb -R JeanJacquesSerpoul/rustshark
```

## Installation rapide (scripts)

Les scripts du dossier `scripts/` vérifient et installent les prérequis,
compilent l'application et l'installent.

### Windows

Depuis une console PowerShell, à la racine du projet :

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install-windows.ps1
```

Le script installe si besoin (via `winget`, après confirmation) les outils C++
de Visual Studio et Rust, puis la cible WebAssembly, Trunk et la CLI Tauri. Il
propose ensuite de télécharger **Npcap** : l'installateur est vérifié (signature
Insecure.Com LLC) puis lancé en mode graphique, car la licence gratuite de Npcap
interdit l'installation silencieuse. Enfin, il compile l'installateur NSIS de
RustShark et l'exécute.

| Option | Effet |
|---|---|
| `-Yes` | répond « oui » à tout ; installation de RustShark silencieuse |
| `-SkipPrereqs` | ne vérifie pas les prérequis |
| `-BuildOnly` | produit `target\release\bundle\nsis\*-setup.exe` sans l'installer |
| `-Portable` | pas d'installateur : copie dans `%LOCALAPPDATA%\Programs\RustShark` + raccourci menu Démarrer |
| `-Uninstall` | désinstalle ; propose d'effacer réglages et clés API |

### Linux

En utilisateur normal (sudo n'est demandé que pour les étapes système) :

```bash
./scripts/install-linux.sh
```

| Distribution | Résultat |
|---|---|
| Debian, Ubuntu, Mint… (`apt`) | paquet `.deb` installé |
| Fedora (`dnf`), openSUSE (`zypper`) | paquet `.rpm` installé |
| Arch et dérivées (`pacman`), autres | binaire + raccourci dans `/usr/local` (modifiable avec `--prefix`) |

Le script installe les dépendances (WebKitGTK, libpcap…), Rust via rustup,
Trunk et la CLI Tauri, compile, installe, puis propose d'accorder les capacités
`cap_net_raw,cap_net_admin` au programme pour capturer sans `sudo`.

| Option | Effet |
|---|---|
| `-y`, `--yes` | répond « oui » à tout |
| `--skip-deps` | ne vérifie pas les dépendances |
| `--build-only` | produit le paquet sans l'installer |
| `--no-setcap` | n'accorde pas les capacités de capture |
| `--prefix DIR` | dossier de l'installation manuelle |
| `--uninstall` | désinstalle ; propose d'effacer réglages et clés API |

## Prérequis (installation manuelle)

- Rust stable (≥ 1.85) et la cible WebAssembly :
  ```bash
  rustup target add wasm32-unknown-unknown
  ```
- [Trunk](https://trunkrs.dev) et la CLI Tauri :
  ```bash
  cargo install trunk tauri-cli --locked
  ```
- **Bibliothèque de capture** :
  - **Windows** : [Npcap](https://npcap.com/#download) (options par défaut).
  - **Linux** : `libpcap` (`sudo apt install libpcap0.8`) ainsi que les
    [dépendances Tauri](https://v2.tauri.app/start/prerequisites/#linux)
    (webkit2gtk, libssl…). Pour capturer sans `sudo` :
    ```bash
    sudo setcap cap_net_raw,cap_net_admin=eip target/release/rustshark
    ```
  - **macOS** : libpcap est fourni ; si la capture est refusée, installez
    ChmodBPF (livré avec Wireshark) ou lancez avec `sudo`.

## Lancer et construire

```bash
cargo tauri dev
```

```bash
cargo tauri build
```

Les installateurs sont produits dans `target/release/bundle/`.

> Si la variable d'environnement `NO_COLOR=1` est définie, Trunk refuse de
> démarrer (`invalid value '1' for '--no-color'`) : utilisez `NO_COLOR=true`
> ou supprimez la variable.

### Diagnostic en ligne de commande

```bash
cargo run -p rustshark -- --selftest 5
```

Affiche la version de libpcap, les interfaces détectées, puis capture 5 secondes
sur l'interface recommandée et imprime les paquets avec leur résumé en français.

### Tests

```bash
cargo test -p rustshark-shared -p rustshark
```

---

## Utilisation avec Claude (serveur MCP)

RustShark peut servir d'outil à Claude grâce au
[Model Context Protocol](https://modelcontextprotocol.io). Lancé avec `--mcp`,
le même exécutable fonctionne sans fenêtre et dialogue avec Claude sur
l'entrée et la sortie standard. On peut alors demander par exemple :

> « Capture 60 secondes de trafic puis fais-moi une représentation graphique
> des flux de mon réseau, en mettant en évidence la quantité de données échangées. »

Claude enchaîne alors seul la capture, la récupération du graphe des flux et
le dessin.

### Principe : qui lance le serveur ?

Vous n'avez **rien à lancer vous-même**. Une fois RustShark déclaré dans
Claude, c'est Claude qui démarre `rustshark --mcp` en arrière-plan (à son
ouverture ou au début d'une session Claude Code), lui parle par l'entrée et la
sortie standard, puis le ferme en quittant.

- Pas de fenêtre, pas de port réseau ouvert : seul Claude peut lui parler.
- La fenêtre de RustShark n'a pas besoin d'être ouverte ; si elle l'est, les
  deux fonctionnent indépendamment (le serveur fait ses propres captures).
- Le serveur ne garde qu'une capture en mémoire : une nouvelle capture (ou
  l'ouverture d'un fichier) remplace la précédente.

### Outils proposés

| Outil | Rôle |
|---|---|
| `list_interfaces` | connexions réseau disponibles, avec celle recommandée |
| `capture` | capture pendant N secondes (120 s au maximum), filtre BPF optionnel |
| `start_capture` / `stop_capture` / `capture_status` | capture longue en arrière-plan (jusqu'à 1 h) |
| `open_capture` | ouvre un fichier `.pcap` / `.pcapng` |
| `get_flows` | graphe « qui parle à qui » : appareils, volumes, flux, part chiffrée |
| `get_stats` | protocoles, familles de trafic, sites contactés, chronologie, alertes |
| `list_packets` / `packet_detail` | paquets filtrés et détail expliqué |

### 1. Installer RustShark

Installez l'application normalement (voir [Installation rapide](#installation-rapide-scripts)),
avec **Npcap** sous Windows ou les capacités de capture sous Linux : le serveur
MCP utilise le même exécutable et les mêmes droits.

Chemin de l'exécutable selon l'installation :

| Installation | Chemin |
|---|---|
| Installateur Windows | `%LOCALAPPDATA%\RustShark\rustshark.exe` |
| Windows portable (`-Portable`) | `%LOCALAPPDATA%\Programs\RustShark\RustShark.exe` |
| Paquet Linux (`.deb`, `.rpm`) | `/usr/bin/rustshark` |
| Linux manuelle | `/usr/local/bin/rustshark` |
| Compilé depuis les sources | `target/release/rustshark` (`.exe` sous Windows) |

### 2. Déclarer le serveur dans Claude

**Claude Desktop** : ouvrez Réglages → Développeur → Modifier la configuration
(fichier `claude_desktop_config.json`, dans `%APPDATA%\Claude\` sous Windows,
`~/Library/Application Support/Claude/` sous macOS) et ajoutez :

```json
{
  "mcpServers": {
    "rustshark": {
      "command": "C:\\Users\\<vous>\\AppData\\Local\\RustShark\\rustshark.exe",
      "args": ["--mcp"]
    }
  }
}
```

Dans le JSON, les `\` des chemins Windows doivent être doublés. Si le fichier
contient déjà une section `mcpServers`, ajoutez seulement le bloc `"rustshark"`
à l'intérieur. **Quittez complètement** Claude Desktop (icône de la zone de
notification → Quitter) puis relancez-le.

**Claude Code** : une seule commande, valable pour tous vos projets
(`--scope user`) :

```powershell
claude mcp add --scope user rustshark -- "C:\Users\<vous>\AppData\Local\RustShark\rustshark.exe" --mcp
```

```bash
claude mcp add --scope user rustshark -- /usr/bin/rustshark --mcp
```

Les options du serveur se placent après `--mcp`, par exemple
`... rustshark.exe --mcp --lang en`. Ouvrez ensuite une nouvelle session
Claude Code.

### 3. Vérifier que le serveur fonctionne

- **Claude Code** : `claude mcp list` doit afficher `rustshark: ... ✔ Connected`.
  Dans une session, la commande `/mcp` montre l'état du serveur et ses outils.
- **Claude Desktop** : dans Réglages → Développeur, `rustshark` doit apparaître
  avec l'état *running* ; ses outils sont listés dans le menu des outils d'une
  conversation.
- **Test manuel**, sans Claude : on envoie deux requêtes au serveur, qui répond
  puis s'arrête de lui-même à la fin de l'entrée. Le message
  `rustshark MCP server ready` s'affiche sur la sortie d'erreur.

  ```bash
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | /usr/bin/rustshark --mcp
  ```

  Sous Windows, la même commande fonctionne dans Git Bash avec le chemin de
  `rustshark.exe`.

### 4. Utiliser RustShark depuis Claude

Parlez simplement à Claude ; il choisit les outils lui-même. Exemples :

| Demande | Ce que fait Claude |
|---|---|
| « Quelles connexions réseau puis-je capturer ? » | `list_interfaces` |
| « Capture 30 secondes sur le Wi-Fi et fais-moi une image des flux » | `capture` puis `get_flows`, puis dessine |
| « Y a-t-il quelque chose de suspect ? » | `get_stats` (alertes) puis `list_packets` |
| « Détaille le flux vers chatgpt.com » | `get_stats` / `list_packets` avec un filtre |
| « Lance une capture longue, je te dis quand arrêter » | `start_capture`, puis `stop_capture` à votre demande |
| « Analyse le fichier C:\captures\maison.pcapng » | `open_capture` puis `get_stats` |
| « Ne garde que le DNS » | filtre de capture BPF `port 53` |

Claude demande votre accord avant d'utiliser un outil. Dans Claude Code,
choisissez « toujours autoriser » pour ne plus être sollicité, ou ajoutez
`mcp__rustshark` à la liste `permissions.allow` de vos réglages.

Une capture longue lancée avec `start_capture` tourne au maximum 1 heure.
Pour l'arrêter plus tôt, il suffit de dire « arrête la capture ».

### 5. Arrêter, désactiver ou retirer le serveur

| Pour… | Claude Desktop | Claude Code |
|---|---|---|
| **Arrêter le serveur** | quitter Claude Desktop | quitter la session (`/exit`) |
| **Le redémarrer** (après une mise à jour) | quitter puis relancer Claude Desktop | `/mcp` → `rustshark` → *Reconnect* |
| **Le désactiver temporairement** | le décocher dans le menu des outils de la conversation | `/mcp` → `rustshark` → *Disable* |
| **Le retirer définitivement** | supprimer le bloc `"rustshark"` du fichier de configuration, puis relancer | `claude mcp remove --scope user rustshark` |

Quand Claude ferme le serveur, celui-ci arrête proprement une éventuelle
capture en cours et libère la mémoire : rien ne continue à tourner en
arrière-plan. Si un processus `rustshark` restait bloqué (Claude arrêté
brutalement), terminez-le dans le Gestionnaire des tâches ou avec
`pkill -f "rustshark --mcp"` sous Linux et macOS.

**Mise à jour de RustShark** : quittez d'abord Claude (sous Windows, un
serveur en cours d'exécution empêche de remplacer `rustshark.exe`), réinstallez,
puis relancez Claude. Aucune autre action n'est nécessaire si le chemin ne
change pas.

### Options et confidentialité

- Les données capturées sont transmises à Claude. Par défaut, les adresses
  privées, les adresses MAC et les adresses de cet ordinateur (y compris son
  préfixe IPv6 public) sont remplacées par des alias stables (`LAN-1`,
  `MAC-1`…). Claude peut utiliser ces alias dans ses filtres. Ajoutez
  `--no-anonymize` aux arguments pour désactiver ce masquage.
- `--lang fr` ou `--lang en` force la langue des résumés (par défaut, celle
  choisie dans l'application).
- Les droits de capture sont ceux de l'application : Npcap sous Windows,
  capacités accordées par le script d'installation sous Linux.

### Dépannage

| Symptôme | Cause probable et solution |
|---|---|
| `rustshark` absent ou en échec dans Claude | chemin incorrect (vérifiez-le, `\` doublés dans le JSON) ; faites le test manuel ci-dessus |
| Claude Desktop ne voit pas la modification | l'application n'a pas été entièrement quittée : passez par l'icône de la zone de notification |
| Erreur signalant que Npcap ou libpcap est absent | installez Npcap (Windows) ou `libpcap` (Linux) |
| Aucune interface ou capture refusée (Linux) | accordez les capacités : `sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/rustshark` |
| Capture vide | mauvaise interface : demandez à Claude de lister les interfaces et de prendre celle recommandée |
| Résumés dans la mauvaise langue | ajoutez `--lang fr` ou `--lang en` après `--mcp` |

Journaux de Claude Desktop : `%APPDATA%\Claude\logs\mcp-server-rustshark.log`
(Windows) ou `~/Library/Logs/Claude/mcp-server-rustshark.log` (macOS). Dans
Claude Code, lancez `claude --debug` pour voir les échanges avec le serveur.

---

## Architecture

```
rustshark/
├── shared/      types sérialisés + langage de filtre (utilisé des deux côtés)
├── src-tauri/   backend Rust (Tauri 2)
│   ├── pcap.rs        chargement dynamique de libpcap / Npcap (FFI)
│   ├── capture.rs     thread de capture, mesure d'activité des interfaces
│   ├── dissect.rs     couches liaison / réseau / transport
│   ├── apps.rs        protocoles applicatifs (DNS, DHCP, HTTP, TLS, QUIC…)
│   ├── explain.rs     résumés et explications FR/EN, noms appris
│   ├── store.rs       stockage, vue filtrée, détails, statistiques, alertes
│   ├── file_io.rs     lecture/écriture pcap et pcapng
│   ├── interfaces.rs  noms lisibles et recommandation d'interface
│   ├── ai.rs          DeepSeek / OpenRouter, contexte, anonymisation
│   ├── mcp.rs         serveur MCP pour Claude (rustshark --mcp)
│   ├── keystore.rs    trousseau sécurisé (crate keyring)
│   ├── config.rs      réglages et profils (JSON, sans secrets)
│   └── main.rs        commandes Tauri
└── frontend/    interface Leptos (CSR, WebAssembly)
    ├── state.rs       état global et actions
    ├── toolbar.rs     barre d'outils, barre de filtre
    ├── packets.rs     liste virtualisée, panneau d'explication
    ├── dashboard.rs   tableau de bord
    ├── ai_panel.rs    assistant IA, générateur de config, profils
    ├── modals.rs      réglages, aide, choix d'interface
    ├── welcome.rs     écran d'accueil
    └── i18n.rs        textes FR/EN
```

## Langage de filtre

| Exemple | Signification |
|---|---|
| `dns` | protocole présent |
| `youtube` | recherche plein texte (un mot seul) |
| `ip.addr == 192.168.1.0/24` | adresse ou réseau (CIDR) |
| `tcp.port == 443 \|\| udp.port == 443` | opérateurs `&&` `\|\|` `!` (ou `and` `or` `not`) |
| `host == *.google.com` | joker `*` sur les noms |
| `tls.sni contains netflix` | contient (insensible à la casse) |
| `internet && !tls && !quic` | propriétés : `local`, `internet`, `broadcast`, `problem`, `cleartext`… |

La liste complète des champs est dans l'aide de l'application (onglet *Filtres*).

## Limites actuelles

- Pas de réassemblage TCP : un message HTTP ou TLS réparti sur plusieurs
  segments n'est décodé que sur son premier segment.
- Pas de déchiffrement TLS ni de capture Wi-Fi en mode moniteur.
- Les programmes à l'origine du trafic (processus) ne sont pas identifiés.

## Usage responsable

N'analysez que les réseaux qui vous appartiennent ou pour lesquels vous disposez
d'une autorisation explicite.

## Licence

Distribué sous licence [MIT](LICENSE).
