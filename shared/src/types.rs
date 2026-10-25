use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Réglages
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    #[default]
    Fr,
    En,
}

impl Lang {
    /// Choisit la chaîne correspondant à la langue.
    pub fn pick<'a>(self, fr: &'a str, en: &'a str) -> &'a str {
        match self {
            Lang::Fr => fr,
            Lang::En => en,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    #[default]
    System,
    Light,
    Dark,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    #[default]
    DeepSeek,
    OpenRouter,
}

impl Provider {
    pub const ALL: [Provider; 2] = [Provider::DeepSeek, Provider::OpenRouter];

    pub fn id(self) -> &'static str {
        match self {
            Provider::DeepSeek => "deepseek",
            Provider::OpenRouter => "openrouter",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Provider::DeepSeek => "DeepSeek",
            Provider::OpenRouter => "OpenRouter",
        }
    }

    pub fn default_model(self) -> &'static str {
        match self {
            Provider::DeepSeek => "deepseek-chat",
            Provider::OpenRouter => "openrouter/auto",
        }
    }

    pub fn key_url(self) -> &'static str {
        match self {
            Provider::DeepSeek => "https://platform.deepseek.com/api_keys",
            Provider::OpenRouter => "https://openrouter.ai/settings/keys",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AiSettings {
    pub provider: Provider,
    pub deepseek_model: String,
    pub openrouter_model: String,
    /// Masque les adresses IP/MAC locales avant envoi à l'IA.
    pub anonymize: bool,
    /// Nombre maximum de paquets inclus en exemple dans le contexte envoyé.
    pub sample_packets: u32,
}

impl Default for AiSettings {
    fn default() -> Self {
        Self {
            provider: Provider::DeepSeek,
            deepseek_model: Provider::DeepSeek.default_model().into(),
            openrouter_model: Provider::OpenRouter.default_model().into(),
            anonymize: true,
            sample_packets: 60,
        }
    }
}

impl AiSettings {
    pub fn model(&self) -> &str {
        match self.provider {
            Provider::DeepSeek => &self.deepseek_model,
            Provider::OpenRouter => &self.openrouter_model,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppSettings {
    pub language: Lang,
    pub theme: Theme,
    /// Mode « simple » : colonnes et vocabulaire pour débutants.
    pub simple_mode: bool,
    /// Affiche les noms (appris passivement via DNS/TLS) plutôt que les IP.
    pub resolve_names: bool,
    pub promiscuous: bool,
    pub onboarding_done: bool,
    pub max_packets: u32,
    pub ai: AiSettings,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            language: Lang::Fr,
            theme: Theme::System,
            simple_mode: true,
            resolve_names: true,
            promiscuous: false,
            onboarding_done: false,
            max_packets: 1_000_000,
            ai: AiSettings::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Système / interfaces
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SystemInfo {
    pub pcap_ok: bool,
    pub pcap_version: Option<String>,
    pub pcap_error: Option<String>,
    pub os: String,
    pub app_version: String,
    /// Nom du trousseau sécurisé utilisé sur cette plateforme.
    pub keystore_name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum IfaceKind {
    Wifi,
    Ethernet,
    Loopback,
    Virtual,
    Vpn,
    Bluetooth,
    #[default]
    Other,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct InterfaceInfo {
    /// Identifiant technique utilisé par pcap (ex. \Device\NPF_{GUID}).
    pub name: String,
    pub description: String,
    /// Nom lisible (ex. « Wi-Fi », « Ethernet 2 »).
    pub friendly: String,
    pub kind: IfaceKind,
    pub addresses: Vec<String>,
    pub up: bool,
    pub connected: bool,
    pub loopback: bool,
    pub recommended: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct InterfaceActivity {
    pub name: String,
    pub packets: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StartCaptureRequest {
    pub interface: String,
    pub capture_filter: Option<String>,
    pub promiscuous: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CaptureState {
    #[default]
    Idle,
    Running,
    Stopped,
    File,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct CaptureStatus {
    pub state: CaptureState,
    /// Interface ou nom de fichier.
    pub source: Option<String>,
    pub capture_filter: Option<String>,
    pub packets: u32,
    pub bytes: u64,
    pub dropped: u32,
    pub elapsed: f64,
    pub error: Option<String>,
    pub truncated: bool,
}

// ---------------------------------------------------------------------------
// Paquets
// ---------------------------------------------------------------------------

/// Famille « grand public » d'un paquet, utilisée pour la couleur et le mode simple.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Web,
    SecureWeb,
    Dns,
    LocalNet,
    Network,
    Mail,
    Files,
    Remote,
    Media,
    Problem,
    #[default]
    Other,
}

impl Category {
    pub const ALL: [Category; 11] = [
        Category::SecureWeb,
        Category::Web,
        Category::Dns,
        Category::LocalNet,
        Category::Network,
        Category::Mail,
        Category::Files,
        Category::Remote,
        Category::Media,
        Category::Problem,
        Category::Other,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Category::Web => "web",
            Category::SecureWeb => "secureweb",
            Category::Dns => "dns",
            Category::LocalNet => "localnet",
            Category::Network => "network",
            Category::Mail => "mail",
            Category::Files => "files",
            Category::Remote => "remote",
            Category::Media => "media",
            Category::Problem => "problem",
            Category::Other => "other",
        }
    }

    pub fn label(self, lang: Lang) -> &'static str {
        match self {
            Category::Web => lang.pick("Web non chiffré", "Unencrypted web"),
            Category::SecureWeb => lang.pick("Web sécurisé", "Secure web"),
            Category::Dns => lang.pick("Annuaire (DNS)", "Directory (DNS)"),
            Category::LocalNet => lang.pick("Réseau local", "Local network"),
            Category::Network => lang.pick("Gestion du réseau", "Network management"),
            Category::Mail => lang.pick("E-mail", "E-mail"),
            Category::Files => lang.pick("Fichiers", "Files"),
            Category::Remote => lang.pick("Accès à distance", "Remote access"),
            Category::Media => lang.pick("Audio / vidéo", "Audio / video"),
            Category::Problem => lang.pick("Problèmes", "Problems"),
            Category::Other => lang.pick("Autre", "Other"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct PacketRow {
    pub no: u32,
    /// Temps relatif depuis le premier paquet (secondes).
    pub time: f64,
    pub src: String,
    pub dst: String,
    pub src_name: Option<String>,
    pub dst_name: Option<String>,
    pub protocol: String,
    pub length: u32,
    /// Résumé technique (style Wireshark).
    pub info: String,
    /// Résumé en langage simple, dans la langue de l'utilisateur.
    pub summary: String,
    pub category: Category,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct ViewResponse {
    pub total: u32,
    pub matched: u32,
    pub offset: u32,
    pub rows: Vec<PacketRow>,
    pub status: CaptureStatus,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Field {
    pub name: String,
    pub value: String,
    pub help: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Layer {
    /// Identifiant court (eth, ip, tcp, dns…).
    pub id: String,
    pub title: String,
    pub help: String,
    pub offset: u32,
    pub len: u32,
    pub fields: Vec<Field>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct PacketDetail {
    pub no: u32,
    pub time: f64,
    pub abs_time: String,
    pub length: u32,
    pub captured: u32,
    pub protocol: String,
    pub category: Category,
    pub src: String,
    pub dst: String,
    pub src_name: Option<String>,
    pub dst_name: Option<String>,
    pub explanation: String,
    pub tips: Vec<String>,
    pub layers: Vec<Layer>,
    pub bytes: Vec<u8>,
    /// Filtre permettant d'isoler la conversation de ce paquet.
    pub conversation_filter: Option<String>,
}

// ---------------------------------------------------------------------------
// Statistiques
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct CountItem {
    pub label: String,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct CategoryCount {
    pub category: Category,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct HostStat {
    pub addr: String,
    pub name: Option<String>,
    pub packets: u64,
    pub bytes: u64,
    pub local: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Conversation {
    pub a: String,
    pub b: String,
    pub a_name: Option<String>,
    pub b_name: Option<String>,
    pub protocol: String,
    pub service: Option<String>,
    pub packets: u64,
    pub bytes: u64,
    pub start: f64,
    pub end: f64,
    pub filter: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AlertLevel {
    #[default]
    Info,
    Warning,
    Danger,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Alert {
    pub level: AlertLevel,
    pub title: String,
    pub detail: String,
    pub filter: Option<String>,
    pub count: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Stats {
    pub packets: u64,
    pub bytes: u64,
    pub duration: f64,
    pub protocols: Vec<CountItem>,
    pub categories: Vec<CategoryCount>,
    pub top_hosts: Vec<HostStat>,
    pub conversations: Vec<Conversation>,
    pub dns_names: Vec<CountItem>,
    pub sites: Vec<CountItem>,
    pub timeline: Vec<u32>,
    pub timeline_step: f64,
    pub alerts: Vec<Alert>,
}

// ---------------------------------------------------------------------------
// IA
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AiScope {
    #[default]
    All,
    Filtered,
    Packet,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AiChatRequest {
    pub request_id: String,
    pub messages: Vec<ChatMessage>,
    pub scope: AiScope,
    pub selected: Option<u32>,
    /// Profil d'analyse actif (ajoute ses consignes au contexte).
    pub profile: Option<AnalysisProfile>,
}

/// Événement émis pendant une réponse en streaming (`ai-chunk`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct AiChunk {
    pub request_id: String,
    pub delta: String,
    pub reasoning: bool,
    pub done: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AnalysisProfile {
    pub id: String,
    pub name: String,
    pub goal: String,
    pub explanation: String,
    /// Filtre de capture (syntaxe BPF) appliqué au démarrage de la capture.
    pub capture_filter: Option<String>,
    /// Filtre d'affichage (syntaxe RustShark).
    pub display_filter: Option<String>,
    pub watch_points: Vec<String>,
    /// Question à poser à l'IA une fois la capture terminée.
    pub ai_prompt: Option<String>,
    pub suggested_duration_s: Option<u32>,
    pub created: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct GeneratedProfile {
    pub profile: AnalysisProfile,
    pub display_filter_error: Option<String>,
    pub capture_filter_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct KeyStatus {
    pub deepseek: bool,
    pub openrouter: bool,
    pub store_ok: bool,
    pub store_error: Option<String>,
}

impl KeyStatus {
    pub fn has(&self, p: Provider) -> bool {
        match p {
            Provider::DeepSeek => self.deepseek,
            Provider::OpenRouter => self.openrouter,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct ModelInfo {
    pub id: String,
    pub name: String,
    pub context: Option<u64>,
    pub free: bool,
}

// ---------------------------------------------------------------------------
// Graphe des flux (qui parle à qui, avec quels volumes)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FlowNodeKind {
    ThisComputer,
    #[default]
    Local,
    Internet,
    Group,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct FlowNode {
    /// Adresse IP, « this-computer » ou « others-* » pour un regroupement.
    pub id: String,
    pub label: String,
    pub kind: FlowNodeKind,
    pub addresses: Vec<String>,
    pub bytes: u64,
    pub packets: u64,
    /// Nombre d'adresses regroupées dans ce nœud.
    pub members: u32,
    /// Filtre d'affichage isolant le trafic de ce nœud.
    pub filter: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct FlowEdge {
    pub source: String,
    pub target: String,
    pub bytes: u64,
    pub packets: u64,
    pub bytes_source_to_target: u64,
    pub bytes_target_to_source: u64,
    pub encrypted_percent: f64,
    pub cleartext_bytes: u64,
    pub services: Vec<String>,
    pub first_s: f64,
    pub last_s: f64,
    pub filter: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct FlowGraph {
    pub packets: u64,
    pub bytes: u64,
    pub duration_s: f64,
    pub non_ip_packets_ignored: u64,
    pub omitted_edges: u32,
    pub omitted_bytes: u64,
    pub nodes: Vec<FlowNode>,
    pub edges: Vec<FlowEdge>,
}

// ---------------------------------------------------------------------------
// Mon réseau : appareils, configuration, sécurité, Internet
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DeviceKind {
    Router,
    Computer,
    Phone,
    Tablet,
    Tv,
    Media,
    Speaker,
    Printer,
    Camera,
    Console,
    Nas,
    SmartHome,
    Watch,
    #[default]
    Unknown,
}

impl DeviceKind {
    pub fn label(self, lang: Lang) -> &'static str {
        match self {
            DeviceKind::Router => lang.pick("Box / routeur", "Router"),
            DeviceKind::Computer => lang.pick("Ordinateur", "Computer"),
            DeviceKind::Phone => lang.pick("Téléphone", "Phone"),
            DeviceKind::Tablet => lang.pick("Tablette", "Tablet"),
            DeviceKind::Tv => lang.pick("Téléviseur", "TV"),
            DeviceKind::Media => lang.pick("Lecteur multimédia", "Media player"),
            DeviceKind::Speaker => lang.pick("Enceinte", "Speaker"),
            DeviceKind::Printer => lang.pick("Imprimante", "Printer"),
            DeviceKind::Camera => lang.pick("Caméra", "Camera"),
            DeviceKind::Console => lang.pick("Console de jeux", "Game console"),
            DeviceKind::Nas => lang.pick("Stockage réseau (NAS)", "Network storage (NAS)"),
            DeviceKind::SmartHome => lang.pick("Objet connecté", "Smart home device"),
            DeviceKind::Watch => lang.pick("Montre", "Watch"),
            DeviceKind::Unknown => lang.pick("Appareil inconnu", "Unknown device"),
        }
    }
}

/// Appareil du réseau local, fusionné à partir de toutes les sources disponibles.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct NetDevice {
    pub ip: String,
    pub ipv6: Vec<String>,
    pub mac: Option<String>,
    /// Fabricant de la carte réseau (préfixe MAC).
    pub vendor: Option<String>,
    /// Meilleur nom connu (mDNS, NetBIOS, DHCP, UPnP, DNS inverse).
    pub name: Option<String>,
    /// Tous les noms rencontrés, avec leur origine (« mDNS : iPhone-de-Lea.local »).
    pub names: Vec<String>,
    pub model: Option<String>,
    pub kind: DeviceKind,
    /// Services annoncés (AirPlay, Google Cast, imprimante…).
    pub services: Vec<String>,
    pub is_gateway: bool,
    pub is_self: bool,
    /// Adresse MAC « privée » (aléatoire), typique des téléphones récents.
    pub random_mac: bool,
    /// Origines de la découverte : table des voisins, analyse, capture…
    pub sources: Vec<String>,
    /// Présent dans la table des voisins ou ayant répondu à l'analyse.
    pub online: bool,
    pub packets: u64,
    pub bytes: u64,
    /// Ports trouvés ouverts lors de la dernière analyse de ports.
    pub open_ports: Option<Vec<PortInfo>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct DeviceList {
    pub devices: Vec<NetDevice>,
    /// Réseau analysé (ex. 192.168.1.0/24).
    pub network: Option<String>,
    /// Heure locale de la dernière analyse active.
    pub scanned_at: Option<String>,
    pub scan_duration: Option<f64>,
    /// Remarque à afficher (analyse limitée, interface sans IPv4…).
    pub note: Option<String>,
}

/// Progression d'une opération longue (événement `net-progress`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct NetProgress {
    /// « scan », « ports », « speed ».
    pub task: String,
    pub phase: String,
    pub done: u32,
    pub total: u32,
    /// Valeur instantanée (débit en Mbit/s pendant le test de vitesse).
    pub value: Option<f64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum WifiSecurity {
    Open,
    Wep,
    Wpa,
    Wpa2,
    Wpa3,
    Enterprise,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct WifiInfo {
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    /// Qualité du signal en pourcentage.
    pub signal: Option<u32>,
    pub rssi: Option<i32>,
    pub channel: Option<u32>,
    pub band: Option<String>,
    pub standard: Option<String>,
    pub rx_mbps: Option<u32>,
    pub tx_mbps: Option<u32>,
    pub auth: Option<String>,
    pub cipher: Option<String>,
    pub security: WifiSecurity,
    /// Explication quand une information n'est pas accessible (localisation désactivée…).
    pub note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct NetworkInfo {
    pub interface: String,
    pub friendly: String,
    pub kind: IfaceKind,
    pub description: Option<String>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub ipv4: Option<String>,
    pub prefix: Option<u8>,
    pub netmask: Option<String>,
    /// Plage du réseau local (ex. 192.168.1.0/24).
    pub network: Option<String>,
    pub broadcast: Option<String>,
    pub hosts: Option<u32>,
    pub ipv6: Vec<String>,
    pub gateway: Option<String>,
    pub gateway_mac: Option<String>,
    pub gateway_vendor: Option<String>,
    pub gateway_v6: Option<String>,
    pub dns: Vec<String>,
    pub dhcp: Option<bool>,
    pub dhcp_server: Option<String>,
    pub dns_suffix: Option<String>,
    pub mtu: Option<u32>,
    pub speed_mbps: Option<u64>,
    pub wifi: Option<WifiInfo>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CheckLevel {
    #[default]
    Ok,
    Info,
    Warning,
    Danger,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct PortInfo {
    pub port: u16,
    pub service: String,
    pub level: CheckLevel,
    pub note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SecurityCheck {
    pub level: CheckLevel,
    pub title: String,
    pub detail: String,
    /// Conseil concret pour corriger le problème.
    pub advice: Option<String>,
    /// Filtre d'affichage pour voir les paquets concernés.
    pub filter: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SecurityReport {
    /// Note sur 100.
    pub score: u8,
    pub checks: Vec<SecurityCheck>,
    /// Vrai si la box a été analysée activement (ports, UPnP).
    pub deep: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct LatencyResult {
    pub label: String,
    pub target: String,
    pub ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    /// Nombre de mesures sans réponse.
    pub lost: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct InternetInfo {
    pub online: bool,
    pub public_ip: Option<String>,
    pub public_ipv6: Option<String>,
    pub reverse: Option<String>,
    pub isp: Option<String>,
    pub asn: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub country: Option<String>,
    pub timezone: Option<String>,
    /// Centre de données Cloudflare le plus proche (ex. CDG).
    pub edge: Option<String>,
    pub ipv6_ok: bool,
    /// La box elle-même n'a pas d'adresse publique (CGNAT, double NAT).
    pub cgnat: bool,
    pub latency: Vec<LatencyResult>,
    pub dns: Vec<LatencyResult>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SpeedResult {
    pub download_mbps: f64,
    pub upload_mbps: f64,
    pub latency_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    /// Latence pendant le téléchargement (mesure du « bufferbloat »).
    pub loaded_latency_ms: Option<f64>,
    pub bytes_down: u64,
    pub bytes_up: u64,
    pub server: String,
}
