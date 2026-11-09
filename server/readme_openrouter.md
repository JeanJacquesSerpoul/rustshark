# Proxy OpenRouter

Proxy HTTP en Go (bibliothèque standard uniquement) vers l'API [openrouter.ai](https://openrouter.ai).

- Injecte votre clé `OPENROUTER_API_KEY` : les clients n'ont pas besoin de la connaître.
- Compatible OpenAI : `/v1/...` et `/api/v1/...` sont relayés vers `https://openrouter.ai/api/v1/...`.
- Streaming SSE (`"stream": true`) relayé sans mise en tampon.
- Contrôle d'accès optionnel par clés propres au proxy (`PROXY_API_KEYS`).
- CORS optionnel, journalisation, endpoint `/health`, arrêt propre (Ctrl+C).

## Démarrage (docker compose)

```bash
cp .env.example .env
```

Renseigner `OPENROUTER_API_KEY` dans `.env`, puis :

```bash
docker compose up -d --build
```

Le proxy est publié par défaut sur `http://127.0.0.1:9018` (adresse et port réglables via `PROXY_HOST` / `PROXY_PORT` dans `.env`). Le conteneur redémarre automatiquement et dispose d'un healthcheck (`docker compose ps` affiche `healthy`).

Commandes utiles :

```bash
docker compose logs -f
```

```bash
docker compose down
```

Après modification de `.env`, recréer le conteneur :

```bash
docker compose up -d
```

L'image est construite en deux étapes (compilation Go, puis image `distroless` sans shell, utilisateur non-root, ~10 Mo). Le fichier `.env` n'est jamais copié dans l'image : il est fourni au conteneur au lancement.

## Livraison en production (`dist/`)

Les scripts `build-dist.ps1` (Windows) et `build-dist.sh` (Linux/macOS/Git Bash) produisent un répertoire `dist/` autonome, sans code source : l'exécutable Linux, un `Dockerfile` qui l'embarque (aucun Go nécessaire sur le serveur), `docker-compose.yml`, `.env.example`, un README de déploiement, `VERSION` et `SHA256SUMS`.

```powershell
.\build-dist.ps1
```

```bash
./build-dist.sh
```

Options : `-Arch arm64` / `--arch arm64`, `-Version X` / `--version X` (par défaut : date et heure), `-SkipTests` / `--skip-tests`. Les tests sont lancés avant la compilation, et un éventuel `dist/.env` est conservé.

Sur le serveur, après copie de `dist/` (voir `dist/README.md`) :

```bash
cp .env.example .env
```

```bash
docker compose build
```

```bash
docker compose up -d
```

La version déployée apparaît dans les logs au démarrage.

## Reverse proxy Caddy

Bloc à ajouter dans le site concerné du `Caddyfile` :

```caddyfile
handle_path /openrouter* {
    reverse_proxy localhost:9018
}
```

`handle_path` retire le préfixe `/openrouter` avant de transmettre la requête au proxy :
`https://votre-domaine/openrouter/v1/chat/completions` → `http://localhost:9018/v1/chat/completions`.

Côté client, l'URL de base devient donc `https://votre-domaine/openrouter/v1`. Le streaming SSE fonctionne sans réglage supplémentaire : Caddy transmet immédiatement les réponses `text/event-stream`.

Le service étant alors accessible depuis Internet, définir `PROXY_API_KEYS` dans `.env`.

## Démarrage sans Docker (développement)

```bash
go run .
```

Un autre fichier de configuration peut être passé avec `-env chemin/vers/fichier.env`.

## Paramètres (`.env`)

| Variable | Défaut | Rôle |
|---|---|---|
| `OPENROUTER_API_KEY` | *(vide)* | Clé injectée dans chaque requête. Vide = mode passthrough (le client envoie sa propre clé). |
| `OPENROUTER_BASE_URL` | `https://openrouter.ai/api/v1` | API cible. |
| `OPENROUTER_HTTP_REFERER` | *(vide)* | En-tête `HTTP-Referer` ajouté si absent. |
| `OPENROUTER_X_TITLE` | *(vide)* | En-tête `X-Title` ajouté si absent. |
| `PROXY_HOST` | `127.0.0.1` | Adresse d'écoute (`0.0.0.0` pour le réseau). Avec Docker : adresse publiée sur l'hôte. |
| `PROXY_PORT` | `9018` | Port d'écoute. Avec Docker : port publié sur l'hôte. |
| `PROXY_API_KEYS` | *(vide)* | Clés client acceptées, séparées par des virgules (16 caractères min.). |
| `PROXY_ALLOWED_PATHS` | *(vide = tout)* | Routes autorisées, ex. `/chat/completions,/models`. |
| `PROXY_MAX_BODY_SIZE` | `20MB` | Taille max du corps de requête (`0` = illimité). |
| `PROXY_BODY_TIMEOUT` | `2m` | Délai max pour recevoir le corps de la requête. |
| `PROXY_WRITE_TIMEOUT` | `1m` | Délai max de chaque envoi au client (renouvelé pendant le streaming). |
| `PROXY_TIMEOUT` | `10m` | Attente max des en-têtes de réponse d'OpenRouter (pas la durée totale d'un flux). |
| `PROXY_MAX_CONCURRENT` | `100` | Requêtes simultanées max (`0` = illimité). |
| `PROXY_CORS_ORIGINS` | *(vide)* | Origines CORS autorisées (`*` pour toutes). |
| `PROXY_LOG_REQUESTS` | `true` | Journalise chaque requête. |

Les variables d'environnement du système sont prioritaires sur le fichier `.env`.

## Utilisation

```bash
curl http://127.0.0.1:9018/v1/chat/completions -H "Content-Type: application/json" -d '{"model":"openai/gpt-4o-mini","messages":[{"role":"user","content":"Bonjour"}]}'
```

Avec le SDK OpenAI (Python) :

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:9018/v1", api_key="peu-importe")  # ou une clé de PROXY_API_KEYS
r = client.chat.completions.create(model="openai/gpt-4o-mini", messages=[{"role": "user", "content": "Bonjour"}])
print(r.choices[0].message.content)
```

## Sécurité

| Risque | Protection | Réponse |
|---|---|---|
| Corps de requête énorme | `PROXY_MAX_BODY_SIZE`, vérifié sur `Content-Length` puis pendant la lecture (envoi chunked) | `413` |
| Client qui envoie très lentement (slowloris) | En-têtes : 10 s, 64 KB max. Corps : `PROXY_BODY_TIMEOUT` | `408` |
| Client qui ne lit plus la réponse | `PROXY_WRITE_TIMEOUT` par envoi | connexion coupée |
| OpenRouter qui ne répond pas | `PROXY_TIMEOUT` (en-têtes), connexion 30 s, TLS 10 s | `504` |
| Saturation | `PROXY_MAX_CONCURRENT` | `429` + `Retry-After` |
| Usage de votre clé par des tiers | Écoute sur `127.0.0.1` par défaut, `PROXY_API_KEYS` (comparaison en temps constant), avertissement au démarrage si exposé sans clé | `401` |
| Accès aux routes sensibles (`/key`, `/credits`...) | `PROXY_ALLOWED_PATHS`, segments `.`/`..` refusés (même encodés) | `403` / `400` |
| Fuite d'informations | Erreurs génériques côté client (détail dans les logs) ; logs sans query string, en-têtes ni corps ; `Cookie`, `Set-Cookie`, `X-Forwarded-*` et IP client non relayés | — |
| Clé envoyée en clair | `OPENROUTER_BASE_URL` en `http://` refusée (sauf localhost) | arrêt au démarrage |
| Conteneur compromis | Image distroless sans shell, utilisateur non-root, système de fichiers en lecture seule, aucune capability, `no-new-privileges`, 256 Mo RAM, 64 processus, logs limités à 30 Mo | — |

Les délais globaux `ReadTimeout`/`WriteTimeout` de Go ne sont volontairement pas utilisés, car ils couperaient les réponses en streaming longues. Les délais sont appliqués par requête (voir `limits.go`).

Rappel : la clé OpenRouter est visible par quiconque peut lancer `docker inspect` sur la machine. Définissez aussi une limite de crédit sur la clé dans le tableau de bord OpenRouter.

## Tests

```bash
go test ./...
```
