<p align="center">
  <img src="https://adperem.github.io/assets/img/recon_subdomains/recon_subdomains-logo.png" alt="RECON SUBDOMAINS logo" width="300"/>
</p>

# Recon Subdomains v2.6

Script bash de reconocimiento automatizado de subdominios con múltiples fuentes OSINT, bruteforce DNS, crawling, post-procesado de calidad y detección de takeovers.

---

## Modos de operación

| Flag | Color | Descripción |
|------|-------|-------------|
| `--passive` | 🔵 Azul | OSINT puro — consulta APIs y fuentes públicas sin enviar tráfico al target |
| `--bruteforce` | 🔴 Rojo | Bruteforce DNS activo — permutaciones, crawling, enumeración |
| `--all` | 🟣 Magenta | Ambos modos combinados (máximo recall) |
| _(sin flag)_ | — | Muestra menú interactivo si hay TTY |

---

## Características

### Fase Pasiva — 22 fuentes OSINT en paralelo

**Herramientas locales**

| Fuente | Clave requerida |
|--------|----------------|
| subfinder | — |
| assetfinder | — |
| findomain | — |
| amass (pasivo) | — |
| github-subdomains | `GITHUB_TOKEN` |
| chaos | `PDCP_API_KEY` |

**APIs públicas / gratuitas**

| Fuente | Clave requerida |
|--------|----------------|
| crt.sh | — |
| Wayback Machine | — |
| AlienVault OTX | — |
| urlscan.io | — |
| HackerTarget | — |
| RapidDNS | — |
| Bufferover (TLS + DNS) | — |
| Facebook CT | — _(opcional: `FB_TOKEN` para mayor límite)_ |

**APIs de pago / premium**

| Fuente | Clave requerida |
|--------|----------------|
| VirusTotal | `VT_APIKEY` |
| SecurityTrails | `SECURITYTRAILS_KEY` |
| Censys v2 | `CENSYS_ID` + `CENSYS_SECRET` |
| BinaryEdge | `BINARYEDGE_KEY` |
| BeVigil OSINT | `BEVIGIL_KEY` |
| FullHunt | `FULLHUNT_KEY` |
| Netlas | `NETLAS_KEY` |
| Shodan DNS | `SHODAN_API_KEY` |

Todas las fuentes corren **en paralelo**. Las que no tienen clave configurada se marcan como `[SKIP]` automáticamente sin bloquear el resto.

---

### Fase Bruteforce — 5 módulos

| Módulo | Descripción |
|--------|-------------|
| **B1 — DNS Bruteforce** | puredns (wildcard-aware) → shuffledns → dnsx → dig como fallback |
| **B2 — Permutaciones** | alterx (patrones + enrich) + gotator con wordlist compacta |
| **B3 — Amass activo** | Enumeración activa con amass |
| **B4 — Crawling** | katana / gospider + gau (histórico) + subjs (extracción JS) |
| **B5 — Recursión** | Permutaciones iterativas sobre nuevos hallazgos hasta N niveles |

**Detección de wildcards DNS** antes del bruteforce: 5 subdominios aleatorios de prueba + `--wildcard-tests 30` en puredns.

---

### Fase 4 — Post-procesado de calidad

- **Consolidación**: merge de todas las fuentes, deduplicación, filtrado de scope
- **Resolución DNS**: dnsx / dig — genera `final_resolved.txt`
- **Sondeo HTTP**: httpx con JSON completo → `subdomains_alive.txt` + `httpx.json`
- **Recolección de IPs**: VirusTotal, AlienVault, urlscan → `ips.txt`
- **Clasificación por categorías**: admin, dev, api, auth, internal, monitoring, mail, cloud, database, git, vpn → `classified/`
- **Detección de takeovers**: subzy (preferido) o nuclei con templates `takeovers/`

---

### Fase 5 — UX

- **Banner con color de modo**: azul (pasivo) / rojo (bruteforce) / magenta (completo)
- **ETA orientativa** en el banner antes de empezar
- **Resumen final** con el mismo color del modo: conteos por fuente, clasificación, detalles de bruteforce
- **Modo `--diff`**: compara con el run anterior — genera `diff_new.txt` y `diff_gone.txt`, muestra caja de cambios inline
- **Modo `--notify`**: notificación de escritorio al terminar (macOS, Linux, Windows WSL)
- **Takeover auto-prompt**: si hay hosts vivos y no se pasó `--takeover`, pregunta en TTY

---

## Instalación

### Dependencias requeridas

```bash
# Solo curl es estrictamente necesario para el modo pasivo básico
sudo apt install curl jq
```

### Herramientas Go (modo pasivo)

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/gwen001/github-subdomains@latest
```

### Herramientas Go (modo bruteforce)

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/d3mondev/puredns/v2@latest
go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/s0md3v/gotator@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/jaeles-project/gospider@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/unfurl@latest
go install github.com/lc/subjs@latest
go install github.com/ffuf/ffuf/v2@latest
sudo apt install amass
```

### Herramientas de detección de takeovers (opcional)

```bash
go install github.com/PentestPad/subzy@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

### findomain (opcional)

```bash
curl -LO https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux
chmod +x findomain-linux && sudo mv findomain-linux /usr/local/bin/findomain
```

---

## Uso

```bash
./recon_subdomains.sh -d <dominio> [--passive|--bruteforce|--all] [opciones]
```

### Opciones generales

| Flag | Descripción |
|------|-------------|
| `-d, --domain <dom>` | Dominio objetivo **(requerido)** |
| `-o, --output <dir>` | Directorio de salida _(default: `output_<dominio>`)_ |
| `--passive` | Solo fuentes OSINT |
| `--bruteforce` | Solo bruteforce activo |
| `--all` | Ambos modos |
| `--skip-active` | Saltar sondeo HTTP final (httpx) |
| `-f, --force` | Re-ejecutar aunque ya existan resultados |
| `-t, --timeout <seg>` | Timeout por herramienta _(default: 300)_ |
| `--no-confirm` | No pedir confirmación en wordlists grandes |
| `--takeover` | Activar detección de subdomain takeover |
| `--diff` | Comparar con run anterior (genera `diff_new.txt` / `diff_gone.txt`) |
| `--notify` | Notificación de escritorio al terminar |
| `-v, --verbose` | Modo verbose |
| `-h, --help` | Mostrar ayuda |

### Opciones de bruteforce

| Flag | Descripción |
|------|-------------|
| `-w, --wordlist <path>` | Wordlist personalizada |
| `--wordlist-size <s>` | Preset: `small`=5k · `med`=100k · `big`=2M _(default: med)_ |
| `-r, --resolvers <path>` | Fichero de resolvers DNS personalizado |
| `--brute-timeout <seg>` | Timeout DNS bruteforce _(default: 3600)_ |
| `--recursive-depth <n>` | Niveles de recursión en permutaciones _(default: 1, 0=off)_ |
| `--crawl-depth <n>` | Profundidad de crawling katana/gospider _(default: 3)_ |
| `--skip-crawl` | Desactivar fase de crawling |

### Variables de entorno

```bash
# Claves de pago / con cuenta
export GITHUB_TOKEN="ghp_..."
export VT_APIKEY="..."
export PDCP_API_KEY="..."          # ProjectDiscovery (chaos)
export SECURITYTRAILS_KEY="..."
export CENSYS_ID="..."
export CENSYS_SECRET="..."
export BINARYEDGE_KEY="..."
export BEVIGIL_KEY="..."
export FULLHUNT_KEY="..."
export NETLAS_KEY="..."
export SHODAN_API_KEY="..."

# Opcional — aumenta el límite de Facebook CT
export FB_TOKEN="..."
```

---

## Ejemplos

```bash
# Recon pasivo básico
./recon_subdomains.sh -d example.com --passive

# Recon completo con todas las APIs
GITHUB_TOKEN=ghp_xxx VT_APIKEY=yyy SHODAN_API_KEY=zzz \
  ./recon_subdomains.sh -d example.com --all

# Bruteforce rápido sin confirmar wordlists grandes
./recon_subdomains.sh -d example.com --bruteforce --wordlist-size small --no-confirm

# Re-ejecutar y ver qué cambió respecto al run anterior
./recon_subdomains.sh -d example.com --passive --diff --notify

# Bruteforce con takeover automático, notificación y sin confirmaciones
./recon_subdomains.sh -d example.com --all --takeover --notify --no-confirm

# Bruteforce profundo con wordlist grande y 2 niveles de recursión
./recon_subdomains.sh -d example.com --bruteforce \
  --wordlist-size big --recursive-depth 2 --no-confirm
```

---

## Estructura de salida

```
output_<dominio>/
├── passive/
│   ├── subfinder.txt
│   ├── assetfinder.txt
│   ├── findomain.txt
│   ├── amass_passive.txt
│   ├── github.txt
│   ├── chaos.txt
│   ├── crtsh.txt
│   ├── wayback.txt
│   ├── virustotal.txt
│   ├── alienvault.txt
│   ├── urlscan.txt
│   ├── hackertarget.txt
│   ├── rapiddns.txt
│   ├── securitytrails.txt
│   ├── censys.txt
│   ├── binaryedge.txt
│   ├── bevigil.txt
│   ├── fullhunt.txt
│   ├── netlas.txt
│   ├── bufferover.txt
│   ├── shodan_dns.txt
│   ├── facebook_ct.txt
│   └── passive_merged.txt
├── bruteforce/
│   ├── dns_bruteforce.txt
│   ├── permutations.txt
│   ├── amass_active.txt
│   ├── crawl.txt
│   ├── recursive.txt
│   └── bruteforce_merged.txt
├── classified/
│   ├── admin.txt  auth.txt  dev.txt  api.txt
│   ├── internal.txt  vpn.txt  git.txt
│   ├── monitoring.txt  mail.txt  cloud.txt  database.txt
│   ├── all_classified.txt
│   └── unclassified.txt
├── final.txt              ← todos los subdomains únicos
├── final.txt.prev         ← baseline del run anterior (con --diff)
├── final_resolved.txt     ← subdomains que resuelven DNS
├── subdomains_alive.txt   ← vivos (HTTP/S)
├── httpx.json             ← output completo de httpx
├── ips.txt                ← IPs asociadas
├── wildcards.txt          ← IPs wildcard filtradas
├── takeovers.txt          ← candidatos a takeover (con --takeover)
├── diff_new.txt           ← nuevos vs run anterior (con --diff)
├── diff_gone.txt          ← desaparecidos vs run anterior (con --diff)
└── recon.log

~/.recon_subdomains/
├── wordlists/
│   ├── small_5k.txt
│   ├── medium_100k.txt
│   ├── big_2m.txt
│   └── permutations.txt
└── resolvers/
    └── resolvers.txt
```

---

## Caché

Las wordlists y los resolvers DNS se descargan automáticamente la primera vez y se almacenan en `~/.recon_subdomains/`. Los resolvers se refrescan si tienen más de 24 horas de antigüedad.

---

## Contribuir

Pull requests bienvenidos. Si encuentras un bug o quieres añadir una fuente nueva, abre un issue.

## Licencia

MIT License
