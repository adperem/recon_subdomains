
# Subdomain Recon Script

This script automates the process of subdomain discovery and related data collection for a given domain using several reconnaissance tools.

## Features
- **Subdomain Collection**: Gathers subdomains using various tools like **subfinder**, **assetfinder**, **amass**, **github-subdomains**, and **crt.sh**.
- **IP Information**: Retrieves IP addresses associated with the discovered subdomains from services like **VirusTotal**, **AlienVault OTX**, and **urlscan.io**.
- **Active Subdomain Checking**: Uses **httpx** to check which subdomains are live on common ports (80, 443, etc.).
- **Result Filtering**: Removes duplicates and unnecessary entries, keeping only relevant data.
- **Organized Output**: Results are saved in an organized directory for easy access and analysis.

## Prerequisites
Before running this script, ensure you have the following tools installed:
- **Go** (for installing the tools)
- **API Keys** for services that require them:
  - **VirusTotal** API key: Set it as `VT_APIKEY`.
  - **Shodan** API key: Set it as `SHODAN_API_KEY`.
  - **GitHub Token**: Set it as `GITHUB_TOKEN`.
  - **Chaos**: API key: Set it as `PDCP_API_KEY`.

## Tools Used
- **subfinder**: Subdomain discovery using multiple sources.
- **assetfinder**: Finds additional subdomains.
- **amass**: Subdomain enumeration (both passive and active).
- **github-subdomains**: Collects subdomains from GitHub.
- **crt.sh**: Retrieves subdomains from SSL certificates.
- **Wayback Machine**: Searches for subdomains through archived URLs.
- **VirusTotal**: Retrieves subdomains and associated IP addresses.
- **alterx**: Enriches and verifies subdomains.
- **chaos**: A subdomain enumeration tool for discovering subdomains from various sources.
- **httpx**: Verifies subdomains on common ports (80, 443, etc.).
- **ffuf (optional)**: Performs fuzzing to find additional subdomains.
- **Shodan (optional)**: Retrieves data related to devices for a domain.

## Installation

1. **Install Go tools**:
   ```bash
   go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
   go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
   go install github.com/projectdiscovery/alterx/cmd/alterx@latest
   go install github.com/tomnomnom/assetfinder@latest
   sudo apt install amass
   go install github.com/gwen001/github-subdomains@latest
   go install github.com/ffuf/ffuf/v2@latest
   go install github.com/incogbyte/shosubgo@latest
   ```

## Usage

Run the script by providing the domain name as an argument:

```bash
./subdomain_recon.sh <domain>
```

### Example:

```bash
./subdomain_recon.sh example.com
```

This will create a directory called `output_example.com` containing the results:
- **subfinder.txt**: Subdomains discovered by subfinder.
- **assetfinder.txt**: Additional subdomains from assetfinder.
- **amass_passive.txt**: Passive subdomains from amass.
- **amass_active.txt**: Active subdomains from amass.
- **subdomains_alive.txt**: Live subdomains after checking active ones.
- **ips.txt**: IPs associated with subdomains.

## Output
All results will be stored in a folder called `output_<domain>`. The results include:
- Subdomains found by different tools.
- Active subdomains checked with **httpx**.
- IPs resolved from various services.
- Final list of unique and active subdomains.

## Contributing

Feel free to fork this repository and contribute by submitting pull requests. Any improvements or fixes are welcome!

## License

Distributed under the MIT License. 

### Notes:
- Ensure you have your API keys for **VirusTotal**, **Shodan**, and **GitHub** set correctly in the script environment.
- The **`ffuf`** and **`Shodan`** steps are optional and can be uncommented in the script.
