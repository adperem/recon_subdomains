#!/bin/bash

# Update
chaos -up -silent &> /dev/null
subfinder -up -silent &> /dev/null
httpx -up -silent &> /dev/null
alterx -up -silent &> /dev/null

# Argumento: dominio
domain=$1
output_dir="output_$domain"
mkdir -p "$output_dir"

echo "[*] Recolectando subdominios para: $domain"

# subfinder
subfinder -d "$domain" --all --recursive -silent -o "$output_dir/subfinder.txt" &> /dev/null
echo "[✔ ] subfinder terminado"

# assetfinder
assetfinder --subs-only "$domain" > "$output_dir/assetfinder.txt"
echo "[✔ ] assetfinder terminado"
# amass passive
amass enum -passive -d "$domain" 2>/dev/null| cut -d ']' -f 2 | awk '{print $1}' | sort -u > "$output_dir/amass_passive.txt" 
echo "[✔ ] amass terminado"
# amass active
amass enum -active -d "$domain" | grep -oE "([a-zA-Z0-9-_-]+\.)+$domain" | sort -u > "$output_dir/amass_active.txt"

# GitHub subdomains (requiere GITHUB_TOKEN)
github-subdomains -d "$domain" -t "$GITHUB_TOKEN" -raw > "$output_dir/github.txt"
echo "[✔ ] github-subdomains terminado"
# crt.sh
curl -s "https://crt.sh?q=$domain&output=json" | jq -r '.[].name_value | split("\n") | .[0]' | grep -Po '(\w+\.\w+\.\w+)$' | sort | uniq > "$output_dir/crtsh.txt"
echo "[✔ ] crt.sh terminado"
# Wayback machine
curl -s "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | uniq > "$output_dir/wayback.txt"
echo "[✔ ] wayback machine terminado"
# VirusTotal siblings
curl -s "https://www.virustotal.com/vtapi/v2/	domain/report?apikey=$VT_APIKEY&domain=$domain" | jq -r '.domain_siblings[]' > "$output_dir/virustotal.txt"
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=$VT_APIKEY&domain=$domain" | jq -r '.subdomains[]' >> "$output_dir/virustotal.txt"
echo "[✔ ] virustotal terminado"

# alterx methods
cat "$output_dir/subfinder.txt" | alterx -silent | httpx -status-code -silent | grep -Po '^[^\[]+' > "$output_dir/alterx.txt" 
chaos -d "$domain" -silent | alterx -enrich -silent | httpx -status-code -silent | grep -Po '^[^\[]+' > "$output_dir/alterx.txt"
echo "$domain" | alterx -pp word=/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -silent | httpx -status-code -silent | grep -Po '^[^\[]+' > "$output_dir/alterx.txt"
echo "[✔ ] alterx terminado"

# ffuf fuzzing
#ffuf -u "https://FUZZ.$domain" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
#     -mc 200,204,301,302,307,401,403 \
#     -H "User-Agent: Mozilla/5.0 Windows NT 10.0; Win64; x64; rv:91.0" \
#     -t 60 --rate 100 -c -of csv -o "$output_dir/ffuf.csv"
#cut -d ',' -f 2 "$output_dir/ffuf.csv" | grep -oP 'https?://\K[^/]*' >> "$output_dir/final.txt"

# IP resolution from VirusTotal
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain=$domain&apikey=$VT_APIKEY" | jq -r '.. | .ip_address? // empty' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' > "$output_dir/ips.txt"

# AlienVault OTX
curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/$domain/url_list?limit=500&page=1" | jq -r '.url_list[]?.result?.urlworker?.ip // empty' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' >> "$output_dir/ips.txt"

# urlscan.io
curl -s "https://urlscan.io/api/v1/search/?q=domain:$domain&size=10000" | jq -r '.results[].page?.ip // empty' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' >> "$output_dir/ips.txt"
echo "[✔ ] IP terminado"

# Sort unique IPs
#sort -u "$output_dir/ips.txt" -o "$output_dir/ips.txt"

# Shodan (requiere SHODAN_API_KEY exportada)
#shosubgo -d "$domain" -s "$SHODAN_API_KEY" > "$output_dir/shosubgo.txt"
#shodan search Ssl.cert.subject.CN:"$domain" 200  --fields ip_str | httpx -sc -title -server -td

cat "$output_dir"/*.txt | sort -u > "$output_dir/final.txt"

cat "$output_dir/final.txt" | httpx -ports 80,443,8080,8000,8888 --threads 200 -silent | sed 's|https\?://||' | sed 's|[[:space:]]*$||'| grep -v -E '^(No|$)' | sort | uniq > "$output_dir/subdomains_alive.txt"

echo "[+] Todos los resultados se encuentran en $output_dir/"
