#!/bin/sh

# works best on busybox ash

set -efux -o pipefail

alias curl="curl -L"
alias rm="rm -rf"

## Use GNU grep, busybox grep is too slow
. "/etc/os-release"
DISTRO="$ID"

if [ -z "$(grep --help | grep 'GNU')" ]; then
  if [ "$DISTRO" = "alpine" ]; then
    echo "Please install GNU grep 'apk add grep'"
    exit 1
  fi
  alias grep="/usr/bin/grep"
fi


## Fallback to busybox dos2unix
if ! command -v dos2unix &> /dev/null; then
  alias dos2unix="busybox dos2unix"
fi


## Create a temporary working folder
mkdir -p "tmp/"
cd "tmp/"

## Prepare datasets
curl "https://zhouhanc.github.io/malware-discoverer/blocklist.csv.zip" -o "source.zip"
curl "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip" -o "top-1m-umbrella.zip"
curl "https://tranco-list.eu/top-1m.csv.zip" -o "top-1m-tranco.zip"

## Cloudflare Radar
if [ -n "$CF_API" ]; then
  mkdir -p "cf/"
  # Get the latest domain ranking buckets
  curl -X GET "https://api.cloudflare.com/client/v4/radar/datasets?limit=5&offset=0&datasetType=RANKING_BUCKET&format=json" \
    -H "Authorization: Bearer $CF_API" -o "cf/datasets.json"
  # Get the top 1m bucket's dataset ID
  DATASET_ID=$(jq ".result.datasets[] | select(.meta.top==1000000) | .id" "cf/datasets.json")
  # Get the dataset download url
  curl --request POST \
    --url "https://api.cloudflare.com/client/v4/radar/datasets/download" \
    --header "Content-Type: application/json" \
    --header "Authorization: Bearer $CF_API" \
    --data "{ \"datasetId\": $DATASET_ID }" \
    -o "cf/dataset-url.json"
  DATASET_URL=$(jq ".result.dataset.url" "cf/dataset-url.json" | sed 's/"//g')
  curl "$DATASET_URL" -o "cf/top-1m-radar.zip"

  ## Parse the Radar 1 Million
  unzip -p "cf/top-1m-radar.zip" | \
  dos2unix | \
  tr "[:upper:]" "[:lower:]" | \
  grep -F "." | \
  sed "s/^www\.//g" | \
  sort -u > "top-1m-radar.txt"
fi


## Parse URLs
unzip -p "source.zip" | \
dos2unix | \
tr "[:upper:]" "[:lower:]" | \
sed "/^domain,/d" | \
cut -f 1 -d ',' > "source-domains.txt"


## Parse the Umbrella 1 Million
unzip -p "top-1m-umbrella.zip" | \
dos2unix | \
tr "[:upper:]" "[:lower:]" | \
# Parse domains only
cut -f 2 -d "," | \
grep -F "." | \
# Remove www.
sed "s/^www\.//g" | \
sort -u > "top-1m-umbrella.txt"

## Parse the Tranco 1 Million
unzip -p "top-1m-tranco.zip" | \
dos2unix | \
tr "[:upper:]" "[:lower:]" | \
cut -f 2 -d "," | \
grep -F "." | \
sed "s/^www\.//g" | \
sort -u > "top-1m-tranco.txt"

cp "../src/exclude.txt" "."

# ## Parse oisd exclusion list
# cat "oisd-exclude.html" | \
# # https://stackoverflow.com/a/47600828
# xmlstarlet format --recover --html 2>/dev/null | \
# xmlstarlet select --html --template --value-of '//a' | \
# ## Append new line https://unix.stackexchange.com/a/31955
# sed '$a\' > "oisd-exclude.txt"

# Merge Umbrella, Tranco, Radar and self-maintained top domains
cat "top-1m-umbrella.txt" "top-1m-tranco.txt" "exclude.txt" | \
sort -u > "top-1m-well-known.txt"

if [ -n "$CF_API" ] && [ -f "top-1m-radar.txt" ]; then
  cat "top-1m-radar.txt" >> "top-1m-well-known.txt"
  # sort in-place
  sort "top-1m-well-known.txt" -u -o "top-1m-well-known.txt"
fi


## Exclude popular domains
cat "source-domains.txt" | \
# grep match whole line
grep -Fx -vf "top-1m-well-known.txt" > "pup-notop-domains.txt"


## Merge malware domains and URLs
CURRENT_TIME="$(date -R -u)"
FIRST_LINE="! Title: PUP Domains Blocklist\n! Description: Block domains that host potentially unwanted programs (PUP)"
SECOND_LINE="! Updated: $CURRENT_TIME"
THIRD_LINE="! Expires: 1 day (update frequency)"
FOURTH_LINE="! Homepage: https://gitlab.com/malware-filter/pup-filter"
FIFTH_LINE="! License: https://gitlab.com/malware-filter/pup-filter#license"
SIXTH_LINE="! Source: https://github.com/zhouhanc/malware-discoverer"
COMMENT_UBO="$FIRST_LINE\n$SECOND_LINE\n$THIRD_LINE\n$FOURTH_LINE\n$FIFTH_LINE\n$SIXTH_LINE"

mkdir -p "../public/"

cat "pup-notop-domains.txt" | \
sort | \
sed '1 i\'"$COMMENT_UBO"'' > "../public/pup-filter.txt"


# Adguard Home
cat "pup-notop-domains.txt" | \
sort | \
sed -e "s/^/||/g" -e "s/$/^/g" | \
sed '1 i\'"$COMMENT_UBO"'' | \
sed "1s/Blocklist/Blocklist (AdGuard Home)/" > "../public/pup-filter-agh.txt"


# Adguard browser extension
cat "pup-notop-domains.txt" | \
sort | \
sed -e "s/^/||/g" -e "s/$/\$all/g" | \
sed '1 i\'"$COMMENT_UBO"'' | \
sed "1s/Blocklist/Blocklist (AdGuard)/" > "../public/pup-filter-ag.txt"


# Vivaldi
cat "pup-notop-domains.txt" | \
sort | \
sed -e "s/^/||/g" -e "s/$/\$document/g" | \
sed '1 i\'"$COMMENT_UBO"'' | \
sed "1s/Blocklist/Blocklist (Vivaldi)/" > "../public/pup-filter-vivaldi.txt"


## Hash comment
# awk + head is a workaround for sed prepend
COMMENT=$(printf "$COMMENT_UBO" | sed "s/^!/#/g" | awk '{printf "%s\\n", $0}' | head -c -2)

cat "pup-notop-domains.txt" | \
sort | \
sed '1 i\'"$COMMENT"'' > "../public/pup-filter-domains.txt"


## Hosts file blocklist
cat "pup-notop-domains.txt" | \
sed "s/^/0.0.0.0 /g" | \
sed '1 i\'"$COMMENT"'' | \
sed "1s/Domains/Hosts/" > "../public/pup-filter-hosts.txt"


## Dnsmasq-compatible blocklist
cat "pup-notop-domains.txt" | \
sed "s/^/address=\//g" | \
sed "s/$/\/0.0.0.0/g" | \
sed '1 i\'"$COMMENT"'' | \
sed "1s/Blocklist/dnsmasq Blocklist/" > "../public/pup-filter-dnsmasq.conf"


## BIND-compatible blocklist
cat "pup-notop-domains.txt" | \
sed 's/^/zone "/g' | \
sed 's/$/" { type master; notify no; file "null.zone.file"; };/g' | \
sed '1 i\'"$COMMENT"'' | \
sed "1s/Blocklist/BIND Blocklist/" > "../public/pup-filter-bind.conf"


## DNS Response Policy Zone (RPZ)
CURRENT_UNIX_TIME="$(date +%s)"
RPZ_SYNTAX="\n\$TTL 30\n@ IN SOA rpz.curben.gitlab.io. hostmaster.rpz.curben.gitlab.io. $CURRENT_UNIX_TIME 86400 3600 604800 30\n NS localhost.\n"

cat "pup-notop-domains.txt" | \
sed "s/$/ CNAME ./g" | \
sed '1 i\'"$RPZ_SYNTAX"'' | \
sed '1 i\'"$COMMENT"'' | \
sed "s/^#/;/g" | \
sed "1s/Blocklist/RPZ Blocklist/" > "../public/pup-filter-rpz.conf"


## Unbound-compatible blocklist
cat "pup-notop-domains.txt" | \
sed 's/^/local-zone: "/g' | \
sed 's/$/" always_nxdomain/g' | \
sed '1 i\'"$COMMENT"'' | \
sed "1s/Blocklist/Unbound Blocklist/" > "../public/pup-filter-unbound.conf"


## dnscrypt-proxy blocklists
# name-based
cat "pup-notop-domains.txt" | \
sed '1 i\'"$COMMENT"'' | \
sed "1s/Domains/Names/" > "../public/pup-filter-dnscrypt-blocked-names.txt"

## Currently there are no IP entries
# # IPv4-based
# cat "phishing-notop-domains.txt" | \
# sort | \
# grep -E "^([0-9]{1,3}[\.]){3}[0-9]{1,3}$" | \
# sed '1 i\'"$COMMENT"'' | \
# sed "1s/Domains/IPs/" > "../public/phishing-filter-dnscrypt-blocked-ips.txt"


## IE blocklist
COMMENT_IE="msFilterList\n$COMMENT\n: Expires=1\n#"

cat "pup-notop-domains.txt" | \
sed "s/^/-d /g" | \
sed '1 i\'"$COMMENT_IE"'' | \
sed "2s/Domains Blocklist/Hosts Blocklist (IE)/" > "../public/pup-filter.tpl"


set +x

## Snort & Suricata rulesets
rm "../public/pup-filter-snort2.rules" \
  "../public/pup-filter-snort3.rules" \
  "../public/pup-filter-suricata.rules"

SID="300000001"
while read DOMAIN; do
  SN_RULE="alert tcp \$HOME_NET any -> \$EXTERNAL_NET [80,443] (msg:\"pup-filter PUP website detected\"; flow:established,from_client; content:\"GET\"; http_method; content:\"$DOMAIN\"; content:\"Host\"; http_header; classtype:web-application-activity; sid:$SID; rev:1;)"

  SN3_RULE="alert http \$HOME_NET any -> \$EXTERNAL_NET any (msg:\"pup-filter PUP website detected\"; http_header:field host; content:\"$DOMAIN\",nocase; classtype:web-application-activity; sid:$SID; rev:1;)"

  SR_RULE="alert http \$HOME_NET any -> \$EXTERNAL_NET any (msg:\"pup-filter PUP website detected\"; flow:established,from_client; http.method; content:\"GET\"; http.host; content:\"$DOMAIN\"; classtype:web-application-activity; sid:$SID; rev:1;)"

  echo "$SN_RULE" >> "../public/pup-filter-snort2.rules"
  echo "$SN3_RULE" >> "../public/pup-filter-snort3.rules"
  echo "$SR_RULE" >> "../public/pup-filter-suricata.rules"

  SID=$(( $SID + 1 ))
done < "pup-notop-domains.txt"


set -x

sed -i '1 i\'"$COMMENT"'' "../public/pup-filter-snort2.rules"
sed -i "1s/Blocklist/Snort2 Ruleset/" "../public/pup-filter-snort2.rules"

sed -i '1 i\'"$COMMENT"'' "../public/pup-filter-snort3.rules"
sed -i "1s/Blocklist/Snort3 Ruleset/" "../public/pup-filter-snort3.rules"

sed -i '1 i\'"$COMMENT"'' "../public/pup-filter-suricata.rules"
sed -i "1s/Blocklist/Suricata Ruleset/" "../public/pup-filter-suricata.rules"


## Clean up artifacts
rm "source.zip" "source-domains.txt" "top-1m-umbrella.zip" "top-1m-umbrella.txt" "top-1m-tranco.txt" "cf/" "top-1m-radar.txt"


cd ../
