# PUP Domains Blocklist

A blocklist of domains that host potentially unwanted programs (PUP), based on the [malware-discoverer](https://github.com/zhouhanc/malware-discoverer). Blocklist is updated twice a day.

There are multiple formats available, refer to the appropriate section according to the program used:

- uBlock Origin (uBO) -> [URL-based](#url-based) section (recommended)
- Pi-hole -> [Domain-based](#domain-based) or [Hosts-based](#hosts-based) section
- AdGuard Home -> [Domain-based (AdGuard Home)](#domain-based-adguard-home) or [Hosts-based](#hosts-based) section
- AdGuard browser extension -> [URL-based (AdGuard)](#url-based-adguard)
- Vivaldi -> [URL-based (Vivaldi)](#url-based-vivaldi)
- [Hosts](#hosts-based)
- [Dnsmasq](#dnsmasq)
- BIND -> BIND [zone](#bind) or [RPZ](#response-policy-zone)
- [Unbound](#unbound)
- Internet Explorer -> [Tracking Protection List (IE)](#tracking-protection-list-ie)
- [Snort2](#snort2)
- [Snort3](#snort3)
- [Suricata](#suricata)

Not sure which format to choose? See [Compatibility](https://gitlab.com/curben/urlhaus-filter/wikis/compatibility) page.

Use [urlhaus-filter](https://gitlab.com/curben/urlhaus-filter) to block malware websites; [phishing-filter](https://gitlab.com/curben/phishing-filter) to block phishing websites.

## URL-based

Import the following URL into uBO to subscribe:

- https://curben.gitlab.io/malware-filter/pup-filter.txt

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/phishing-filter/master/dist/pup-filter.txt
- https://glcdn.githack.com/curben/phishing-filter/raw/master/dist/pup-filter.txt
- https://raw.githubusercontent.com/curbengh/phishing-filter/master/dist/pup-filter.txt
- https://cdn.statically.io/gh/curbengh/phishing-filter/master/dist/pup-filter.txt
- https://gitcdn.xyz/repo/curbengh/phishing-filter/master/dist/pup-filter.txt
- https://cdn.jsdelivr.net/gh/curbengh/phishing-filter/dist/pup-filter.txt

</details>

## URL-based (AdGuard)

Import the following URL into AdGuard browser extension to subscribe:

- https://curben.gitlab.io/malware-filter/pup-filter-ag.txt

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/phishing-filter/master/dist/pup-filter-ag.txt
- https://glcdn.githack.com/curben/phishing-filter/raw/master/dist/pup-filter-ag.txt
- https://raw.githubusercontent.com/curbengh/phishing-filter/master/dist/pup-filter-ag.txt
- https://cdn.statically.io/gh/curbengh/phishing-filter/master/dist/pup-filter-ag.txt
- https://gitcdn.xyz/repo/curbengh/phishing-filter/master/dist/pup-filter-ag.txt
- https://cdn.jsdelivr.net/gh/curbengh/phishing-filter/dist/pup-filter-ag.txt

</details>

## URL-based (Vivaldi)

_Requires Vivaldi Desktop/Android 3.3+, blocking level must be at least "Block Trackers"_

Import the following URL into Vivaldi's **Tracker Blocking Sources** to subscribe:

- https://curben.gitlab.io/malware-filter/pup-filter-vivaldi.txt

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/pup-filter/master/dist/pup-filter-vivaldi.txt
- https://glcdn.githack.com/curben/pup-filter/raw/master/dist/pup-filter-vivaldi.txt
- https://raw.githubusercontent.com/curbengh/pup-filter/master/dist/pup-filter-vivaldi.txt
- https://cdn.statically.io/gh/curbengh/pup-filter/master/dist/pup-filter-vivaldi.txt
- https://gitcdn.xyz/repo/curbengh/pup-filter/master/dist/pup-filter-vivaldi.txt
- https://cdn.jsdelivr.net/gh/curbengh/pup-filter/dist/pup-filter-vivaldi.txt

</details>

## Domain-based

This blocklist includes domains and IP addresses.

- https://curben.gitlab.io/malware-filter/pup-filter-domains.txt

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/pup-filter/master/dist/pup-filter-domains.txt
- https://glcdn.githack.com/curben/pup-filter/raw/master/dist/pup-filter-domains.txt
- https://raw.githubusercontent.com/curbengh/pup-filter/master/dist/pup-filter-domains.txt
- https://cdn.statically.io/gh/curbengh/pup-filter/master/dist/pup-filter-domains.txt
- https://gitcdn.xyz/repo/curbengh/pup-filter/master/dist/pup-filter-domains.txt
- https://cdn.jsdelivr.net/gh/curbengh/pup-filter/dist/pup-filter-domains.txt

</details>

## Domain-based (AdGuard Home)

This AdGuard Home-compatible blocklist includes domains and IP addresses.

- https://curben.gitlab.io/malware-filter/pup-filter-agh.txt

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/pup-filter/master/dist/pup-filter-agh.txt
- https://glcdn.githack.com/curben/pup-filter/raw/master/dist/pup-filter-agh.txt
- https://raw.githubusercontent.com/curbengh/pup-filter/master/dist/pup-filter-agh.txt
- https://cdn.statically.io/gh/curbengh/pup-filter/master/dist/pup-filter-agh.txt
- https://gitcdn.xyz/repo/curbengh/pup-filter/master/dist/pup-filter-agh.txt
- https://cdn.jsdelivr.net/gh/curbengh/pup-filter/pup-filter-agh.txt

</details>

## Hosts-based

This blocklist includes domains only.

- https://curben.gitlab.io/malware-filter/pup-filter-hosts.txt

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/pup-filter/master/dist/pup-filter-hosts.txt
- https://glcdn.githack.com/curben/pup-filter/raw/master/dist/pup-filter-hosts.txt
- https://raw.githubusercontent.com/curbengh/pup-filter/master/dist/pup-filter-hosts.txt
- https://cdn.statically.io/gh/curbengh/pup-filter/master/dist/pup-filter-hosts.txt
- https://gitcdn.xyz/repo/curbengh/pup-filter/master/dist/pup-filter-hosts.txt
- https://cdn.jsdelivr.net/gh/curbengh/pup-filter/dist/pup-filter-hosts.txt

</details>

## Dnsmasq

This blocklist includes domains only.

### Install

```
# Create a new folder to store the blocklist
mkdir -p /usr/local/etc/dnsmasq/

# Create a new cron job for daily update
printf '#!/bin/sh\ncurl -L "https://curben.gitlab.io/malware-filter/pup-filter-dnsmasq.conf" -o "/usr/local/etc/dnsmasq/pup-filter-dnsmasq.conf"\n' > /etc/cron.daily/pup-filter

# cron job requires execution permission
chmod 755 /etc/cron.daily/pup-filter

# Configure dnsmasq to use the blocklist
printf "\nconf-file=/usr/local/etc/dnsmasq/pup-filter-dnsmasq.conf\n" >> /etc/dnsmasq.conf
```

- https://curben.gitlab.io/malware-filter/pup-filter-dnsmasq.conf

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/pup-filter/master/dist/pup-filter-dnsmasq.conf
- https://glcdn.githack.com/curben/pup-filter/raw/master/dist/pup-filter-dnsmasq.conf
- https://raw.githubusercontent.com/curbengh/pup-filter/master/dist/pup-filter-dnsmasq.conf
- https://cdn.statically.io/gh/curbengh/pup-filter/master/dist/pup-filter-dnsmasq.conf
- https://gitcdn.xyz/repo/curbengh/pup-filter/master/dist/pup-filter-dnsmasq.conf
- https://cdn.jsdelivr.net/gh/curbengh/pup-filter/dist/pup-filter-dnsmasq.conf

</details>

## BIND

This blocklist includes domains only.

### Install

```
# Create a new folder to store the blocklist
mkdir -p /usr/local/etc/bind/

# Create a new cron job for daily update
printf '#!/bin/sh\ncurl -L "https://curben.gitlab.io/malware-filter/pup-filter-bind.conf" -o "/usr/local/etc/bind/pup-filter-bind.conf"\n' > /etc/cron.daily/pup-filter

# cron job requires execution permission
chmod 755 /etc/cron.daily/pup-filter

# Configure BIND to use the blocklist
printf '\ninclude "/usr/local/etc/bind/pup-filter-bind.conf";\n' >> /etc/bind/named.conf
```

Add this to "/etc/bind/null.zone.file" (skip this step if the file already exists):

```
$TTL    86400   ; one day
@       IN      SOA     ns.nullzone.loc. ns.nullzone.loc. (
               2017102203
                    28800
                     7200
                   864000
                    86400 )
                NS      ns.nullzone.loc.
                A       0.0.0.0
@       IN      A       0.0.0.0
*       IN      A       0.0.0.0
```

Zone file is derived from [here](https://github.com/tomzuu/blacklist-named/blob/master/null.zone.file).

- https://curben.gitlab.io/malware-filter/pup-filter-bind.conf

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/pup-filter/master/dist/pup-filter-bind.conf
- https://glcdn.githack.com/curben/pup-filter/raw/master/dist/pup-filter-bind.conf
- https://raw.githubusercontent.com/curbengh/pup-filter/master/dist/pup-filter-bind.conf
- https://cdn.statically.io/gh/curbengh/pup-filter/master/dist/pup-filter-bind.conf
- https://gitcdn.xyz/repo/curbengh/pup-filter/master/dist/pup-filter-bind.conf
- https://cdn.jsdelivr.net/gh/curbengh/pup-filter/dist/pup-filter-bind.conf

</details>

## Response Policy Zone

This blocklist includes domains only.

- https://curben.gitlab.io/malware-filter/pup-filter-rpz.conf

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/pup-filter/master/dist/pup-filter-rpz.conf
- https://glcdn.githack.com/curben/pup-filter/raw/master/dist/pup-filter-rpz.conf
- https://raw.githubusercontent.com/curbengh/pup-filter/master/dist/pup-filter-rpz.conf
- https://cdn.statically.io/gh/curbengh/pup-filter/master/dist/pup-filter-rpz.conf
- https://gitcdn.xyz/repo/curbengh/pup-filter/master/dist/pup-filter-rpz.conf
- https://cdn.jsdelivr.net/gh/curbengh/pup-filter/dist/pup-filter-rpz.conf

</details>

## Unbound

This blocklist includes domains only.

### Install

```
# Create a new folder to store the blocklist
mkdir -p /usr/local/etc/unbound/

# Create a new cron job for daily update
printf '#!/bin/sh\ncurl -L "https://curben.gitlab.io/malware-filter/pup-filter-unbound.conf" -o "/usr/local/etc/unbound/pup-filter-unbound.conf"\n' > /etc/cron.daily/pup-filter

# cron job requires execution permission
chmod 755 /etc/cron.daily/pup-filter

# Configure Unbound to use the blocklist
printf '\n  include: "/usr/local/etc/unbound/pup-filter-unbound.conf"\n' >> /etc/unbound/unbound.conf
```

- https://curben.gitlab.io/malware-filter/pup-filter-unbound.conf

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/pup-filter/master/dist/pup-filter-unbound.conf
- https://glcdn.githack.com/curben/pup-filter/raw/master/dist/pup-filter-unbound.conf
- https://raw.githubusercontent.com/curbengh/pup-filter/master/dist/pup-filter-unbound.conf
- https://cdn.statically.io/gh/curbengh/pup-filter/master/dist/pup-filter-unbound.conf
- https://gitcdn.xyz/repo/curbengh/pup-filter/master/dist/pup-filter-unbound.conf
- https://cdn.jsdelivr.net/gh/curbengh/pup-filter/dist/pup-filter-unbound.conf

</details>

## Tracking Protection List (IE)

This blocklist includes domains only.

- https://curben.gitlab.io/malware-filter/pup-filter.tpl

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/pup-filter/master/dist/pup-filter.tpl
- https://glcdn.githack.com/curben/pup-filter/raw/master/dist/pup-filter.tpl
- https://raw.githubusercontent.com/curbengh/pup-filter/master/dist/pup-filter.tpl
- https://cdn.statically.io/gh/curbengh/pup-filter/master/dist/pup-filter.tpl
- https://gitcdn.xyz/repo/curbengh/pup-filter/master/dist/pup-filter.tpl
- https://cdn.jsdelivr.net/gh/curbengh/pup-filter/dist/pup-filter.tpl

</details>

## Snort2

This ruleset includes online URLs only. Not compatible with [Snort3](#snort3).

### Install

```
# Download ruleset
curl -L "https://curben.gitlab.io/malware-filter/pup-filter-snort2.rules" -o "/etc/snort/rules/pup-filter-snort2.rules"

# Create a new cron job for daily update
printf '#!/bin/sh\ncurl -L "https://curben.gitlab.io/malware-filter/pup-filter-snort2.rules" -o "/etc/snort/rules/pup-filter-snort2.rules"\n' > /etc/cron.daily/pup-filter

# cron job requires execution permission
chmod 755 /etc/cron.daily/pup-filter

# Configure Snort to use the ruleset
printf "\ninclude \$RULE_PATH/pup-filter-snort2.rules\n" >> /etc/snort/snort.conf
```

- https://curben.gitlab.io/malware-filter/pup-filter-snort2.rules

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/pup-filter/master/dist/pup-filter-snort2.rules
- https://glcdn.githack.com/curben/pup-filter/raw/master/dist/pup-filter-snort2.rules
- https://raw.githubusercontent.com/curbengh/pup-filter/master/dist/pup-filter-snort2.rules
- https://cdn.statically.io/gh/curbengh/pup-filter/master/dist/pup-filter-snort2.rules
- https://gitcdn.xyz/repo/curbengh/pup-filter/master/dist/pup-filter-snort2.rules
- https://cdn.jsdelivr.net/gh/curbengh/pup-filter/dist/pup-filter-snort2.rules

</details>

## Snort3

This ruleset includes online URLs only. Not compatible with [Snort2](#snort2).

### Install

```
# Download ruleset
curl -L "https://curben.gitlab.io/malware-filter/pup-filter-snort3.rules" -o "/etc/snort/rules/pup-filter-snort3.rules"

# Create a new cron job for daily update
printf '#!/bin/sh\ncurl -L "https://curben.gitlab.io/malware-filter/pup-filter-snort3.rules" -o "/etc/snort/rules/pup-filter-snort3.rules"\n' > /etc/cron.daily/pup-filter

# cron job requires execution permission
chmod 755 /etc/cron.daily/pup-filter
```

Configure Snort to use the ruleset:

``` diff
# /etc/snort/snort.lua
ips =
{
  variables = default_variables,
+  include = 'rules/pup-filter-snort3.rules'
}
```

- https://curben.gitlab.io/malware-filter/pup-filter-snort3.rules

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/pup-filter/master/dist/pup-filter-snort3.rules
- https://glcdn.githack.com/curben/pup-filter/raw/master/dist/pup-filter-snort3.rules
- https://raw.githubusercontent.com/curbengh/pup-filter/master/dist/pup-filter-snort3.rules
- https://cdn.statically.io/gh/curbengh/pup-filter/master/dist/pup-filter-snort3.rules
- https://gitcdn.xyz/repo/curbengh/pup-filter/master/dist/pup-filter-snort3.rules
- https://cdn.jsdelivr.net/gh/curbengh/pup-filter/dist/pup-filter-snort3.rules

</details>

## Suricata

This ruleset includes online URLs only.

### Install

```
# Download ruleset
curl -L "https://curben.gitlab.io/malware-filter/pup-filter-suricata.rules" -o "/etc/suricata/rules/pup-filter-suricata.rules"

# Create a new cron job for daily update
printf '#!/bin/sh\ncurl -L "https://curben.gitlab.io/malware-filter/pup-filter-suricata.rules" -o "/etc/suricata/rules/pup-filter-suricata.rules"\n' > /etc/cron.daily/pup-filter

# cron job requires execution permission
chmod 755 /etc/cron.daily/pup-filter
```

Configure Suricata to use the ruleset:

``` diff
# /etc/suricata/suricata.yaml
rule-files:
  - local.rules
+  - pup-filter-suricata.rules
```

- https://curben.gitlab.io/malware-filter/pup-filter-suricata.rules

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/pup-filter/master/dist/pup-filter-suricata.rules
- https://glcdn.githack.com/curben/pup-filter/raw/master/dist/pup-filter-suricata.rules
- https://raw.githubusercontent.com/curbengh/pup-filter/master/dist/pup-filter-suricata.rules
- https://cdn.statically.io/gh/curbengh/pup-filter/master/dist/pup-filter-suricata.rules
- https://gitcdn.xyz/repo/curbengh/pup-filter/master/dist/pup-filter-suricata.rules
- https://cdn.jsdelivr.net/gh/curbengh/pup-filter/dist/pup-filter-suricata.rules

</details>

## Issues

This blocklist operates by blocking the **whole** website, popular websites are excluded from the filters.

*Popular* websites are as listed in the [Umbrella Popularity List](https://s3-us-west-1.amazonaws.com/umbrella-static/index.html) (top 1M domains + subdomains), [Tranco List](https://tranco-list.eu/) (top 1M domains) and this [custom list](src/exclude.txt).

If you wish to exclude certain website(s) that you believe is sufficiently well-known, please create an [issue](https://gitlab.com/curben/pup-filter/issues) or [merge request](https://gitlab.com/curben/pup-filter/merge_requests).

This blocklist **only** accepts new malicious URLs from [malware-discoverer](https://github.com/zhouhanc/malware-discoverer).

## Cloning

Since the filter is updated frequently, cloning the repo would become slower over time as the revision grows.

Use shallow clone to get the recent revisions only. Getting the last five revisions should be sufficient for a valid MR.

`git clone --depth 5 https://gitlab.com/curben/pup-filter.git`

## License

[src/](src/): [CC0](LICENSE.md)

[dist/](dist/): Derivations of [malware-discoverer](https://github.com/zhouhanc/malware-discoverer) with [Zhouhan Chen](https://github.com/zhouhanc)'s permission.

[malware-discoverer](https://github.com/zhouhanc/malware-discoverer): All rights reserved by [Zhouhan Chen](https://github.com/zhouhanc)

[badge.sh](src/badge.sh) & [.gitlab/](.gitlab/) contain badges that are licensed by [Shields.io](https://shields.io) under [CC0 1.0](LICENSE.md)

[Tranco List](https://tranco-list.eu/): MIT License

[Umbrella Popularity List](https://s3-us-west-1.amazonaws.com/umbrella-static/index.html): Available free of charge by Cisco Umbrella
