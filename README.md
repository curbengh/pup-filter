# PUP Domains Blocklist

- Formats
  - [URL-based](#url-based)
  - [Domain-based](#domain-based)
  - [Hosts-based](#hosts-based)
  - [Domain-based (AdGuard Home)](#domain-based-adguard-home)
  - [URL-based (AdGuard)](#url-based-adguard)
  - [URL-based (Vivaldi)](#url-based-vivaldi)
  - [Dnsmasq](#dnsmasq)
  - [BIND zone](#bind)
  - [RPZ](#response-policy-zone)
  - [Unbound](#unbound)
  - [dnscrypt-proxy](#dnscrypt-proxy)
  - [Tracking Protection List (IE)](#tracking-protection-list-ie)
  - [Snort2](#snort2)
  - [Snort3](#snort3)
  - [Suricata](#suricata)
  - [Splunk](#splunk)
- [Compressed version](#compressed-version)
- [Reporting issues](#issues)
- [FAQ and Guides](#faq-and-guides)
- [CI Variables](#ci-variables)
- [License](#license)

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
- [dnscrypt-proxy](#dnscrypt-proxy)
- Internet Explorer -> [Tracking Protection List (IE)](#tracking-protection-list-ie)
- [Snort2](#snort2)
- [Snort3](#snort3)
- [Suricata](#suricata)
- [Splunk](#splunk)

For other programs, see [Compatibility](https://gitlab.com/malware-filter/malware-filter/wikis/compatibility) page in the wiki.

Check out my other filters:

- [urlhaus-filter](https://gitlab.com/malware-filter/urlhaus-filter)
- [phishing-filter](https://gitlab.com/malware-filter/phishing-filter)
- [tracking-filter](https://gitlab.com/malware-filter/tracking-filter)
- [vn-badsite-filter](https://gitlab.com/malware-filter/vn-badsite-filter)

## URL-based

Import the following URL into uBO to subscribe:

- https://malware-filter.gitlab.io/malware-filter/pup-filter.txt

_included by default in uBO >=[1.39.0](https://github.com/gorhill/uBlock/releases/tag/1.39.0); to enable, head to "Filter lists" tab, expand "Malware domains" section and tick "PUP URL Blocklist"._

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/pup-filter.txt
- https://curbengh.github.io/pup-filter/pup-filter.txt
- https://malware-filter.gitlab.io/pup-filter/pup-filter.txt
- https://malware-filter.pages.dev/pup-filter.txt
- https://pup-filter.pages.dev/pup-filter.txt

</details>

## URL-based (AdGuard)

Import the following URL into AdGuard browser extension to subscribe:

- https://malware-filter.gitlab.io/malware-filter/pup-filter-ag.txt

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/pup-filter-ag.txt
- https://curbengh.github.io/pup-filter/pup-filter-ag.txt
- https://malware-filter.gitlab.io/pup-filter/pup-filter-ag.txt
- https://malware-filter.pages.dev/pup-filter-ag.txt
- https://pup-filter.pages.dev/pup-filter-ag.txt

</details>

## URL-based (Vivaldi)

_Requires Vivaldi Desktop/Android 3.3+, blocking level must be at least "Block Trackers"_

Import the following URL into Vivaldi's **Tracker Blocking Sources** to subscribe:

- https://malware-filter.gitlab.io/malware-filter/pup-filter-vivaldi.txt

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/pup-filter-vivaldi.txt
- https://curbengh.github.io/pup-filter/pup-filter-vivaldi.txt
- https://malware-filter.gitlab.io/pup-filter/pup-filter-vivaldi.txt
- https://malware-filter.pages.dev/pup-filter-vivaldi.txt
- https://pup-filter.pages.dev/pup-filter-vivaldi.txt

</details>

## Domain-based

This blocklist includes domains and IP addresses.

- https://malware-filter.gitlab.io/malware-filter/pup-filter-domains.txt

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/pup-filter-domains.txt
- https://curbengh.github.io/pup-filter/pup-filter-domains.txt
- https://malware-filter.gitlab.io/pup-filter/pup-filter-domains.txt
- https://malware-filter.pages.dev/pup-filter-domains.txt
- https://pup-filter.pages.dev/pup-filter-domains.txt

</details>

## Domain-based (AdGuard Home)

This AdGuard Home-compatible blocklist includes domains and IP addresses.

- https://malware-filter.gitlab.io/malware-filter/pup-filter-agh.txt

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/pup-filter-agh.txt
- https://curbengh.github.io/pup-filter/pup-filter-agh.txt
- https://malware-filter.gitlab.io/pup-filter/pup-filter-agh.txt
- https://malware-filter.pages.dev/pup-filter-agh.txt
- https://pup-filter.pages.dev/pup-filter-agh.txt

</details>

## Hosts-based

This blocklist includes domains only.

- https://malware-filter.gitlab.io/malware-filter/pup-filter-hosts.txt

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/pup-filter-hosts.txt
- https://curbengh.github.io/pup-filter/pup-filter-hosts.txt
- https://malware-filter.gitlab.io/pup-filter/pup-filter-hosts.txt
- https://malware-filter.pages.dev/pup-filter-hosts.txt
- https://pup-filter.pages.dev/pup-filter-hosts.txt

</details>

## Dnsmasq

This blocklist includes domains only.

Save the ruleset to "/usr/local/etc/dnsmasq/pup-filter-dnsmasq.conf". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure dnsmasq to use the blocklist:

`printf "\nconf-file=/usr/local/etc/dnsmasq/pup-filter-dnsmasq.conf\n" >> /etc/dnsmasq.conf`

- https://malware-filter.gitlab.io/malware-filter/pup-filter-dnsmasq.conf

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/pup-filter-dnsmasq.conf
- https://curbengh.github.io/pup-filter/pup-filter-dnsmasq.conf
- https://malware-filter.gitlab.io/pup-filter/pup-filter-dnsmasq.conf
- https://malware-filter.pages.dev/pup-filter-dnsmasq.conf
- https://pup-filter.pages.dev/pup-filter-dnsmasq.conf

</details>

## BIND

This blocklist includes domains only.

Save the ruleset to "/usr/local/etc/bind/pup-filter-bind.conf". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure BIND to use the blocklist:

`printf '\ninclude "/usr/local/etc/bind/pup-filter-bind.conf";\n' >> /etc/bind/named.conf`

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

- https://malware-filter.gitlab.io/malware-filter/pup-filter-bind.conf

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/pup-filter-bind.conf
- https://curbengh.github.io/pup-filter/pup-filter-bind.conf
- https://malware-filter.gitlab.io/pup-filter/pup-filter-bind.conf
- https://malware-filter.pages.dev/pup-filter-bind.conf
- https://pup-filter.pages.dev/pup-filter-bind.conf

</details>

## Response Policy Zone

This blocklist includes domains only.

- https://malware-filter.gitlab.io/malware-filter/pup-filter-rpz.conf

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/pup-filter-rpz.conf
- https://curbengh.github.io/pup-filter/pup-filter-rpz.conf
- https://malware-filter.gitlab.io/pup-filter/pup-filter-rpz.conf
- https://malware-filter.pages.dev/pup-filter-rpz.conf
- https://pup-filter.pages.dev/pup-filter-rpz.conf

</details>

## Unbound

This blocklist includes domains only.

Save the rulesets to "/usr/local/etc/unbound/pup-filter-unbound.conf". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure Unbound to use the blocklist:

`printf '\n  include: "/usr/local/etc/unbound/pup-filter-unbound.conf"\n' >> /etc/unbound/unbound.conf`

- https://malware-filter.gitlab.io/malware-filter/pup-filter-unbound.conf

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/pup-filter-unbound.conf
- https://curbengh.github.io/pup-filter/pup-filter-unbound.conf
- https://malware-filter.gitlab.io/pup-filter/pup-filter-unbound.conf
- https://malware-filter.pages.dev/pup-filter-unbound.conf
- https://pup-filter.pages.dev/pup-filter-unbound.conf

</details>

## dnscrypt-proxy

Save the rulesets to "/etc/dnscrypt-proxy/". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure dnscrypt-proxy to use the blocklist:

```diff
[blocked_names]
+  blocked_names_file = '/etc/dnscrypt-proxy/pup-filter-dnscrypt-blocked-names.txt'
```

- https://malware-filter.gitlab.io/malware-filter/pup-filter-dnscrypt-blocked-names.txt

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/pup-filter-dnscrypt-blocked-names.txt
- https://curbengh.github.io/pup-filter/pup-filter-dnscrypt-blocked-names.txt
- https://malware-filter.gitlab.io/pup-filter/pup-filter-dnscrypt-blocked-names.txt
- https://malware-filter.pages.dev/pup-filter-dnscrypt-blocked-names.txt
- https://pup-filter.pages.dev/pup-filter-dnscrypt-blocked-names.txt

</details>

## Tracking Protection List (IE)

This blocklist includes domains only.

- https://malware-filter.gitlab.io/malware-filter/pup-filter.tpl

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/pup-filter.tpl
- https://curbengh.github.io/pup-filter/pup-filter.tpl
- https://malware-filter.gitlab.io/pup-filter/pup-filter.tpl
- https://malware-filter.pages.dev/pup-filter.tpl
- https://pup-filter.pages.dev/pup-filter.tpl

</details>

## Snort2

Not compatible with [Snort3](#snort3).

Save the ruleset to "/etc/snort/rules/pup-filter-snort2.rules". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure Snort to use the ruleset:

`printf "\ninclude \$RULE_PATH/pup-filter-snort2.rules\n" >> /etc/snort/snort.conf`

- https://malware-filter.gitlab.io/malware-filter/pup-filter-snort2.rules

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/pup-filter-snort2.rules
- https://curbengh.github.io/pup-filter/pup-filter-snort2.rules
- https://malware-filter.gitlab.io/pup-filter/pup-filter-snort2.rules
- https://malware-filter.pages.dev/pup-filter-snort2.rules
- https://pup-filter.pages.dev/pup-filter-snort2.rules

</details>

## Snort3

Not compatible with [Snort2](#snort2).

Save the ruleset to "/etc/snort/rules/pup-filter-snort3.rules". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure Snort to use the ruleset:

```diff
# /etc/snort/snort.lua
ips =
{
  variables = default_variables,
+  include = 'rules/pup-filter-snort3.rules'
}
```

- https://malware-filter.gitlab.io/malware-filter/pup-filter-snort3.rules

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/pup-filter-snort3.rules
- https://curbengh.github.io/pup-filter/pup-filter-snort3.rules
- https://malware-filter.gitlab.io/pup-filter/pup-filter-snort3.rules
- https://malware-filter.pages.dev/pup-filter-snort3.rules
- https://pup-filter.pages.dev/pup-filter-snort3.rules

</details>

## Suricata

Save the ruleset to "/etc/suricata/rules/pup-filter-suricata.rules". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure Suricata to use the ruleset:

```diff
# /etc/suricata/suricata.yaml
rule-files:
  - local.rules
+  - pup-filter-suricata.rules
```

- https://malware-filter.gitlab.io/malware-filter/pup-filter-suricata.rules

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/pup-filter-suricata.rules
- https://curbengh.github.io/pup-filter/pup-filter-suricata.rules
- https://malware-filter.gitlab.io/pup-filter/pup-filter-suricata.rules
- https://malware-filter.pages.dev/pup-filter-suricata.rules
- https://pup-filter.pages.dev/pup-filter-suricata.rules

</details>

## Splunk

A CSV file for Splunk [lookup](https://docs.splunk.com/Documentation/Splunk/9.0.2/Knowledge/Aboutlookupsandfieldactions).

Either upload the file via GUI or save the file in `$SPLUNK_HOME/Splunk/etc/system/lookups` or app-specific `$SPLUNK_HOME/etc/YourApp/apps/search/lookups`. Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) or [Getwatchlist](https://splunkbase.splunk.com/app/635) app for auto-update.

Columns:

| host         | path       | message                         | updated              |
| ------------ | ---------- | ------------------------------- | -------------------- |
| example.com  |            | pup-filter PUP website detected | 2022-12-21T12:34:56Z |
| example2.com | /some-path | pup-filter PUP website detected | 2022-12-21T12:34:56Z |

- https://malware-filter.gitlab.io/malware-filter/pup-filter-splunk.csv

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/pup-filter-splunk.csv
- https://curbengh.github.io/pup-filter/pup-filter-splunk.csv
- https://malware-filter.gitlab.io/pup-filter/pup-filter-splunk.csv
- https://malware-filter.pages.dev/pup-filter-splunk.csv
- https://pup-filter.pages.dev/pup-filter-splunk.csv

</details>

## Compressed version

All filters are also available as gzip- and brotli-compressed.

- Gzip: https://malware-filter.gitlab.io/malware-filter/pup-filter.txt.gz
- Brotli: https://malware-filter.gitlab.io/malware-filter/pup-filter.txt.br

## Issues

This blocklist operates by blocking the **whole** website, popular websites are excluded from the filters.

_Popular_ websites are as listed in the [Umbrella Popularity List](https://s3-us-west-1.amazonaws.com/umbrella-static/index.html) (top 1M domains + subdomains), [Tranco List](https://tranco-list.eu/) (top 1M domains), [Cloudflare Radar](https://developers.cloudflare.com/radar/investigate/domain-ranking-datasets/) (top 1M domains) and this [custom list](src/exclude.txt).

If you wish to exclude certain website(s) that you believe is sufficiently well-known, please create an [issue](https://gitlab.com/malware-filter/pup-filter/issues) or [merge request](https://gitlab.com/malware-filter/pup-filter/merge_requests).

This blocklist **only** accepts new malicious URLs from [malware-discoverer](https://github.com/zhouhanc/malware-discoverer).

## FAQ and Guides

See [wiki](https://gitlab.com/malware-filter/malware-filter/-/wikis/home)

## CI Variables

Optional variables:

- `CLOUDFLARE_BUILD_HOOK`: Deploy to Cloudflare Pages.
- `NETLIFY_SITE_ID`: Deploy to Netlify.
- `CF_API`: Include Cloudflare Radar [domains ranking](https://developers.cloudflare.com/radar/investigate/domain-ranking-datasets/). [Guide](https://developers.cloudflare.com/radar/get-started/first-request/) to create an API token.

## License

[src/](src/): [Creative Commons Zero v1.0 Universal](LICENSE-CC0.md) and [MIT License](LICENSE)

filters: Derived from [malware-discoverer](https://github.com/zhouhanc/malware-discoverer) with [Zhouhan Chen](https://zhouhanc.com/)'s permission

[malware-discoverer](https://github.com/zhouhanc/malware-discoverer): All rights reserved by [Zhouhan Chen](https://zhouhanc.com/)

[Tranco List](https://tranco-list.eu/): MIT License

[Umbrella Popularity List](https://s3-us-west-1.amazonaws.com/umbrella-static/index.html): Available free of charge by Cisco Umbrella

[Cloudflare Radar](https://developers.cloudflare.com/radar/investigate/domain-ranking-datasets/): Available to free Cloudflare account
