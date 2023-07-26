# PUP Domains Blocklist

Update (2023-05-10): Daily update of this blocklist has been paused while waiting for the upstream maintainer to complete migrating https://github.com/zhouhanc/malware-discoverer to https://malwarediscoverer.com. No ETC is given. See [issue #2](https://gitlab.com/malware-filter/pup-filter/-/issues/2). Other malware-filter blocklists are not affected.

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

| Client                                            | mirror 1                                                                                           | mirror 2                                                                                     | mirror 3                                                                                 | mirror 4                                                                                       | mirror 5                                                                            | mirror 6                                                                        |
| ------------------------------------------------- | -------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| uBlock Origin, [IP-based](#ip-based)              | [link](https://malware-filter.gitlab.io/malware-filter/pup-filter.txt)                             | [link](https://curbengh.github.io/malware-filter/pup-filter.txt)                             | [link](https://curbengh.github.io/pup-filter/pup-filter.txt)                             | [link](https://malware-filter.gitlab.io/pup-filter/pup-filter.txt)                             | [link](https://malware-filter.pages.dev/pup-filter.txt)                             | [link](https://pup-filter.pages.dev/pup-filter.txt)                             |
| [Pi-hole](#domain-based)                          | [link](https://malware-filter.gitlab.io/malware-filter/pup-filter-domains.txt)                     | [link](https://curbengh.github.io/malware-filter/pup-filter-domains.txt)                     | [link](https://curbengh.github.io/pup-filter/pup-filter-domains.txt)                     | [link](https://malware-filter.gitlab.io/pup-filter/pup-filter-domains.txt)                     | [link](https://malware-filter.pages.dev/pup-filter-domains.txt)                     | [link](https://pup-filter.pages.dev/pup-filter-domains.txt)                     |
| [AdGuard Home](#domain-based-adguard-home)        | [link](https://malware-filter.gitlab.io/malware-filter/pup-filter-agh.txt)                         | [link](https://curbengh.github.io/malware-filter/pup-filter-agh.txt)                         | [link](https://curbengh.github.io/pup-filter/pup-filter-agh.txt)                         | [link](https://malware-filter.gitlab.io/pup-filter/pup-filter-agh.txt)                         | [link](https://malware-filter.pages.dev/pup-filter-agh.txt)                         | [link](https://pup-filter.pages.dev/pup-filter-agh.txt)                         |
| [AdGuard (browser extension)](#ip-based-adguard)  | [link](https://malware-filter.gitlab.io/malware-filter/pup-filter-ag.txt)                          | [link](https://curbengh.github.io/malware-filter/pup-filter-ag.txt)                          | [link](https://curbengh.github.io/pup-filter/pup-filter-ag.txt)                          | [link](https://malware-filter.gitlab.io/pup-filter/pup-filter-ag.txt)                          | [link](https://malware-filter.pages.dev/pup-filter-ag.txt)                          | [link](https://pup-filter.pages.dev/pup-filter-ag.txt)                          |
| [Vivaldi](#ip-based-vivaldi)                      | [link](https://malware-filter.gitlab.io/malware-filter/pup-filter-vivaldi.txt)                     | [link](https://curbengh.github.io/malware-filter/pup-filter-vivaldi.txt)                     | [link](https://curbengh.github.io/pup-filter/pup-filter-vivaldi.txt)                     | [link](https://malware-filter.gitlab.io/pup-filter/pup-filter-vivaldi.txt)                     | [link](https://malware-filter.pages.dev/pup-filter-vivaldi.txt)                     | [link](https://pup-filter.pages.dev/pup-filter-vivaldi.txt)                     |
| [Hosts](#hosts-based)                             | [link](https://malware-filter.gitlab.io/malware-filter/pup-filter-hosts.txt)                       | [link](https://curbengh.github.io/malware-filter/pup-filter-hosts.txt)                       | [link](https://curbengh.github.io/pup-filter/pup-filter-hosts.txt)                       | [link](https://malware-filter.gitlab.io/pup-filter/pup-filter-hosts.txt)                       | [link](https://malware-filter.pages.dev/pup-filter-hosts.txt)                       | [link](https://pup-filter.pages.dev/pup-filter-hosts.txt)                       |
| [Dnsmasq](#dnsmasq)                               | [link](https://malware-filter.gitlab.io/malware-filter/pup-filter-dnsmasq.conf)                    | [link](https://curbengh.github.io/malware-filter/pup-filter-dnsmasq.conf)                    | [link](https://curbengh.github.io/pup-filter/pup-filter-dnsmasq.conf)                    | [link](https://malware-filter.gitlab.io/pup-filter/pup-filter-dnsmasq.conf)                    | [link](https://malware-filter.pages.dev/pup-filter-dnsmasq.conf)                    | [link](https://pup-filter.pages.dev/pup-filter-dnsmasq.conf)                    |
| BIND [zone](#bind)                                | [link](https://malware-filter.gitlab.io/malware-filter/pup-filter-bind.conf)                       | [link](https://curbengh.github.io/malware-filter/pup-filter-bind.conf)                       | [link](https://curbengh.github.io/pup-filter/pup-filter-bind.conf)                       | [link](https://malware-filter.gitlab.io/pup-filter/pup-filter-bind.conf)                       | [link](https://malware-filter.pages.dev/pup-filter-bind.conf)                       | [link](https://pup-filter.pages.dev/pup-filter-bind.conf)                       |
| BIND [RPZ](#response-policy-zone)                 | [link](https://malware-filter.gitlab.io/malware-filter/pup-filter-rpz.conf)                        | [link](https://curbengh.github.io/malware-filter/pup-filter-rpz.conf)                        | [link](https://curbengh.github.io/pup-filter/pup-filter-rpz.conf)                        | [link](https://malware-filter.gitlab.io/pup-filter/pup-filter-rpz.conf)                        | [link](https://malware-filter.pages.dev/pup-filter-rpz.conf)                        | [link](https://pup-filter.pages.dev/pup-filter-rpz.conf)                        |
| [dnscrypt-proxy](#dnscrypt-proxy)                 | [names.txt](https://malware-filter.gitlab.io/malware-filter/pup-filter-dnscrypt-blocked-names.txt) | [names.txt](https://curbengh.github.io/malware-filter/pup-filter-dnscrypt-blocked-names.txt) | [names.txt](https://curbengh.github.io/pup-filter/pup-filter-dnscrypt-blocked-names.txt) | [names.txt](https://malware-filter.gitlab.io/pup-filter/pup-filter-dnscrypt-blocked-names.txt) | [names.txt](https://malware-filter.pages.dev/pup-filter-dnscrypt-blocked-names.txt) | [names.txt](https://pup-filter.pages.dev/pup-filter-dnscrypt-blocked-names.txt) |
| [Internet Explorer](#tracking-protection-list-ie) | [link](https://malware-filter.gitlab.io/malware-filter/pup-filter.tpl)                             | [link](https://curbengh.github.io/malware-filter/pup-filter.tpl)                             | [link](https://curbengh.github.io/pup-filter/pup-filter.tpl)                             | [link](https://malware-filter.gitlab.io/pup-filter/pup-filter.tpl)                             | [link](https://malware-filter.pages.dev/pup-filter.tpl)                             | [link](https://pup-filter.pages.dev/pup-filter.tpl)                             |
| [Snort2](#snort2)                                 | [link](https://malware-filter.gitlab.io/malware-filter/pup-filter-snort2.rules)                    | [link](https://curbengh.github.io/malware-filter/pup-filter-snort2.rules)                    | [link](https://curbengh.github.io/pup-filter/pup-filter-snort2.rules)                    | [link](https://malware-filter.gitlab.io/pup-filter/pup-filter-snort2.rules)                    | [link](https://malware-filter.pages.dev/pup-filter-snort2.rules)                    | [link](https://pup-filter.pages.dev/pup-filter-snort2.rules)                    |
| [Snort3](#snort3)                                 | [link](https://malware-filter.gitlab.io/malware-filter/pup-filter-snort3.rules)                    | [link](https://curbengh.github.io/malware-filter/pup-filter-snort3.rules)                    | [link](https://curbengh.github.io/pup-filter/pup-filter-snort3.rules)                    | [link](https://malware-filter.gitlab.io/pup-filter/pup-filter-snort3.rules)                    | [link](https://malware-filter.pages.dev/pup-filter-snort3.rules)                    | [link](https://pup-filter.pages.dev/pup-filter-snort3.rules)                    |
| [Suricata](#suricata)                             | [link](https://malware-filter.gitlab.io/malware-filter/pup-filter-suricata.rules)                  | [link](https://curbengh.github.io/malware-filter/pup-filter-suricata.rules)                  | [link](https://curbengh.github.io/pup-filter/pup-filter-suricata.rules)                  | [link](https://malware-filter.gitlab.io/pup-filter/pup-filter-suricata.rules)                  | [link](https://malware-filter.pages.dev/pup-filter-suricata.rules)                  | [link](https://pup-filter.pages.dev/pup-filter-suricata.rules)                  |
| [Splunk](#splunk)                                 | [link](https://malware-filter.gitlab.io/malware-filter/pup-filter-splunk.csv)                      | [link](https://curbengh.github.io/malware-filter/pup-filter-splunk.csv)                      | [link](https://curbengh.github.io/pup-filter/pup-filter-splunk.csv)                      | [link](https://malware-filter.gitlab.io/pup-filter/pup-filter-splunk.csv)                      | [link](https://malware-filter.pages.dev/pup-filter-splunk.csv)                      | [link](https://pup-filter.pages.dev/pup-filter-splunk.csv)                      |

For other programs, see [Compatibility](https://gitlab.com/malware-filter/malware-filter/wikis/compatibility) page in the wiki.

Check out my other filters:

- [urlhaus-filter](https://gitlab.com/malware-filter/urlhaus-filter)
- [phishing-filter](https://gitlab.com/malware-filter/phishing-filter)
- [tracking-filter](https://gitlab.com/malware-filter/tracking-filter)
- [vn-badsite-filter](https://gitlab.com/malware-filter/vn-badsite-filter)

## URL-based

Import the link into uBO's filter list to subscribe.

_included by default in uBO >=[1.39.0](https://github.com/gorhill/uBlock/releases/tag/1.39.0); to enable, head to "Filter lists" tab, expand "Malware domains" section and tick "PUP URL Blocklist"._

## URL-based (AdGuard)

Import the link into AdGuard browser extension to subscribe.

## URL-based (Vivaldi)

_Requires Vivaldi Desktop/Android 3.3+, blocking level must be at least "Block Trackers"_

Import the link into Vivaldi's **Tracker Blocking Sources** to subscribe.

## Domain-based

This blocklist includes domains and IP addresses.

## Domain-based (AdGuard Home)

This AdGuard Home-compatible blocklist includes domains and IP addresses.

## Hosts-based

This blocklist includes domains only.

## Dnsmasq

This blocklist includes domains only.

Save the ruleset to "/usr/local/etc/dnsmasq/pup-filter-dnsmasq.conf". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure dnsmasq to use the blocklist:

`printf "\nconf-file=/usr/local/etc/dnsmasq/pup-filter-dnsmasq.conf\n" >> /etc/dnsmasq.conf`

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

## Response Policy Zone

This blocklist includes domains only.

## Unbound

This blocklist includes domains only.

Save the rulesets to "/usr/local/etc/unbound/pup-filter-unbound.conf". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure Unbound to use the blocklist:

`printf '\n  include: "/usr/local/etc/unbound/pup-filter-unbound.conf"\n' >> /etc/unbound/unbound.conf`

## dnscrypt-proxy

Save the rulesets to "/etc/dnscrypt-proxy/". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure dnscrypt-proxy to use the blocklist:

```diff
[blocked_names]
+  blocked_names_file = '/etc/dnscrypt-proxy/pup-filter-dnscrypt-blocked-names.txt'
```

## Tracking Protection List (IE)

This blocklist includes domains only.

## Snort2

Not compatible with [Snort3](#snort3).

Save the ruleset to "/etc/snort/rules/pup-filter-snort2.rules". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure Snort to use the ruleset:

`printf "\ninclude \$RULE_PATH/pup-filter-snort2.rules\n" >> /etc/snort/snort.conf`

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

## Suricata

Save the ruleset to "/etc/suricata/rules/pup-filter-suricata.rules". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure Suricata to use the ruleset:

```diff
# /etc/suricata/suricata.yaml
rule-files:
  - local.rules
+  - pup-filter-suricata.rules
```

## Splunk

A CSV file for Splunk [lookup](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Aboutlookupsandfieldactions).

Either upload the file via GUI or save the file in `$SPLUNK_HOME/Splunk/etc/system/lookups` or app-specific `$SPLUNK_HOME/etc/YourApp/apps/search/lookups`.

Or use [malware-filter add-on](https://splunkbase.splunk.com/app/6970) to install this lookup and optionally auto-update it.

Columns:

| host         | path       | message                         | updated              |
| ------------ | ---------- | ------------------------------- | -------------------- |
| example.com  |            | pup-filter PUP website detected | 2022-12-21T12:34:56Z |
| example2.com | /some-path | pup-filter PUP website detected | 2022-12-21T12:34:56Z |

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

## Repository Mirrors

https://gitlab.com/curben/blog#repository-mirrors

## License

[src/](src/): [Creative Commons Zero v1.0 Universal](LICENSE-CC0.md) and [MIT License](LICENSE)

filters: Derived from [malware-discoverer](https://github.com/zhouhanc/malware-discoverer) with [Zhouhan Chen](https://zhouhanc.com/)'s permission

[malware-discoverer](https://github.com/zhouhanc/malware-discoverer): All rights reserved by [Zhouhan Chen](https://zhouhanc.com/)

[Tranco List](https://tranco-list.eu/): MIT License

[Umbrella Popularity List](https://s3-us-west-1.amazonaws.com/umbrella-static/index.html): Available free of charge by Cisco Umbrella

[Cloudflare Radar](https://developers.cloudflare.com/radar/investigate/domain-ranking-datasets/): Available to free Cloudflare account
