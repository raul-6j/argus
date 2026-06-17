# FEATURE_CATALOG.md — ARGUS Feature Catalog
Populate during M3 (Weeks 5–6). Update Status as features are implemented.
Extraction paths: **Static** = URL string only, no request | **Live** = requires HTTP fetch

---

## Category 1 — URL Lexical Features (Static)

| # | Feature | Type | Extraction | Importance | Status |
|---|---|---|---|---|---|
| F01 | url_length | int | len(url) | High | ☐ |
| F02 | hostname_length | int | tldextract | Med | ☐ |
| F03 | path_length | int | urllib.parse | Med | ☐ |
| F04 | num_dots | int | url.count('.') | High | ☐ |
| F05 | num_hyphens_hostname | int | hostname.count('-') | High | ☐ |
| F06 | num_at_symbols | int | url.count('@') | High | ☐ |
| F07 | num_question_marks | int | url.count('?') | Med | ☐ |
| F08 | num_percent_encoding | int | url.count('%') | Med | ☐ |
| F09 | has_ip_address | bool | regex IPv4/IPv6 | Very High | ☐ |
| F10 | has_https | bool | urlparse.scheme | Med | ☐ |
| F11 | has_port | bool | urlparse.port | High | ☐ |
| F12 | num_subdomains | int | tldextract subdomain | High | ☐ |
| F13 | is_suspicious_tld | bool | tldextract suffix vs. list (.tk .ml .ga .cf .xyz) | High | ☐ |
| F14 | has_suspicious_keywords | bool | regex (login, verify, secure, update, account, bank, signin) | High | ☐ |
| F15 | digit_ratio | float | sum(c.isdigit())/len(url) | Med | ☐ |
| F16 | url_entropy | float | Shannon entropy of URL string | Med | ☐ |
| F17 | has_double_slash_redirect | bool | url.find('//', 7) > -1 | High | ☐ |
| F18 | prefix_suffix_hyphen | bool | '-' in tldextract.registered_domain | High | ☐ |

## Category 2 — Domain Intelligence Features (Static + External Lookup)
Slow (100–500ms). Use threading for real-time inference path.

| # | Feature | Type | Extraction | Importance | Status |
|---|---|---|---|---|---|
| F19 | domain_age_days | int | python-whois creation_date | Very High | ☐ |
| F20 | is_recently_registered | bool | F19 < 30 days | Very High | ☐ |
| F21 | days_until_expiry | int | python-whois expiration_date | Med-High | ☐ |
| F22 | dns_record_exists | bool | dnspython A record lookup | High | ☐ |
| F23 | mx_record_exists | bool | dnspython MX record lookup | Med | ☐ |

## Category 3 — HTML Content Features (Live Fetch Required)
Used in real-time web app inference. Not in UCI pre-engineered dataset.

| # | Feature | Type | Extraction | Importance | Status |
|---|---|---|---|---|---|
| F24 | num_external_links | int | BeautifulSoup `<a href>` + domain compare | High | ☐ |
| F25 | external_link_ratio | float | F24 / total links | High | ☐ |
| F26 | num_forms | int | soup.find_all('form') | High | ☐ |
| F27 | has_password_field | bool | input[type=password] | Very High | ☐ |
| F28 | has_iframe | bool | soup.find_all('iframe') | High | ☐ |
| F29 | has_hidden_elements | bool | display:none / visibility:hidden | Med | ☐ |
| F30 | right_click_disabled | bool | oncontextmenu in scripts | Med | ☐ |
| F31 | has_favicon | bool | link[rel=icon] | Med | ☐ |
| F32 | has_copyright | bool | © or 'copyright' in visible text | Med | ☐ |

---

## UCI Dataset Pre-Engineered Features (30 features — used directly in training)
UCI features are already encoded as −1 / 0 / 1. Map to ARGUS features where overlapping.

| UCI Feature | ARGUS Equivalent |
|---|---|
| having_IP_Address | F09 |
| URL_Length | F01 |
| having_At_Symbol | F06 |
| double_slash_redirecting | F17 |
| Prefix_Suffix | F18 |
| having_Sub_Domain | F12 |
| Domain_registeration_length | F21 |
| Favicon | F31 |
| port | F11 |
| age_of_domain | F19/F20 |
| DNSRecord | F22 |
| Iframe | F28 |
| popUpWidnow | — |
| RightClick | F30 |
| Request_URL | F25 |
| URL_of_Anchor | F24 |
| SFH (Server Form Handler) | — |
| Redirect | — |
| SSLfinal_State | F10 |
| web_traffic (Alexa rank) | — |
| *remaining 10 UCI features* | — (used as-is from dataset) |

---

## Post-EDA Notes (Fill after Week 3–4)
- Features dropped (low variance / high null rate / redundant): *[fill]*
- Encoding strategy for categorical features (e.g., TLD): *[fill]*
- Final feature count entering model training: *[fill]*
- Feature selection method applied (if any): *[fill]*
