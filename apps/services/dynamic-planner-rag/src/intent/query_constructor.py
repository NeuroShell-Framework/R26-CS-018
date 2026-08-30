MODIFIER_TEXT_MAP = {
    "stealth": "SYN stealth scan half-open technique",
    "aggressive": "aggressive scan OS detection version detection all ports",
    "all-ports": "scan all 65535 ports complete port range",
    "quick": "fast scan top 100 common ports timing",
    "os-detection": "operating system fingerprinting OS detection",
    "ssl": "HTTPS SSL TLS certificate secure connection port 443",
    "silent": "quiet mode suppress output no progress bar",
    "full": "full scan all directories check all",
    "evasion": "IDS evasion technique bypass detection encoding",
    "extension:php": "PHP file extension search .php files",
    "extension:html": "HTML file extension search .html files",
    "dns": "DNS subdomain enumeration domain brute force",
    "vhost": "virtual host enumeration vhost mode",
    "wordlist:common": "common wordlist dirb small fast",
    "wordlist:medium": "medium wordlist dirbuster standard coverage",
}

QUERY_TEMPLATES = {
    "NETWORK_SCAN": "nmap {modifiers} network port scan syntax flags {target_type}",
    "SERVICE_ENUMERATION": "nmap service version detection banner grabbing {modifiers}",
    "VULNERABILITY_AUDIT": "nikto web vulnerability scan {modifiers} {target_type} port {ports}",
    "DIRECTORY_BRUTEFORCE": "gobuster directory enumeration wordlist {modifiers} {target_type}",
    "EXPLOITATION": "metasploit exploit command syntax required options payload {cve}",
    "PASSWORD_ATTACK": "hydra brute force {target_type} command syntax",
    "PASSIVE_RECON": "whois DNS reconnaissance OSINT command syntax",
}


class QueryConstructor:
    def build_query(self, params: dict) -> str:
        intent = params["intent"]
        modifiers = params.get("modifiers", [])
        target_type = params.get("target_type", "IP").lower()
        ports = params.get("ports", [])
        cve_ids = params.get("cve_ids", [])

        modifier_text = " ".join(
            MODIFIER_TEXT_MAP.get(m, m) for m in modifiers
        )

        template = QUERY_TEMPLATES.get(
            intent,
            "security tool command syntax {modifiers} {target_type}"
        )

        query = template.format(
            modifiers=modifier_text,
            target_type=target_type,
            ports=" ".join(str(p) for p in ports) if ports else "",
            cve=" ".join(cve_ids) if cve_ids else "",
        ).strip()

        import re
        query = re.sub(r"\s+", " ", query)

        return query