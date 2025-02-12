"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""

WIDGET_NAMES = {
    "Threats Timeline": "threats_timeline",
    "Incidents Timeline": "incidents_timeline",
    "Source Country": "srccountry",
    "Attack Type": "attack_type",
    "High Risk": "high_risk",
    "Http Host": "http_host"
}

GROUP_BY = {
    "Logs": "logs",
    "Attack Type": "attack_type",
    "Source Country": "srccountry",
    "HTTP Host": "http_host",
    "HTTP URL": "http_url",
    "Source IP": "src_ip",
    "Signature CVE ID": "signature_cve_id",
    "OWASP TOP10": "owasp_top10"
}

EVENT_TYPE = {
    "Exposed Server": "exposed_server",
    "Trust IP": "trust_ip",
    "Unprotected Host": "unprotected_host",
    "Monitor Service": "monitor_service",
    "WAF Config Alarm": "waf_config_alarm"
}

IP_TYPE = {
    "Trust IP": "trust-ip",
    "Block IP": "block-ip",
    "Allow Only IP": "allow-only-ip"
}
