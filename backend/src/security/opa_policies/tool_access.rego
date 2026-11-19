package secureagent.tool_access

default allow = false

whitelisted_tools := {
    "manager_agent": ["assign_task", "request_human_approval", "query_memory", "fetch_alert"],
    "phishing_agent": ["whois_lookup", "check_domain_reputation", "extract_email_artifacts", "query_threat_intel"],
    "triage_agent": ["enrich_ip", "query_cmdb", "inspect_network_session", "check_firewall_rule"],
    "malware_agent": ["check_virustotal", "sandbox_detonation", "query_yara", "inspect_hash"],
    "threat_intel_agent": ["query_feodo_c2", "query_mitre_attack", "correlate_campaign", "query_threat_intel"],
    "quality_checker": ["verify_evidence_dag", "calculate_egs", "review_verdict"]
}

allow {
    tools := whitelisted_tools[input.agent_role]
    tools[_] == input.tool_name
}
