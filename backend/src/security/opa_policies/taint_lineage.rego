package secureagent.taint_lineage

default allow_execution = false

critical_tools := {"isolate_host", "block_firewall_ip", "disable_user_account", "revoke_session_token"}

# 1. Allow non-critical tools regardless of taint
allow_execution {
    not critical_tools[input.tool_name]
}

# 2. Allow critical tools if taint is low (<= 0.40)
allow_execution {
    critical_tools[input.tool_name]
    input.taint_score <= 0.40
}

# 3. Allow critical tools if taint is high (> 0.40) ONLY with explicit human approval
allow_execution {
    critical_tools[input.tool_name]
    input.taint_score > 0.40
    input.human_approved == true
}
