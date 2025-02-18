def telemetryHeaders(session : None):
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "User-Agent": "CyberArk/1.0 (Ansible; cyberark.isp)"
    }
    if session is not None:
        pass
    return headers
