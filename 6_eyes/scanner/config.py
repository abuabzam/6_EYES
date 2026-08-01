COMMON_PORTS = (
    20, 21, 22, 23,
    25, 53, 80,
    110, 135, 139,
    143, 443,
    445, 3306,
    3389
)

TIMEOUT = 5

BUFFER_SIZE = 1024

SERVICE_SIGNATURES = {
    "SSH": "SSH",
    "OPENSSH": "SSH",

    "FTP": "FTP",

    "SMTP": "SMTP",
    "ESMTP": "SMTP",

    "HTTP": "HTTP",
    "APACHE": "HTTP",
    "NGINX": "HTTP",
    "MICROSOFT-IIS": "HTTP",

    "HTTPS": "HTTPS",

    "MYSQL": "MySQL",

    "POSTGRESQL": "PostgreSQL",

    "REDIS": "Redis",

    "TELNET": "Telnet",

    "POP3": "POP3",

    "IMAP": "IMAP",

    "SMB": "SMB",

    "RDP": "Remote Desktop (RDP)",

    "DNS": "DNS"
}

REQUEST = (
    "HEAD / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "User-Agent: 6EYES Scanner\r\n"
    "Accept: */*\r\n"
    "Connection: close\r\n"
    "\r\n"
)
HTTPS_PORTS = (443, 8443, 9443)

HTTP_PORTS = (80, 8080, 8000, 8888)

WEB_PORTS = HTTPS_PORTS + HTTP_PORTS

KNOWN_PORT_SERVICES = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NETBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MYSQL",
    3389: "RDP"
}

RISK_RULES = {

    "SSH": {
        "risk": "LOW",
        "reason": "Secure encrypted remote administration service.",
        "recommendation": "Use key-based authentication and disable password authentication whenever possible.",
        "score_penalty": 2
    },

    "FTP": {
        "risk": "HIGH",
        "reason": "FTP transmits usernames and passwords without encryption.",
        "recommendation": "Replace FTP with SFTP or FTPS.",
        "score_penalty": 20
    },

    "FTP-DATA": {
        "risk": "HIGH",
        "reason": "FTP data channel is associated with an insecure FTP service.",
        "recommendation": "Disable FTP if unnecessary or migrate to SFTP.",
        "score_penalty": 20
    },

    "TELNET": {
        "risk": "HIGH",
        "reason": "Telnet transmits all communication in plaintext.",
        "recommendation": "Disable Telnet and use SSH instead.",
        "score_penalty": 30
    },

    "SMTP": {
        "risk": "MEDIUM",
        "reason": "Mail servers may allow relay attacks or expose unnecessary information.",
        "recommendation": "Disable open relay and enable TLS.",
        "score_penalty": 10
    },

    "DNS": {
        "risk": "MEDIUM",
        "reason": "Misconfigured DNS servers can be abused for amplification attacks.",
        "recommendation": "Restrict recursion and allow queries only from trusted clients.",
        "score_penalty": 8
    },

    "HTTP": {
        "risk": "MEDIUM",
        "reason": "HTTP traffic is transmitted without encryption.",
        "recommendation": "Redirect users to HTTPS.",
        "score_penalty": 15
    },

    "HTTPS": {
        "risk": "LOW",
        "reason": "HTTPS provides encrypted communication.",
        "recommendation": "Keep TLS certificates updated and disable weak TLS versions.",
        "score_penalty": 2
    },

    "POP3": {
        "risk": "MEDIUM",
        "reason": "POP3 may transmit credentials without encryption.",
        "recommendation": "Use POP3S or IMAPS.",
        "score_penalty": 10
    },

    "IMAP": {
        "risk": "MEDIUM",
        "reason": "IMAP without encryption exposes authentication credentials.",
        "recommendation": "Enable IMAPS over SSL/TLS.",
        "score_penalty": 10
    },

    "RPC": {
        "risk": "MEDIUM",
        "reason": "RPC services may expose system management interfaces.",
        "recommendation": "Restrict access using firewall rules.",
        "score_penalty": 8
    },

    "NETBIOS": {
        "risk": "MEDIUM",
        "reason": "NetBIOS can expose host and shared resource information.",
        "recommendation": "Disable NetBIOS if not required.",
        "score_penalty": 10
    },

    "SMB": {
        "risk": "HIGH",
        "reason": "SMB is frequently targeted by attackers if improperly configured.",
        "recommendation": "Disable SMBv1, apply security updates, and restrict network access.",
        "score_penalty": 18
    },

    "MYSQL": {
        "risk": "MEDIUM",
        "reason": "Database services should never be publicly exposed.",
        "recommendation": "Restrict access using firewall rules and strong authentication.",
        "score_penalty": 12
    },

    "POSTGRESQL": {
        "risk": "MEDIUM",
        "reason": "Publicly accessible database servers increase attack surface.",
        "recommendation": "Allow connections only from trusted hosts.",
        "score_penalty": 12
    },

    "REDIS": {
        "risk": "HIGH",
        "reason": "Unauthenticated Redis servers are a common attack target.",
        "recommendation": "Enable authentication and restrict network access.",
        "score_penalty": 25
    },

    "RDP": {
        "risk": "HIGH",
        "reason": "Remote Desktop services are common brute-force attack targets.",
        "recommendation": "Enable Network Level Authentication, use strong passwords, and restrict access.",
        "score_penalty": 18
    },

    "Unknown Service": {
        "risk": "MEDIUM",
        "reason": "The service could not be identified.",
        "recommendation": "Perform manual investigation to identify the service.",
        "score_penalty": 10
    }
}

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"