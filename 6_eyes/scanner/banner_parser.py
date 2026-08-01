import re


def clean_banner(banner):

    if not banner:
        return None

    return banner.strip()


def extract_http_server(banner):

    for line in banner.splitlines():

        if line.lower().startswith("server:"):

            return line.split(":", 1)[1].strip()

    return None


def extract_product_version(text):

    if not text:
        return None, None

    match = re.search(
        r"([A-Za-z0-9\-_]+)[/ ]([0-9][A-Za-z0-9.\-_]*)",
        text
    )

    if match:
        return match.group(1), match.group(2)

    return text, None


def parse_http_banner(banner):
 
    server = extract_http_server(banner)

    product, version = extract_product_version(server)

    return {
        "service": "HTTP",
        "product": product,
        "version": version
    }


def parse_ssh_banner(banner):

    match = re.search(
        r"OpenSSH[_\- ]([0-9A-Za-z.\-]+)",
        banner,
        re.IGNORECASE
    )

    if match:
        return {
            "service": "SSH",
            "product": "OpenSSH",
            "version": match.group(1)
        }

    return {
        "service": "SSH",
        "product": "OpenSSH",
        "version": None
    }


def parse_ftp_banner(banner):

    match = re.search(
        r"(vsFTPd|ProFTPD|Pure-FTPd)[ /]?([0-9A-Za-z.\-_]*)",
        banner,
        re.IGNORECASE
    )

    if match:
        return {
            "service": "FTP",
            "product": match.group(1),
            "version": match.group(2)
        }

    return {
        "service": "FTP",
        "product": None,
        "version": None
    }


def parse_smtp_banner(banner):

    match = re.search(
        r"(Postfix|Exim|Sendmail)[ /]?([0-9A-Za-z.\-_]*)",
        banner,
        re.IGNORECASE
    )

    if match:
        return {
            "service": "SMTP",
            "product": match.group(1),
            "version": match.group(2)
        }

    return {
        "service": "SMTP",
        "product": None,
        "version": None
    }


def parse_banner(banner):
    

    banner = clean_banner(banner)

    if not banner:

        return {
            "banner": None,
            "service": None,
            "product": None,
            "version": None
        }

    upper = banner.upper()

    if upper.startswith("HTTP/") or "SERVER:" in upper:

        result = parse_http_banner(banner)

    elif upper.startswith("SSH-"):

        result = parse_ssh_banner(banner)

    elif "FTP" in upper:

        result = parse_ftp_banner(banner)

    elif "SMTP" in upper or "ESMTP" in upper:

        result = parse_smtp_banner(banner)

    else:

        result = {
            "service": None,
            "product": None,
            "version": None
        }

    result["banner"] = banner

    return result