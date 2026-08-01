import socket
import ssl
import config
import banner_parser

def detect_service(ip, port, version,hostname = None):
  
    family = socket.AF_INET if version == 4 else socket.AF_INET6

    sock = None

    try:
       
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(config.TIMEOUT)

        if port in config.HTTPS_PORTS:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname = hostname if hostname else ip)


        address = socket.getaddrinfo(
            ip,
            port,
            family,
            socket.SOCK_STREAM
            )[0][4]

        sock.connect(address)

        if port in config.WEB_PORTS:
            host = hostname if hostname else ip
            request = config.REQUEST.format(host= host)
            sock.sendall(request.encode())

        
        
        sock.settimeout(1.5)
        chunks = []

        total_size = 0
        max_size = 8192      

        while True:

            try:

                data = sock.recv(config.BUFFER_SIZE)

                if not data:
                    break

                chunks.append(data)

                total_size += len(data)

                if total_size >= max_size:
                    break

            except socket.timeout:
                break

        if not chunks:
            return None

        banner = b"".join(chunks).decode(errors="ignore").strip()

        
        return banner

    except socket.timeout:
        return None

    except ssl.SSLError as error:
        return None

    except socket.error as error:
        print(f"[SOCKET ERROR] {ip}:{port} -> {error}")

    finally:
        if sock:
            sock.close()

    return None


def identify_service(banner,port):

    default_service = known_port_detection(port)

    if not banner:
            return default_service
      

    banner = banner.upper()

    for keyword, service in config.SERVICE_SIGNATURES.items():
        if keyword in banner:
            return service
    

    return default_service


def detect_and_identify(ip, port, version,hostname= None):
   
    banner = detect_service(ip, port, version, hostname)

    parsed = banner_parser.parse_banner(banner)

    return {
    "port": port,
    "state": "OPEN",
    "banner": parsed["banner"],
    "default_service": known_port_detection(port),
    "service": identify_service(banner, port),
    "product": parsed["product"],
    "version": parsed["version"]
    }

def known_port_detection(port):
    return config.KNOWN_PORT_SERVICES.get(port, "Unknown Service")
