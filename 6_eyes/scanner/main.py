import validator
import config
import port_scanner
import risk_analyzer
import report_generator
import url_validator
import vulnerability_scanner

targets = []
scan_result = []
target_type=int(input("Enter\n1. to scan ip-address\n2. to scan URL\n"))
match target_type:
    case 1:
        ip = input("Enter an IP address :\n ")
        ip_version = validator.validate_ip(ip)
        if ip_version:
            print(f"Valid IP address.\nVersion: IPv{ip_version}")
            
            targets = [
            {
                'ip' : ip,
                'version' : ip_version,
                "hostname": None
            }
        ]
        else:
            print("Invalid IP Address.")
            exit()
    case 2:
        url = input("Enter a URL : \t")
        
        resolved = url_validator.resolve_domain(url)
        if not resolved['valid'] :
            print(resolved['error'])
            exit()
        targets = resolved['addresses']
        print("\nResolved Addresses:")

        for target in targets:
            print(f"{target['ip']} (IPv{target['version']})")
    case _ :
        print("Invalid Choice.")
        exit()


try:
    scan_type = int(input("Choose Scan Type\n1. Common Ports\n2. Single Port\n3. Custom Range\n"))
    match scan_type:
        case 1:
            for target in targets :
                ip = target['ip']
                version = target['version']
                hostname =target.get('hostname')
                result = port_scanner.common_port(ip, config.COMMON_PORTS,version,hostname) 

                for item in result:
                    item['ip'] = ip
                    item["version"] = version
                    item["hostname"] = target.get("hostname")
                scan_result.extend(result)
        case 2:
            port = int(input("Enter the port to scan: "))
            for target in targets:
                ip = target['ip']
                version = target['version']
                hostname =target.get('hostname')
                result = port_scanner.single_port(ip, port,version,hostname)

                for item in result:
                    item['ip'] = ip
                    item["version"] = version
                    item["hostname"] = target.get("hostname")
                scan_result.extend(result)
        case 3:
            start_port = int(input("Enter the starting port: "))
            end_port = int(input("Enter the ending port: "))
            for target in targets:
                ip = target['ip']
                version = target['version']
                hostname =target.get('hostname')
                result = port_scanner.custom_range(ip, start_port, end_port,version, hostname)

                for item in result :    
                    item['ip'] = ip
                    item["version"] = version
                    item["hostname"] = target.get("hostname")
                scan_result.extend(result)
        case _:
            print("Invalid scan type.")
            exit()
except ValueError:
    print("Invalid input. Please enter a number.")
    exit()


risks = []

for result in scan_result:

    if result["state"] == "OPEN":

        risk = risk_analyzer.get_risk_info(result["service"])

        vulnerabilities = vulnerability_scanner.get_vulnerabilities(
            result["server"],
            result["version"]
        )

    else:

        risk = {
            "risk": "-",
            "score_penalty": 0
        }

        vulnerabilities = []

    result["risk"] = risk
    result["vulnerabilities"] = vulnerabilities

    risks.append(risk)

security_score = risk_analyzer.calculate_security_score(risks)




filename = report_generator.generate_report(target_type, targets, scan_type, scan_result, security_score )

print(f"\nReport saved successfully to: {filename}\n")