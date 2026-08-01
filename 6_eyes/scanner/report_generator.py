import os
from abc import ABC, abstractmethod
from datetime import datetime


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_DIR_PATH = os.path.join(BASE_DIR, "Reports")


class REPORT_DIR(ABC):

    @abstractmethod
    def ensure_directory(self):
        pass

    @abstractmethod
    def get_filepath(self, filename):
        pass

    @abstractmethod
    def get_next_report_filepath(self):
        pass


class ReportDirectory(REPORT_DIR):

    def __init__(self, directory=None):
        self.directory = directory or REPORT_DIR_PATH

    def ensure_directory(self):
        os.makedirs(self.directory, exist_ok=True)

    def get_filepath(self, filename):
        return os.path.join(self.directory, filename)

    def get_next_report_filepath(self):

        self.ensure_directory()

        count = 1

        while True:

            filename = f"report{count:02}.txt"
            filepath = self.get_filepath(filename)

            if not os.path.exists(filepath):
                return filepath

            count += 1


def generate_report_filename():
    return ReportDirectory().get_next_report_filepath()


# ======================================================
# HEADER
# ======================================================

def write_header(file):

    file.write("=" * 100 + "\n")
    file.write("6EYES\n")
    file.write("NETWORK SECURITY SCANNER REPORT\n")
    file.write("Scanner Version : v3.0\n")
    file.write("=" * 100 + "\n")

    file.write(f"Generated On   : {datetime.now().strftime('%d-%m-%Y')}\n")
    file.write(f"Generated Time : {datetime.now().strftime('%H:%M:%S')}\n")
    file.write("\n")


# ======================================================
# TARGET INFORMATION
# ======================================================

def write_target_info(file, target_type, targets, scan_type):

    file.write("=" * 100 + "\n")
    file.write("TARGET INFORMATION\n")
    file.write("=" * 100 + "\n\n")

    file.write(
        f"Target Type   : {'IP Address' if target_type == 1 else 'URL'}\n"
    )

    file.write(f"Total Targets : {len(targets)}\n\n")

    for target in targets:

        hostname = target.get("hostname", "N/A")

        file.write(
            f"IP Address : {target['ip']}\n"
            f"IP Version : IPv{target['version']}\n"
            f"Hostname   : {hostname}\n\n"
        )

    scan_names = {
        1: "Common Ports Scan",
        2: "Single Port Scan",
        3: "Custom Range Scan"
    }

    file.write(
        f"Scan Type : {scan_names.get(scan_type,'Unknown Scan')}\n"
    )


# ======================================================
# SCAN RESULTS
# ======================================================

def write_scan_results(file, scan_results):

    file.write("\n")
    file.write("=" * 100 + "\n")
    file.write("SCAN RESULTS\n")
    file.write("=" * 100 + "\n\n")

    file.write(
        f"{'STATE':<10}"
        f"{'PORT':<8}"
        f"{'IP ADDRESS':<40}"
        f"{'SERVICE':<18}"
        f"{'RISK':<10}"
        f"BANNER\n"
    )

    file.write("-" * 100 + "\n")

    for result in scan_results:

        service = result["service"] or "-"
        risk = result["risk"]["risk"]

        if result["banner"]:
            banner = result["banner"].splitlines()[0]
        else:
            banner = "Not Available"

        file.write(
            f"{result['state']:<10}"
            f"{result['port']:<8}"
            f"{result['ip']:<40}"
            f"{service:<18}"
            f"{risk:<10}"
            f"{banner}\n"
        )


# ======================================================
# RISK ANALYSIS
# ======================================================

def write_risk_analysis(file, scan_results):

    file.write("\n")
    file.write("=" * 100 + "\n")
    file.write("RISK ANALYSIS\n")
    file.write("=" * 100 + "\n\n")

    for result in scan_results:

        if result["state"] != "OPEN":
            continue

        risk = result["risk"]

        file.write(f"IP Address      : {result['ip']}\n")
        file.write(f"Port            : {result['port']}\n")
        file.write(f"Default Service : {result['default_service']}\n")
        file.write(f"Detected Service: {result['service']}\n")
        file.write(f"Risk            : {risk['risk']}\n")
        file.write(f"Reason          : {risk['reason']}\n")
        file.write(f"Recommendation  : {risk['recommendation']}\n")

        file.write("-" * 100 + "\n")


# ======================================================
# STATISTICS
# ======================================================

def write_statistics(file, scan_results, security_score):

    total_ports = len(scan_results)

    open_ports = sum(
        1 for r in scan_results
        if r["state"] == "OPEN"
    )

    closed_ports = total_ports - open_ports

    high = sum(
        1 for r in scan_results
        if r["risk"]["risk"] == "HIGH"
    )

    medium = sum(
        1 for r in scan_results
        if r["risk"]["risk"] == "MEDIUM"
    )

    low = sum(
        1 for r in scan_results
        if r["risk"]["risk"] == "LOW"
    )

    file.write("=" * 100 + "\n")
    file.write("SCAN STATISTICS\n")
    file.write("=" * 100 + "\n\n")

    file.write(f"Total Ports Scanned : {total_ports}\n")
    file.write(f"Open Ports          : {open_ports}\n")
    file.write(f"Closed Ports        : {closed_ports}\n")
    file.write(f"High Risks          : {high}\n")
    file.write(f"Medium Risks        : {medium}\n")
    file.write(f"Low Risks           : {low}\n\n")

    file.write("=" * 100 + "\n")
    file.write("OVERALL SECURITY SCORE\n")
    file.write("=" * 100 + "\n\n")

    file.write(f"Security Score : {security_score}/100\n")


# ======================================================
# FOOTER
# ======================================================

def write_footer(file):

    file.write("\n")
    file.write("=" * 100 + "\n")
    file.write("End of Report\n")
    file.write("Generated by 6EYES Network Security Scanner\n")
    file.write("=" * 100 + "\n")


# ======================================================
# MAIN REPORT
# ======================================================

def generate_report(
        target_type,
        targets,
        scan_type,
        scan_results,
        security_score):

    filename = generate_report_filename()

    with open(filename, "w", encoding="utf-8") as file:

        write_header(file)

        write_target_info(
            file,
            target_type,
            targets,
            scan_type
        )

        write_scan_results(
            file,
            scan_results
        )

        write_risk_analysis(
            file,
            scan_results
        )

        write_statistics(
            file,
            scan_results,
            security_score
        )

        write_footer(file)

    return filename