from reconforge.models.target import get_target_type
from reconforge.modules.dns_enum import resolve_target, reverse_lookup
from reconforge.modules.http_enum import enumerate_http
from reconforge.modules.port_scan import is_nmap_installed, run_nmap_scan
from reconforge.reports.writer import write_json_report, write_markdown_report


def run_scan(target: str, output_dir: str = "output"):
    print("[+] ReconForge started")
    print(f"[+] Target: {target}")

    target_type = get_target_type(target)

    if target_type == "domain":
        print("[+] Running DNS enumeration...")
        dns_result = resolve_target(target)

        a_records = dns_result["a_records"]
        aaaa_records = dns_result["aaaa_records"]

        if a_records:
            print("[+] Resolved A records:")
            for ip in a_records:
                print(f"    - {ip}")
        else:
            print("[-] No A records found")

        if aaaa_records:
            print("[+] Resolved AAAA records:")
            for ip in aaaa_records:
                print(f"    - {ip}")
        else:
            print("[-] No AAAA records found")

    else:
        print("[*] Target identified as IP address, skipping direct DNS enumeration")
        reverse_dns = reverse_lookup(target)

        if reverse_dns:
            print("[+] Reverse DNS results:")
            for hostname in reverse_dns:
                print(f"    - {hostname}")
        else:
            print("[-] No reverse DNS records found")

        dns_result = {
            "a_records": [],
            "aaaa_records": [],
            "reverse_dns": reverse_dns,
        }

    print("[+] Running HTTP enumeration...")
    http_result = enumerate_http(target)

    print(f"[+] URL: {http_result['url']}")
    print(f"[+] Status: {http_result['status_code']}")
    print(f"[+] Title: {http_result['title']}")
    print(f"[+] Server: {http_result['headers']['server']}")
    print(f"[+] Content-Type: {http_result['headers']['content-type']}")

    if http_result["security_headers"]["present"]:
        print("[+] Present security headers:")
        for header, value in http_result["security_headers"]["present"].items():
            print(f"    - {header}: {value}")
    else:
        print("[-] No common security headers detected")

    if http_result["security_headers"]["missing"]:
        print("[+] Missing security headers:")
        for header in http_result["security_headers"]["missing"]:
            print(f"    - {header}")

    print("[+] Running port scan...")
    if is_nmap_installed():
        ports = run_nmap_scan(target)
        if ports:
            print("[+] Open ports found:")
            for port in ports:
                print(f"    - {port['port']}/{port['protocol']} ({port['service']})")
        else:
            print("[-] No open ports found or scan failed")
    else:
        print("[-] Nmap not found in PATH")
        ports = []

    result = {
        "target": target,
        "target_type": target_type,
        "dns": dns_result,
        "http": http_result,
        "ports": ports,
    }

    json_output_path = write_json_report(result, target, output_dir)
    markdown_output_path = write_markdown_report(result, target, output_dir)

    print(f"[+] JSON report saved to {json_output_path}")
    print(f"[+] Markdown report saved to {markdown_output_path}")
    print("[+] Done")
