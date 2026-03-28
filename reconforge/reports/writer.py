import json
from pathlib import Path


def ensure_output_dir(output_dir: str) -> Path:
    """
    Create the output directory if it does not exist.
    """
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    return output_path


def sanitize_target(target: str) -> str:
    """
    Sanitize target value for safe file naming.
    """
    return target.replace("/", "_").replace(":", "_")


def write_json_report(data: dict, target: str, output_dir: str = "output") -> str:
    """
    Write scan results to a target-based JSON file.
    """
    base_dir = ensure_output_dir(output_dir)
    safe_target = sanitize_target(target)
    output_file = base_dir / f"{safe_target}.json"

    output_file.write_text(json.dumps(data, indent=4), encoding="utf-8")
    return str(output_file)


def write_markdown_report(data: dict, target: str, output_dir: str = "output") -> str:
    """
    Write scan results to a Markdown report.
    """
    base_dir = ensure_output_dir(output_dir)
    safe_target = sanitize_target(target)
    output_file = base_dir / f"{safe_target}.md"

    dns_data = data.get("dns", {})
    a_records = dns_data.get("a_records", [])
    aaaa_records = dns_data.get("aaaa_records", [])
    reverse_dns = dns_data.get("reverse_dns", [])

    subdomains = data.get("subdomains", [])

    http_data = data.get("http", {})
    headers = http_data.get("headers", {})
    security_headers = http_data.get("security_headers", {})
    present_security_headers = security_headers.get("present", {})
    missing_security_headers = security_headers.get("missing", [])

    ports = data.get("ports", [])

    a_section = "\n".join(f"- {ip}" for ip in a_records) if a_records else "- No A records found"
    aaaa_section = "\n".join(f"- {ip}" for ip in aaaa_records) if aaaa_records else "- No AAAA records found"
    reverse_section = "\n".join(f"- {host}" for host in reverse_dns) if reverse_dns else "- No reverse DNS records found"

    subdomain_section = (
        "\n".join(
            f"- {item['name']} -> {', '.join(item['a_records'])}"
            for item in subdomains
        )
        if subdomains else "- No common subdomains found"
    )

    present_section = (
        "\n".join(f"- {header}: {value}" for header, value in present_security_headers.items())
        if present_security_headers else "- No common security headers detected"
    )

    missing_section = (
        "\n".join(f"- {header}" for header in missing_security_headers)
        if missing_security_headers else "- None"
    )

    ports_section = (
        "\n".join(f"- {port['port']}/{port['protocol']} ({port['service']})" for port in ports)
        if ports else "- No open ports found"
    )

    markdown_content = f"""# ReconForge Report

## Target
{data.get("target", "N/A")}

## Target Type
{data.get("target_type", "N/A")}

## DNS Resolution

### A Records
{a_section}

### AAAA Records
{aaaa_section}

### Reverse DNS
{reverse_section}

## Subdomain Enumeration
{subdomain_section}

## HTTP Enumeration
- URL: {http_data.get("url", "N/A")}
- Status Code: {http_data.get("status_code", "N/A")}
- Title: {http_data.get("title", "N/A")}
- Server: {headers.get("server", "N/A")}
- Content-Type: {headers.get("content-type", "N/A")}
- Content-Length: {headers.get("content-length", "N/A")}

## Security Headers

### Present
{present_section}

### Missing
{missing_section}

## Open Ports
{ports_section}
"""

    output_file.write_text(markdown_content, encoding="utf-8")
    return str(output_file)
