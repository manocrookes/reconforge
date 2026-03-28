import shutil
import subprocess
import xml.etree.ElementTree as ET


def is_nmap_installed() -> bool:
    """
    Check whether Nmap is installed and available in PATH.
    """
    return shutil.which("nmap") is not None


def run_nmap_scan(target: str) -> list[dict]:
    """
    Run a basic Nmap scan and return open TCP ports.

    Args:
        target: Domain or IP address.

    Returns:
        A list of dictionaries describing open ports.
    """
    if not is_nmap_installed():
        return []

    try:
        result = subprocess.run(
            ["nmap", "-Pn", "-T4", "-oX", "-", target],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

        if result.returncode != 0 or not result.stdout.strip():
            return []

        return parse_nmap_xml(result.stdout)

    except (subprocess.SubprocessError, ET.ParseError):
        return []


def parse_nmap_xml(xml_data: str) -> list[dict]:
    """
    Parse Nmap XML output and extract open ports.

    Args:
        xml_data: Raw XML output from Nmap.

    Returns:
        A list of open ports with service information.
    """
    ports = []
    root = ET.fromstring(xml_data)

    for host in root.findall("host"):
        ports_node = host.find("ports")
        if ports_node is None:
            continue

        for port in ports_node.findall("port"):
            state = port.find("state")
            service = port.find("service")

            if state is not None and state.get("state") == "open":
                ports.append(
                    {
                        "port": int(port.get("portid", 0)),
                        "protocol": port.get("protocol", "unknown"),
                        "state": state.get("state", "unknown"),
                        "service": service.get("name", "unknown") if service is not None else "unknown",
                    }
                )

    return ports
