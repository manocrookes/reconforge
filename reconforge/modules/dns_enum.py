import dns.resolver
import dns.reversename
from dns.exception import DNSException


def resolve_record(target: str, record_type: str) -> list[str]:
    """
    Resolve a specific DNS record type for a target.

    Args:
        target: Domain or hostname to resolve.
        record_type: DNS record type, such as A or AAAA.

    Returns:
        A list of resolved values.
    """
    results = []

    try:
        answers = dns.resolver.resolve(target, record_type)
        for answer in answers:
            results.append(answer.to_text())
    except DNSException:
        return []

    return results


def reverse_lookup(ip_address: str) -> list[str]:
    """
    Perform reverse DNS lookup for an IP address.

    Args:
        ip_address: IPv4 or IPv6 address.

    Returns:
        A list of PTR results.
    """
    results = []

    try:
        reverse_name = dns.reversename.from_address(ip_address)
        answers = dns.resolver.resolve(reverse_name, "PTR")
        for answer in answers:
            results.append(answer.to_text().rstrip("."))
    except DNSException:
        return []

    return results


def resolve_target(target: str) -> dict:
    """
    Resolve common DNS records for a target.

    Args:
        target: Domain or hostname to resolve.

    Returns:
        A dictionary containing A, AAAA, and reverse DNS placeholders.
    """
    return {
        "a_records": resolve_record(target, "A"),
        "aaaa_records": resolve_record(target, "AAAA"),
        "reverse_dns": [],
    }
