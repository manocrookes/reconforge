import ipaddress
import re


def is_valid_ip(value: str) -> bool:
    """
    Check whether the given value is a valid IPv4 or IPv6 address.
    """
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_domain(value: str) -> bool:
    """
    Check whether the given value looks like a valid domain name.
    """
    domain_regex = re.compile(
        r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
        r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
    )
    return bool(domain_regex.match(value))


def normalize_target(value: str) -> str:
    """
    Normalize the target by trimming spaces and converting to lowercase.
    """
    return value.strip().lower()


def get_target_type(value: str) -> str:
    """
    Return the target type: 'ip' or 'domain'.
    """
    if is_valid_ip(value):
        return "ip"
    if is_valid_domain(value):
        return "domain"
    raise ValueError("Invalid target type")


def validate_target(value: str) -> str:
    """
    Validate and normalize the target.

    Accepts:
    - domain names
    - IPv4
    - IPv6

    Rejects:
    - full URLs
    - invalid strings
    """
    normalized_value = normalize_target(value)

    if normalized_value.startswith("http://") or normalized_value.startswith("https://"):
        raise ValueError("Please provide a domain or IP address, not a full URL")

    if is_valid_ip(normalized_value) or is_valid_domain(normalized_value):
        return normalized_value

    raise ValueError("Invalid target. Please provide a valid domain or IP address")
