from pathlib import Path
from reconforge.modules.dns_enum import resolve_record


LOCAL_DEFAULT_WORDLIST = Path("wordlists/common.txt")

KALI_WORDLIST_CANDIDATES = [
    Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"),
    Path("/usr/share/seclists/Discovery/DNS/namelist.txt"),
    Path("/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"),
    Path("/usr/share/wordlists/seclists/Discovery/DNS/namelist.txt"),
]


def get_default_wordlist_path() -> Path:
    """
    Return the best available default wordlist path.

    Priority:
    1. Kali/SecLists common paths
    2. Local project wordlist
    """
    for candidate in KALI_WORDLIST_CANDIDATES:
        if candidate.exists():
            return candidate

    return LOCAL_DEFAULT_WORDLIST


def load_wordlist(path: str | None = None) -> tuple[list[str], str]:
    """
    Load subdomain wordlist from a custom path or fallback defaults.

    Args:
        path: Optional custom wordlist path.

    Returns:
        A tuple with:
        - list of subdomain prefixes
        - resolved wordlist path as string
    """
    if path:
        wordlist_path = Path(path)
    else:
        wordlist_path = get_default_wordlist_path()

    if not wordlist_path.exists():
        raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

    with wordlist_path.open("r", encoding="utf-8", errors="ignore") as file_handle:
        entries = [line.strip() for line in file_handle if line.strip()]

    return entries, str(wordlist_path)


def enumerate_subdomains(target: str, wordlist_path: str | None = None) -> tuple[list[dict], str]:
    """
    Enumerate subdomains using a wordlist.

    Args:
        target: Base domain.
        wordlist_path: Optional path to a custom wordlist file.

    Returns:
        A tuple with:
        - list of discovered subdomains
        - the wordlist path actually used
    """
    discovered = []
    candidates, resolved_wordlist_path = load_wordlist(wordlist_path)

    for subdomain in candidates:
        full_domain = f"{subdomain}.{target}"
        a_records = resolve_record(full_domain, "A")

        if a_records:
            discovered.append(
                {
                    "name": full_domain,
                    "a_records": a_records,
                }
            )

    return discovered, resolved_wordlist_path
