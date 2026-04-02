#!/usr/bin/env python3
import argparse
import csv
import os
import pathlib
import re
import zlib
from urllib.parse import urlsplit

import yaml


HEADER = [
    "name",
    "description",
    "category",
    "value",
    "type",
    "state",
    "max_attempts",
    "flags",
    "tags",
    "hints",
    "type_data",
]


JUICE_CATEGORY_GROUPS = {
    "Broken Access Control": "Web",
    "Broken Anti Automation": "Web",
    "Broken Authentication": "Authentication",
    "Cryptographic Issues": "Cryptography",
    "Improper Input Validation": "Web",
    "Injection": "Web",
    "Insecure Deserialization": "Server Security",
    "Miscellaneous": "Miscellaneous",
    "Observability Failures": "Server Security",
    "Security Misconfiguration": "Server Security",
    "Security through Obscurity": "Miscellaneous",
    "Sensitive Data Exposure": "Secrets & Data Exposure",
    "Unvalidated Redirects": "Web",
    "Vulnerable Components": "Server Security",
    "XSS": "Web",
    "XXE": "Server Security",
}

ARCHIVE_CATEGORY_MAP = {
    "CRYPTO": "Cryptography",
    "CRYTPO": "Cryptography",
    "HASHING": "Cryptography",
    "RNG": "Cryptography",
    "PWN": "Binary Exploitation",
    "PWNABLE": "Binary Exploitation",
    "BINARY": "Binary Exploitation",
    "EXPLOIT": "Binary Exploitation",
    "EXPLOITATION": "Binary Exploitation",
    "ROP": "Binary Exploitation",
    "VULNERABILITY": "Binary Exploitation",
    "PWN/MISC": "Binary Exploitation",
    "REV": "Reverse Engineering",
    "RE": "Reverse Engineering",
    "REVERSE": "Reverse Engineering",
    "REVERSING": "Reverse Engineering",
    "FORENSICS": "Forensics",
    "WEB": "Web",
    "MISC": "Miscellaneous",
    "OSINT": "Miscellaneous",
    "PPC": "Programming",
    "PROGRAMMING": "Programming",
    "STEGO": "Steganography",
    "STEGANOGRAPHY": "Steganography",
    "CRYPTOGRAPHY": "Cryptography",
    "BLOCKCHAIN": "Miscellaneous",
    "RF": "Miscellaneous",
    "HARDWARE-RF": "Miscellaneous",
    "RADIO FREQUENCY": "Miscellaneous",
    "RECON": "Miscellaneous",
    "SOCIAL ENGINEERING": "Miscellaneous",
    "TRIVIA": "Miscellaneous",
    "LOGICAL": "Miscellaneous",
}

WRONGSECRETS_CATEGORY_GROUPS = {
    "Intro": "Warmup",
    "Git": "Source & CI/CD",
    "CI/CD": "Source & CI/CD",
    "Docker": "Infrastructure",
    "Configmaps": "Infrastructure",
    "Terraform": "Infrastructure",
    "CSI-Driver": "Infrastructure",
    "IAM privilege escalation": "Infrastructure",
    "Vault": "Secrets & Data Exposure",
    "Secrets": "Secrets & Data Exposure",
    "Password Manager": "Secrets & Data Exposure",
    "Cryptography": "Cryptography",
    "Binary": "Binary Exploitation",
    "Front-end": "Web",
    "Documentation": "Recon & Documentation",
    "Logging": "Recon & Documentation",
    "Web3": "Miscellaneous",
    "AI": "Miscellaneous",
}

AWESOME_CATEGORY_GROUPS = {
    "Forensics": "Forensics",
    "Platforms": "Resources",
    "Steganography": "Steganography",
    "Web": "Web",
    "Attacks": "Binary Exploitation",
    "Bruteforcers": "Cryptography",
    "Crypto": "Cryptography",
    "Exploits": "Binary Exploitation",
    "Networking": "Infrastructure",
    "Reversing": "Reverse Engineering",
    "Services": "Infrastructure",
    "Operating Systems": "Programming",
    "Starter Packs": "Resources",
    "Tutorials": "Resources",
    "Wargames": "Resources",
    "Websites": "Resources",
    "Wikis": "Resources",
    "Writeups Collections": "Resources",
}

PWN_COLLEGE_TRACK_GROUPS = {
    "Shell Lin Do": "Shell",
    "Advent Of Pwn": "Binary Exploitation",
}

DEFAULT_CATALOG_FLAG_PREFIX = "catalog"
MAX_CHALLENGE_NAME_LENGTH = 80


def append_html_link(description, label, url):
    description = (description or "").strip()
    link_block = f'Launch target: <a href="{url}" target="_blank" rel="noopener">{label}</a>'
    if link_block in description:
        return description
    if description:
        return f"{description}\n\n{link_block}"
    return link_block


def _clean_url(value):
    value = (value or "").strip()
    return value.rstrip("/") if value else None


def _public_base_url():
    return _clean_url(os.environ.get("CTFD_PUBLIC_URL"))


def _public_host(default="localhost"):
    base_url = _public_base_url()
    if not base_url:
        return default
    return urlsplit(base_url).hostname or default


def _service_url(env_name, default_local_url):
    explicit = _clean_url(os.environ.get(env_name))
    if explicit:
        return explicit

    public_base = _public_base_url()
    if not public_base:
        return default_local_url

    split = urlsplit(default_local_url)
    if split.port:
        return f"{public_base.rsplit(':', 1)[0]}:{split.port}".rstrip("/")
    return public_base


def pico_rows():
    web_flag = "picoCTF{1n5p3t0r_ftw_42424242}"
    ssh_seed = "ctfd-general-ssh"
    ssh_password = hex(zlib.crc32(ssh_seed.encode()))[2:]
    ssh_flag = "picoCTF{sh311_n4v1g4t10n_ftw_8675309}"
    reversing_flag = "picoCTF{4_d14m0nd_1n_7h3_r0ugh_1234abcd}"
    perceptron_flag = "picoCTF{perceptron_party_deadbeef}"
    grep_flag = "picoCTF{gr3p_15_4_5up3rp0w3r_c001d00d}"
    disk_flag = "picoCTF{d15k_513uth_facefeed}"
    artifacts = _service_url("PICO_ARTIFACTS_URL", "http://localhost:8084/start-problem-dev")
    web_url = _service_url("PICO_WEB_CSS_URL", "http://localhost:8083")
    ssh_host = os.environ.get("PICO_GENERAL_SSH_HOST", _public_host())
    ssh_port = os.environ.get("PICO_GENERAL_SSH_PORT", "2222")
    reversing_host = os.environ.get("PICO_REVERSING_PYTHON_HOST", _public_host())
    reversing_port = os.environ.get("PICO_REVERSING_PYTHON_PORT", "2223")
    perceptron_host = os.environ.get("PICO_PERCEPTRON_HOST", _public_host())
    perceptron_port = os.environ.get("PICO_PERCEPTRON_PORT", "2224")
    return [
        {
            "name": "picoCTF Example: Sanity Download",
            "description": (
                "Test connectivity and download the provided flag file.\n\n"
                f'Artifact: <a href="{artifacts}/sanity-static-flag/flag.txt" '
                f'target="_blank" rel="noopener">{artifacts}/sanity-static-flag/flag.txt</a>'
            ),
            "category": "Warmup",
            "value": 50,
            "type": "standard",
            "state": "hidden",
            "max_attempts": 0,
            "flags": "picoCTF{s4n1ty_d0wnl04d3d}",
            "tags": "picoctf,example,download",
            "hints": '[{"content":"Download the linked file and read its contents.","cost":0}]',
            "type_data": "",
        },
        {
            "name": "picoCTF Example: Web CSS",
            "description": (
                "Do you know how to use the web inspector?\n\n"
                f'Browse the bundled service at <a href="{web_url}" target="_blank" '
                f'rel="noopener">{web_url}</a> and inspect the linked CSS to find the flag.'
            ),
            "category": "Web",
            "value": 100,
            "type": "standard",
            "state": "hidden",
            "max_attempts": 0,
            "flags": web_flag,
            "tags": "picoctf,example,web",
            "hints": '[{"content":"Use your browser developer tools to inspect linked assets.","cost":0}]',
            "type_data": "",
        },
        {
            "name": "picoCTF Example: General SSH",
            "description": (
                "Do you know how to move between directories and read files in the shell?\n\n"
                "Log in to the bundled SSH service and recover the three flag fragments.\n\n"
                f"Connection: ssh -p {ssh_port} ctf-player@{ssh_host}\nPassword: {ssh_password}"
            ),
            "category": "Shell",
            "value": 100,
            "type": "standard",
            "state": "hidden",
            "max_attempts": 0,
            "flags": ssh_flag,
            "tags": "picoctf,example,ssh,bash",
            "hints": '[{"content":"Use ls, cd, and cat after logging in to the container.","cost":0}]',
            "type_data": "",
        },
        {
            "name": "picoCTF Example: Reversing Python",
            "description": (
                "Connect to the live service with netcat and inspect the provided source file.\n\n"
                f"Service: nc {reversing_host} {reversing_port}\n\n"
                f'Source: <a href="{artifacts}/reversing-python/picker-I.py" '
                f'target="_blank" rel="noopener">{artifacts}/reversing-python/picker-I.py</a>'
            ),
            "category": "Reverse Engineering",
            "value": 125,
            "type": "standard",
            "state": "hidden",
            "max_attempts": 0,
            "flags": reversing_flag,
            "tags": "picoctf,example,reversing,python",
            "hints": '[{"content":"The winning function name is exposed in the Python source.","cost":0}]',
            "type_data": "",
        },
        {
            "name": "picoCTF Example: Perceptron Gate",
            "description": (
                "Probe the black-box perceptron over a socket service and submit a matching model.\n\n"
                f"Service: nc {perceptron_host} {perceptron_port}\n\n"
                f'Source: <a href="{artifacts}/perceptron-gate/perceptron_gate.py" '
                f'target="_blank" rel="noopener">{artifacts}/perceptron-gate/perceptron_gate.py</a>'
            ),
            "category": "Machine Learning",
            "value": 150,
            "type": "standard",
            "state": "hidden",
            "max_attempts": 0,
            "flags": perceptron_flag,
            "tags": "picoctf,example,reversing,ml,netcat",
            "hints": '[{"content":"Query all four binary input combinations and model the resulting truth table.","cost":0}]',
            "type_data": "",
        },
        {
            "name": "picoCTF Example: Forensics Grep",
            "description": (
                "Download the large text file and search it for the embedded flag.\n\n"
                f'Artifact: <a href="{artifacts}/forensics-grep/war-and-peace.flag.txt" '
                f'target="_blank" rel="noopener">{artifacts}/forensics-grep/war-and-peace.flag.txt</a>'
            ),
            "category": "Forensics",
            "value": 100,
            "type": "standard",
            "state": "hidden",
            "max_attempts": 0,
            "flags": grep_flag,
            "tags": "picoctf,example,forensics,grep",
            "hints": '[{"content":"Use grep for the picoCTF prefix rather than reading the whole file manually.","cost":0}]',
            "type_data": "",
        },
        {
            "name": "picoCTF Example: Forensics Disk",
            "description": (
                "Download the disk image and inspect slack space to recover the flag.\n\n"
                f'Artifact: <a href="{artifacts}/forensics-disk/disk.flag.img.gz" '
                f'target="_blank" rel="noopener">{artifacts}/forensics-disk/disk.flag.img.gz</a>'
            ),
            "category": "Forensics",
            "value": 125,
            "type": "standard",
            "state": "hidden",
            "max_attempts": 0,
            "flags": disk_flag,
            "tags": "picoctf,example,forensics,disk",
            "hints": '[{"content":"Sleuth Kit tools such as blkls are the intended path here.","cost":0}]',
            "type_data": "",
        },
    ], ssh_password


def normalize_row(row):
    return {key: row.get(key, "") for key in HEADER}


def slugify(value):
    value = re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")
    return value or "item"


def limit_name(value, max_length=MAX_CHALLENGE_NAME_LENGTH):
    value = (value or "").strip()
    if len(value) <= max_length:
        return value
    return value[: max_length - 3].rstrip() + "..."


def safe_load_yaml(path):
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore"))
    except OSError:
        return {}
    return data if isinstance(data, dict) else {}


def read_text_if_exists(path, limit=4000):
    if not path.exists():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:limit].strip()
    except OSError:
        return ""


def english_catalog_description(lines):
    cleaned = [line.strip() for line in lines if line and line.strip()]
    return "\n\n".join(cleaned)


def deterministic_catalog_flag(prefix, *parts):
    joined = "::".join(str(part) for part in parts if part)
    checksum = zlib.crc32(joined.encode("utf-8")) & 0xFFFFFFFF
    return f"{prefix}{{{checksum:08x}}}"


def archive_category_from_name(name):
    if " - " not in (name or ""):
        return "Miscellaneous"
    prefix = name.split(" - ", 1)[0].strip().upper()
    return ARCHIVE_CATEGORY_MAP.get(prefix, prefix.title() if prefix else "Miscellaneous")


def awesome_category(title):
    return AWESOME_CATEGORY_GROUPS.get(title, "Resources")


def pwncollege_category(track_name, module_name=""):
    if track_name in PWN_COLLEGE_TRACK_GROUPS:
        return PWN_COLLEGE_TRACK_GROUPS[track_name]

    normalized_module = re.sub(r"[^a-z0-9]+", " ", (module_name or "").lower()).strip()
    if "web server" in normalized_module:
        return "Web"
    if any(token in normalized_module for token in ("assembly", "debug", "introspect", "memory", "stack", "control flow")):
        return "Reverse Engineering"
    return "Programming"


def archive_display_name(name):
    if not name:
        return "Unnamed Challenge"
    parts = [part.strip() for part in name.split(" - ") if part.strip()]
    if len(parts) >= 3 and parts[1].isdigit():
        return parts[2]
    if len(parts) >= 2:
        return parts[-1]
    return name.strip()


def awesome_ctf_rows(repo_root):
    readme = repo_root / "README.md"
    text = read_text_if_exists(readme, limit=200000)
    if not text:
        return []

    rows = []
    section_pattern = re.compile(r"^##\s+(.+?)\s*$", re.M)
    matches = list(section_pattern.finditer(text))
    for index, match in enumerate(matches):
        title = match.group(1).strip()
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        section = text[start:end]
        bullets = re.findall(r"^- \[(.+?)\]\((.+?)\)\s*-\s*(.+)$", section, re.M)
        if not bullets:
            continue

        sample_lines = []
        for item_name, item_url, item_desc in bullets[:6]:
            sample_lines.append(f"- {item_name}: {item_desc} ({item_url})")

        description = english_catalog_description(
            [
                "Imported from `apsdehal/awesome-ctf` as a reference catalog entry.",
                "This is not a self-contained solvable CTF challenge pack. It is a curated English-language resource list for challenge design, practice, and tooling.",
                f"Resource section: {title}",
                f"Source path: {readme}",
                "Sample resources:\n" + "\n".join(sample_lines),
                "Admin note: keep hidden unless you want to expose this entry as a reference item inside CTFd.",
            ]
        )
        rows.append(
            normalize_row(
                {
                    "name": limit_name(f"Awesome CTF Reference: {title}"),
                    "description": description,
                    "category": awesome_category(title),
                    "value": 25,
                    "type": "standard",
                    "state": "hidden",
                    "max_attempts": 0,
                    "flags": deterministic_catalog_flag(DEFAULT_CATALOG_FLAG_PREFIX, "awesome-ctf", title),
                    "tags": "catalog,reference,awesome-ctf,requires-curation",
                    "hints": '[{"content":"This imported entry is a reference catalog item, not a live runtime-backed challenge.","cost":0}]',
                    "type_data": "",
                }
            )
        )
    return rows


def ctf_archive_rows(repo_root):
    rows = []
    for module_path in sorted(repo_root.glob("**/module.yml")):
        module = safe_load_yaml(module_path)
        event_id = module.get("id") or module_path.parent.name
        event_name = (module.get("name") or event_id).strip()
        for challenge in module.get("challenges", []) or []:
            if not isinstance(challenge, dict):
                continue
            challenge_id = str(challenge.get("id") or "").strip()
            source_name = str(challenge.get("name") or challenge_id or "Unnamed Challenge").strip()
            display_name = archive_display_name(source_name)
            category = archive_category_from_name(source_name)
            description = english_catalog_description(
                [
                    "Imported from `pwncollege/ctf-archive` as an archived challenge catalog entry.",
                    "This entry captures source metadata from a historical event archive. It is hidden by default because the archive is not a direct drop-in runtime for this CTFd instance.",
                    f"Event: {event_name}",
                    f"Archive module: {event_id}",
                    f"Original challenge title: {source_name}",
                    f"Archive challenge id: {challenge_id or 'unknown'}",
                    f"Source path: {module_path}",
                    "Admin note: publish only after reviewing and wiring a real runtime or replacing the placeholder flag.",
                ]
            )
            rows.append(
                normalize_row(
                    {
                        "name": limit_name(f"CTF Archive: {event_name} / {display_name}"),
                        "description": description,
                        "category": category,
                        "value": 100,
                        "type": "standard",
                        "state": "hidden",
                        "max_attempts": 0,
                        "flags": deterministic_catalog_flag(DEFAULT_CATALOG_FLAG_PREFIX, "ctf-archive", event_id, challenge_id, source_name),
                        "tags": f"catalog,ctf-archive,{slugify(category)},requires-curation",
                        "hints": '[{"content":"This archived entry is cataloged for admin curation and is hidden by default until a live runtime is attached.","cost":0}]',
                        "type_data": "",
                    }
                )
            )
    return rows


def pwncollege_rows(repo_root):
    challenges_root = repo_root / "challenges"
    rows = []
    for module_path in sorted(challenges_root.glob("**/module.yml")):
        module_dir = module_path.parent
        module = safe_load_yaml(module_path)
        module_name = str(module.get("name") or module_dir.name.replace("-", " ").title()).strip()
        module_parts = module_dir.relative_to(challenges_root).parts
        track_name = module_parts[0].replace("-", " ").title() if module_parts else "General"

        resource_entries = []
        if isinstance(module.get("resources"), list):
            resource_entries.extend(item for item in module["resources"] if isinstance(item, dict) and item.get("type") == "challenge")
        if isinstance(module.get("challenges"), list):
            resource_entries.extend(item for item in module["challenges"] if isinstance(item, dict))

        for entry in resource_entries:
            challenge_id = str(entry.get("id") or "").strip()
            if not challenge_id:
                continue
            challenge_name = str(entry.get("name") or challenge_id.replace("-", " ").title()).strip()
            challenge_dir = module_dir / challenge_id
            challenge_yml = safe_load_yaml(challenge_dir / "challenge.yml")
            challenge_description = (
                str(entry.get("description") or "").strip()
                or str(challenge_yml.get("description") or "").strip()
                or read_text_if_exists(challenge_dir / "DESCRIPTION.md")
                or "Imported from `pwncollege/challenges` as a hidden catalog entry pending runtime wiring and admin review."
            )
            metadata_bits = []
            if challenge_yml.get("privileged") is True:
                metadata_bits.append("This source challenge declares privileged execution requirements.")
            if (challenge_dir / "challenge").exists():
                metadata_bits.append("Challenge artifacts are present in the source repository.")
            if (challenge_dir / "tests_public").exists():
                metadata_bits.append("Public tests are present in the source repository.")

            description = english_catalog_description(
                [
                    "Imported from `pwncollege/challenges` as a structured catalog entry.",
                    challenge_description,
                    f"Track: {track_name}",
                    f"Module: {module_name}",
                    f"Challenge id: {challenge_id}",
                    f"Source path: {challenge_dir}",
                    *metadata_bits,
                    "Admin note: this entry is hidden by default. Publish only after confirming the runtime model, replacing the placeholder flag, and deciding whether the challenge should stay shared or isolated.",
                ]
            )
            rows.append(
                normalize_row(
                    {
                        "name": limit_name(f"pwn.college: {module_name} / {challenge_name}"),
                        "description": description,
                        "category": pwncollege_category(track_name, module_name),
                        "value": 150,
                        "type": "standard",
                        "state": "hidden",
                        "max_attempts": 0,
                        "flags": deterministic_catalog_flag(DEFAULT_CATALOG_FLAG_PREFIX, "pwncollege", "/".join(module_parts), challenge_id),
                        "tags": f"catalog,pwncollege,{slugify(track_name)},requires-curation",
                        "hints": '[{"content":"This pwn.college entry was imported as a hidden catalog item. Review its runtime requirements before making it visible.","cost":0}]',
                        "type_data": "",
                    }
                )
            )
    return rows


def normalize_source_category(source_name, category):
    category = (category or "").strip()
    if source_name == "juice_shop":
        return JUICE_CATEGORY_GROUPS.get(category, category or "Miscellaneous")
    if source_name == "wrongsecrets":
        normalized = category.replace("Docker - ", "", 1).strip() or "General"
        return WRONGSECRETS_CATEGORY_GROUPS.get(normalized, "Miscellaneous")
    return category or "Miscellaneous"


def load_csv_rows(path, source_name):
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = [normalize_row(row) for row in reader]

    if source_name == "juice_shop":
        for row in rows:
            row["category"] = normalize_source_category(source_name, row.get("category"))
            row["state"] = "hidden"
            row["description"] = append_html_link(
                row["description"],
                "Open Juice Shop",
                _service_url("JUICE_SHOP_URL", "http://localhost:3001"),
            )
    elif source_name == "wrongsecrets":
        for row in rows:
            row["category"] = normalize_source_category(source_name, row.get("category"))
            row["state"] = "hidden"
            row["description"] = append_html_link(
                row["description"],
                "Open WrongSecrets",
                _service_url("WRONGSECRETS_URL", "http://localhost:8081"),
            )

    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--juice-shop-csv", required=True)
    parser.add_argument("--wrongsecrets-csv", required=True)
    parser.add_argument("--output-csv", required=True)
    parser.add_argument("--runtime-env", required=True)
    parser.add_argument("--ctf-archive-root")
    parser.add_argument("--pwncollege-root")
    parser.add_argument("--awesome-ctf-root")
    parser.add_argument(
        "--include-catalog-sources",
        action="store_true",
        help="Also import non-runtime catalog/reference entries from archive/reference repos.",
    )
    args = parser.parse_args()

    rows = []
    rows.extend(load_csv_rows(pathlib.Path(args.juice_shop_csv), "juice_shop"))
    rows.extend(load_csv_rows(pathlib.Path(args.wrongsecrets_csv), "wrongsecrets"))
    pico, ssh_password = pico_rows()
    rows.extend(pico)
    if args.include_catalog_sources and args.ctf_archive_root:
        rows.extend(ctf_archive_rows(pathlib.Path(args.ctf_archive_root)))
    if args.include_catalog_sources and args.pwncollege_root:
        rows.extend(pwncollege_rows(pathlib.Path(args.pwncollege_root)))
    if args.include_catalog_sources and args.awesome_ctf_root:
        rows.extend(awesome_ctf_rows(pathlib.Path(args.awesome_ctf_root)))

    output_csv = pathlib.Path(args.output_csv)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=HEADER)
        writer.writeheader()
        writer.writerows(rows)

    runtime_env = pathlib.Path(args.runtime_env)
    runtime_env.parent.mkdir(parents=True, exist_ok=True)
    runtime_env.write_text(
        "\n".join(
            [
                f"PICO_WEB_CSS_URL={_service_url('PICO_WEB_CSS_URL', 'http://localhost:8083')}",
                f"PICO_GENERAL_SSH_HOST={os.environ.get('PICO_GENERAL_SSH_HOST', _public_host())}",
                f"PICO_GENERAL_SSH_PORT={os.environ.get('PICO_GENERAL_SSH_PORT', '2222')}",
                f"PICO_GENERAL_SSH_PASSWORD={ssh_password}",
                f"PICO_REVERSING_PYTHON_HOST={os.environ.get('PICO_REVERSING_PYTHON_HOST', _public_host())}",
                f"PICO_REVERSING_PYTHON_PORT={os.environ.get('PICO_REVERSING_PYTHON_PORT', '2223')}",
                f"PICO_PERCEPTRON_HOST={os.environ.get('PICO_PERCEPTRON_HOST', _public_host())}",
                f"PICO_PERCEPTRON_PORT={os.environ.get('PICO_PERCEPTRON_PORT', '2224')}",
                f"PICO_ARTIFACTS_URL={_service_url('PICO_ARTIFACTS_URL', 'http://localhost:8084/start-problem-dev')}",
                f"JUICE_SHOP_URL={_service_url('JUICE_SHOP_URL', 'http://localhost:3001')}",
                f"WRONGSECRETS_URL={_service_url('WRONGSECRETS_URL', 'http://localhost:8081')}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
