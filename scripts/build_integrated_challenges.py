#!/usr/bin/env python3
import argparse
import csv
import pathlib
import zlib


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


def append_html_link(description, label, url):
    description = (description or "").strip()
    link_block = f'Launch target: <a href="{url}" target="_blank" rel="noopener">{label}</a>'
    if link_block in description:
        return description
    if description:
        return f"{description}\n\n{link_block}"
    return link_block


def pico_rows():
    web_flag = "picoCTF{1n5p3t0r_ftw_42424242}"
    ssh_seed = "ctfd-general-ssh"
    ssh_password = hex(zlib.crc32(ssh_seed.encode()))[2:]
    ssh_flag = "picoCTF{sh311_n4v1g4t10n_ftw_8675309}"
    reversing_flag = "picoCTF{4_d14m0nd_1n_7h3_r0ugh_1234abcd}"
    perceptron_flag = "picoCTF{perceptron_party_deadbeef}"
    grep_flag = "picoCTF{gr3p_15_4_5up3rp0w3r_c001d00d}"
    disk_flag = "picoCTF{d15k_513uth_facefeed}"
    artifacts = "http://localhost:8084/start-problem-dev"
    return [
        {
            "name": "picoCTF Example: Sanity Download",
            "description": (
                "Test connectivity and download the provided flag file.\n\n"
                f'Artifact: <a href="{artifacts}/sanity-static-flag/flag.txt" '
                f'target="_blank" rel="noopener">{artifacts}/sanity-static-flag/flag.txt</a>'
            ),
            "category": "picoCTF Examples",
            "value": 50,
            "type": "standard",
            "state": "visible",
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
                f'Browse the bundled service at <a href="http://localhost:8083" target="_blank" '
                f'rel="noopener">http://localhost:8083</a> and inspect the linked CSS to find the flag.'
            ),
            "category": "picoCTF Examples",
            "value": 100,
            "type": "standard",
            "state": "visible",
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
                f"Connection: ssh -p 2222 ctf-player@localhost\nPassword: {ssh_password}"
            ),
            "category": "picoCTF Examples",
            "value": 100,
            "type": "standard",
            "state": "visible",
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
                "Service: nc localhost 2223\n\n"
                f'Source: <a href="{artifacts}/reversing-python/picker-I.py" '
                f'target="_blank" rel="noopener">{artifacts}/reversing-python/picker-I.py</a>'
            ),
            "category": "picoCTF Examples",
            "value": 125,
            "type": "standard",
            "state": "visible",
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
                "Service: nc localhost 2224\n\n"
                f'Source: <a href="{artifacts}/perceptron-gate/perceptron_gate.py" '
                f'target="_blank" rel="noopener">{artifacts}/perceptron-gate/perceptron_gate.py</a>'
            ),
            "category": "picoCTF Examples",
            "value": 150,
            "type": "standard",
            "state": "visible",
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
            "category": "picoCTF Examples",
            "value": 100,
            "type": "standard",
            "state": "visible",
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
            "category": "picoCTF Examples",
            "value": 125,
            "type": "standard",
            "state": "visible",
            "max_attempts": 0,
            "flags": disk_flag,
            "tags": "picoctf,example,forensics,disk",
            "hints": '[{"content":"Sleuth Kit tools such as blkls are the intended path here.","cost":0}]',
            "type_data": "",
        },
    ], ssh_password


def normalize_row(row):
    return {key: row.get(key, "") for key in HEADER}


def load_csv_rows(path, source_name):
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = [normalize_row(row) for row in reader]

    if source_name == "juice_shop":
        for row in rows:
            row["description"] = append_html_link(
                row["description"], "Open Juice Shop", "http://localhost:3001"
            )
    elif source_name == "wrongsecrets":
        for row in rows:
            row["description"] = append_html_link(
                row["description"], "Open WrongSecrets", "http://localhost:8081"
            )

    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--juice-shop-csv", required=True)
    parser.add_argument("--wrongsecrets-csv", required=True)
    parser.add_argument("--output-csv", required=True)
    parser.add_argument("--runtime-env", required=True)
    args = parser.parse_args()

    rows = []
    rows.extend(load_csv_rows(pathlib.Path(args.juice_shop_csv), "juice_shop"))
    rows.extend(load_csv_rows(pathlib.Path(args.wrongsecrets_csv), "wrongsecrets"))
    pico, ssh_password = pico_rows()
    rows.extend(pico)

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
                "PICO_WEB_CSS_URL=http://localhost:8083",
                "PICO_GENERAL_SSH_HOST=localhost",
                "PICO_GENERAL_SSH_PORT=2222",
                f"PICO_GENERAL_SSH_PASSWORD={ssh_password}",
                "PICO_REVERSING_PYTHON_HOST=localhost",
                "PICO_REVERSING_PYTHON_PORT=2223",
                "PICO_PERCEPTRON_HOST=localhost",
                "PICO_PERCEPTRON_PORT=2224",
                "PICO_ARTIFACTS_URL=http://localhost:8084/start-problem-dev",
                "JUICE_SHOP_URL=http://localhost:3001",
                "WRONGSECRETS_URL=http://localhost:8081",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
