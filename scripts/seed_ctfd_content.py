#!/usr/bin/env python3
import os
import csv

from CTFd import create_app
from CTFd.models import Admins, Challenges, Flags, Hints, Pages, Tags, db
from CTFd.utils import get_config, set_config
from CTFd.utils.csv import load_challenges_csv


CSV_PATH = os.environ.get("INTEGRATED_CTF_CSV", "/opt/CTFd/.generated/integrated-challenges.csv")
RUNTIME_ENV_PATH = os.environ.get("INTEGRATED_RUNTIME_ENV", "/opt/CTFd/.generated/runtime.env")


def load_runtime_env(path):
    values = {}
    if not os.path.exists(path):
        return values
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key] = value
    return values


def ensure_config(key, value):
    if get_config(key) is None:
        set_config(key, value)


def ensure_setup():
    ensure_config("ctf_name", "Integrated CTF Lab")
    ensure_config("ctf_description", "CTFd seeded with Docker-backed training content.")
    ensure_config("user_mode", "users")
    ensure_config("ctf_theme", "core")
    ensure_config("challenge_visibility", "public")
    ensure_config("registration_visibility", "public")
    ensure_config("score_visibility", "public")
    ensure_config("account_visibility", "public")
    ensure_config("social_shares", False)
    ensure_config("verify_emails", False)
    ensure_config("setup", True)

    admin = Admins.query.filter_by(email="admin@example.com").first()
    if admin is None:
        admin = Admins(name="admin", email="admin@example.com", password="AdminPass123!")
        db.session.add(admin)

    index = Pages.query.filter_by(route="index").first()
    if index is None:
        index = Pages(
            title="Home",
            route="index",
            content="Integrated CTF Lab",
            draft=False,
            hidden=False,
            auth_required=False,
            format="markdown",
        )
        db.session.add(index)

    db.session.commit()


def replace_page(route, title, content):
    page = Pages.query.filter_by(route=route).first()
    if page is None:
        page = Pages(route=route)
        db.session.add(page)
    page.title = title
    page.content = content
    page.draft = False
    page.hidden = False
    page.auth_required = False
    page.format = "markdown"


def challenge_names_from_csv(path):
    with open(path, "r", encoding="utf-8-sig", newline="") as handle:
        return [row["name"] for row in csv.DictReader(handle) if row.get("name")]


def clear_integrated_challenges(path):
    names = challenge_names_from_csv(path)
    challenge_ids = [chal.id for chal in Challenges.query.filter(Challenges.name.in_(names)).all()]
    if not challenge_ids:
        return
    Tags.query.filter(Tags.challenge_id.in_(challenge_ids)).delete(synchronize_session=False)
    Hints.query.filter(Hints.challenge_id.in_(challenge_ids)).delete(synchronize_session=False)
    Flags.query.filter(Flags.challenge_id.in_(challenge_ids)).delete(synchronize_session=False)
    Challenges.query.filter(Challenges.id.in_(challenge_ids)).delete(synchronize_session=False)
    db.session.commit()


def import_csv(path):
    with open(path, "r", encoding="utf-8-sig", newline="") as handle:
        result = load_challenges_csv(csv.DictReader(handle))
    if result is not True:
        raise RuntimeError(f"Challenge import failed: {result}")


def sync_challenge_descriptions(path):
    with open(path, "r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            name = row.get("name")
            if not name:
                continue
            challenge = Challenges.query.filter_by(name=name).first()
            if challenge is None:
                continue
            description = row.get("description", "")
            if challenge.description != description:
                challenge.description = description
    db.session.commit()


def build_review_page(runtime):
    pico_ssh = runtime.get("PICO_GENERAL_SSH_HOST", "localhost")
    pico_ssh_port = runtime.get("PICO_GENERAL_SSH_PORT", "2222")
    pico_ssh_password = runtime.get("PICO_GENERAL_SSH_PASSWORD", "unknown")
    pico_rev_port = runtime.get("PICO_REVERSING_PYTHON_PORT", "2223")
    pico_perc_port = runtime.get("PICO_PERCEPTRON_PORT", "2224")
    pico_artifacts = runtime.get("PICO_ARTIFACTS_URL", "http://localhost:8084/start-problem-dev")
    juice_shop = runtime.get("JUICE_SHOP_URL", "http://localhost:3001")
    wrongsecrets = runtime.get("WRONGSECRETS_URL", "http://localhost:8081")
    pico_web = runtime.get("PICO_WEB_CSS_URL", "http://localhost:8083")
    return f"""# Integrated Repository Review

This CTFd instance was reviewed and seeded from the requested repositories with the following integration model:

| Repository | Review | Imported Into CTFd |
| --- | --- | --- |
| `apsdehal/awesome-ctf` | Curated reference list, not a native challenge pack | Reviewed on this page only |
| `pwncollege/ctf-archive` | Archive/source repository, not a drop-in CTFd export | Reviewed on this page only |
| `pwncollege/challenges` | Custom pwnshop + Docker monorepo with templating and encrypted private material | Reviewed on this page only |
| `picoCTF/start-problem-dev` | Challenge authoring examples | Two Docker-backed example challenges imported |
| `OWASP/wrongsecrets` | Dockerized training target with CTF export support | Imported via generated CTFd CSV |
| `juice-shop/juice-shop` | Dockerized training target | Imported via generated CTFd CSV |
| `juice-shop/juice-shop-ctf` | CTFd CSV generator used by the integration | Used as the import bridge |

## Local Runtime Endpoints

- Juice Shop: {juice_shop}
- WrongSecrets: {wrongsecrets}
- picoCTF Web CSS example: {pico_web}
- picoCTF General SSH example: `ssh -p {pico_ssh_port} ctf-player@{pico_ssh}` with password `{pico_ssh_password}`
- picoCTF Reversing Python example: `nc localhost {pico_rev_port}`
- picoCTF Perceptron Gate example: `nc localhost {pico_perc_port}`
- picoCTF artifact host: {pico_artifacts}

## Notes

- `awesome-ctf`, `ctf-archive`, and `pwncollege/challenges` are not native CTFd imports, so they were reviewed and documented instead of being forced into broken challenge entries.
- `wrongsecrets` and `juice-shop` were integrated the correct upstream way: expose the app, generate CTFd challenge CSV, then load the CSV into CTFd.
- The picoCTF example problems were normalized into standard CTFd rows with matching runtime endpoints and flags.
"""


app = create_app()
with app.app_context():
    ensure_setup()
    clear_integrated_challenges(CSV_PATH)
    import_csv(CSV_PATH)
    sync_challenge_descriptions(CSV_PATH)
    replace_page("repo-review", "Integrated Repository Review", build_review_page(load_runtime_env(RUNTIME_ENV_PATH)))
    db.session.commit()
    print("Seeded integrated CTF content successfully.")
