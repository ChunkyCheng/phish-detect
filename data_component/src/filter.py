from pathlib import Path
import sys
import shutil
import json
from bs4 import BeautifulSoup

ERROR_TITLE_KEYWORDS = {
    "404", "not found", "error", "forbidden",
    "access denied", "bad gateway", "service unavailable"
}

ERROR_BODY_KEYWORDS = {
    "page not found", "404 not found", "something went wrong",
    "potentially malicious", "site is no longer online",
    "campaign has been disabled", "temporarily unavailable",
    "service unavailable", "access denied", "forbidden"
}

TERMINATED_BODY_KEYWORDS = {
    "url terminated", "link terminated",
    "this link has been terminated", "this link has been disabled",
    "this link has been suspended", "this link has been blocked",
    "this url has been disabled", "account has been suspended",
    "account has been terminated", "hosting suspended",
    "domain suspended", "violation of our terms",
    "violated our terms", "abuse policy", "no-abuse policy",
    "used in violation", "reported as phishing",
    "reported for phishing", "flagged as phishing",
    "identified as phishing", "this site has been flagged",
    "this page has been suspended", "this page has been taken down",
    "this website has been suspended", "has been disabled by",
    "has been removed by", "taken down due to", "removed due to",
    "suspended due to", "terminated due to",
    "trial period has expired",
    "link space is being discontinued",
    "domain not available",
    "chatbot page is blocked",
    "link is no longer available"
}

TERMINATED_TITLES_EXACT = {
    "warning! | there might be a problem with the requested link",
    "warning! | the account that created this link has been suspended",
    "ukit — website's trial period has expired",
    "account suspended",
    "important update: streamlabs link space is being discontinued | streamlabs",
    "strato - domain not available",
    "this chatbot page is blocked",
    "link is no longer available"
}

TERMINATED_TITLE_KEYWORDS = {
    "account suspended",
    "domain suspended",
    "domain not available",
    "trial period has expired",
    "cpanel redirect",
    "link has been suspended",
    "link has been disabled",
    "link has been terminated",
    "being discontinued",
    "chatbot page is blocked",
    "qr code generator",
    "url shortener",
    "shortener",
}

# Field name/id substrings that suggest credential harvesting
CREDENTIAL_FIELD_KEYWORDS = {
    "password", "passwd", "pass", "pwd",
    "contrasena", "heslo", "kennwort", "wachtwoord",
    "motdepasse", "mot_de_passe", "parola", "senha",
    "email", "mail", "username", "user_name", "userid",
    "login", "account", "phone", "telefon", "mobile",
    "card", "cvv", "ssn", "dob", "credit",
}

def filter_all_jsons(input_dir):
    input_dir = Path(input_dir)
    good_data_dir = input_dir / "good_data"
    bad_data_dir = input_dir / "bad_data"

    for f in input_dir.iterdir():
        if f.is_file() and f.suffix == ".json":
            usable, reason = is_usable_for_training(f)
            if usable:
                print(f"✅ Usable: {f.name}")
                dst = good_data_dir / f.name
            else:
                print(f"⚠️  Unusable: {f.name} ({reason})")
                dst = bad_data_dir / reason / f.name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(f), dst)


def is_usable_for_training(json_path: Path) -> tuple[bool, str]:
    with json_path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not data.get("success", False):
        return False, "request_failed"
    if data.get("error") is not None:
        return False, "request_error"
    if data.get("status_code") != 200:
        return False, f"status_{data.get('status_code')}"

    body = data.get("body", "")
    if not body.strip():
        return False, "empty_body"

    headers = data.get("headers", {})
    content_type = headers.get("Content-Type", "").lower()
    if "html" not in content_type:
        return False, "non_html"

    soup = BeautifulSoup(body, "html.parser")

    title = ""
    if soup.title:
        title = soup.title.get_text(" ", strip=True).lower()

    page_text = soup.get_text(" ", strip=True).lower()

    if len(page_text) < 100:
        return False, "insufficient_text"

    if title in TERMINATED_TITLES_EXACT:
        return False, "terminated_title"

    if any(kw in title for kw in TERMINATED_TITLE_KEYWORDS):
        return False, "terminated_title"

    if any(kw in title for kw in ERROR_TITLE_KEYWORDS):
        return False, "error_title"

    if any(kw in page_text for kw in ERROR_BODY_KEYWORDS):
        return False, "error_page"

    if any(kw in page_text for kw in TERMINATED_BODY_KEYWORDS):
        return False, "terminated_page"
    
    return True, "usable"


if __name__ == "__main__":
    if len(sys.argv) == 2:
        filter_all_jsons(sys.argv[1])