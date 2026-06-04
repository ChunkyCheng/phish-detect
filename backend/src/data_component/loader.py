import json
import sqlite3
from pathlib import Path


def load_all_json(in_dir, out_dir):
    input_path = Path(in_dir)
    output_path = Path(out_dir)
    output_path.mkdir(parents=True, exist_ok=True)  # create dir if not exist

    # where db output resides
    db_path = output_path / "phishing.db"

    # connect to sqlite
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # delete the table if it exists
    # cursor.execute(
    #     "DROP TABLE IF EXISTS phishing_sites"
    # )  # for any column format changes

    # create phishing table if not exist yet
    # duplicate url will be auto rejected - primary key
    # change the column names
    cursor.execute("""
            CREATE TABLE IF NOT EXISTS phishing_sites (
                url TEXT PRIMARY KEY,
                status_code INTEGER,
                text_sample TEXT,
                -- URL features
                domain TEXT,
                subdomain_count INTEGER,
                uses_ip INTEGER,
                path_length INTEGER,
                query_length INTEGER,
                has_suspicious_tld INTEGER,
                path_entropy_hint REAL,
                -- Page content features
                visible_text_length INTEGER,
                word_count INTEGER,
                link_count INTEGER,
                internal_links INTEGER,
                external_links INTEGER,
                -- Form features (summary counts)
                form_count INTEGER,
                [forms.action] TEXT,
                [forms.method] TEXT,
                [forms.input_types.text] INTEGER,
                [forms.input_types.hidden] INTEGER,
                [forms.input_types.submit] INTEGER,
                [forms.is_external_action] INTEGER,
                [forms.has_password] INTEGER,
                external_form_posts INTEGER,
                password_forms INTEGER,
                -- Form details (nested — stored as JSON string)
                -- forms_detail TEXT
                -- Script features (summary counts)
                script_count INTEGER,
                inline_script_count INTEGER,
                external_script_count INTEGER,
                -- Script details (arrays — stored as JSON string)
                external_scripts TEXT,
                script_signals TEXT,
                -- Risk signals
                has_password_forms INTEGER,
                external_form_post INTEGER,
                suspicious_scripts INTEGER,
                urgent_language INTEGER,
                -- Keywords
                login_keyword_count INTEGER,
                login_keyword_matches TEXT,
                -- N-grams (stored as JSON string)
                bigrams TEXT,
                trigrams TEXT
            )
        """)
    conn.commit()

    total_files = 0
    inserted = 0
    skipped = 0

    # Test with first N files only
    # for json_file in itertools.islice(input_path.glob("*.json"), 2500):
    for json_file in input_path.glob("*.json"):
        total_files += 1
        try:
            data = json.loads(
                json_file.read_text(encoding="utf-8")
            )  # read & parse json

            uf = data.get("url_features", {})
            forms = data.get("forms", {})
            scripts = data.get("scripts", {})
            risk = data.get("risk_score_inputs", {})
            keywords = data.get("keywords", {})
            forms_list = forms.get("forms", [])
            forms2 = (
                forms_list[0] if isinstance(forms_list, list) and forms_list else {}
            )
            input_types = forms2.get("input_types", {})

            cursor.execute(
                """
                INSERT OR IGNORE INTO phishing_sites VALUES (
                    ?,?,?,?,?,?,?,?,?,
                    ?,?,?,?,?,
                    ?,?,?,?,
                    ?,?,?,?,?,
                    ?,?,?,?,
                    ?,?,
                    ?,?,?,
                    ?,?,?,?,?,
                    ?
                )
                """,
                (
                    data.get("url"),
                    data.get("status_code"),
                    data.get("text_sample"),
                    # URL features
                    uf.get("domain"),
                    uf.get("subdomain_count", 0),
                    int(uf.get("uses_ip", False)),
                    uf.get("path_length", 0),
                    uf.get("query_length", 0),
                    int(uf.get("has_suspicious_tld", False)),
                    uf.get("path_entropy_hint", 0.0),
                    # Page content
                    data.get("visible_text_length", 0),
                    data.get("word_count", 0),
                    data.get("link_count", 0),
                    data.get("internal_links", 0),
                    data.get("external_links", 0),
                    # Form summary
                    forms.get("form_count", 0),
                    forms2.get("action"),
                    forms2.get("method"),
                    input_types.get("text", 0),
                    input_types.get("hidden", 0),
                    input_types.get("submit", 0),
                    int(forms2.get("is_external_action", False)),
                    int(forms2.get("has_password", False)),
                    int(forms.get("external_form_posts", 0) > 0),
                    int(forms.get("password_forms", 0) > 0),
                    # Script summary
                    scripts.get("script_count", 0),
                    scripts.get("inline_script_count", 0),
                    scripts.get("external_script_count", 0),
                    # Script details — arrays as JSON string
                    json.dumps(scripts.get("external_scripts", [])),
                    ", ".join(scripts.get("script_signals", [])),
                    # Risk signals
                    int(risk.get("has_password_forms", False)),
                    int(risk.get("external_form_post", False)),
                    int(risk.get("suspicious_scripts", False)),
                    int(risk.get("urgent_language", False)),
                    # Keywords
                    keywords.get("login", {}).get("count", 0),
                    ", ".join(keywords.get("login", {}).get("matches", [])),
                    # N-grams
                    ", ".join(data.get("bigrams", [])),
                    ", ".join(data.get("trigrams", [])),
                ),
            )
            if cursor.rowcount > 0:
                inserted += 1
                print(f"✅ Inserted {total_files}: {json_file.name}")
            else:
                print(f"⏭️ Skipped duplicate {total_files}: {json_file.name}")
                skipped += 1
            conn.commit()

        except Exception as e:
            print(f"[ERROR] {json_file.name}: {e}")
    conn.close()
    print(
        f"Done. Files: {total_files} | Inserted: {inserted} | Skipped (duplicate): {skipped}"
    )
    print(f"Database saved to: {db_path}")


def main():
    input = Path("../data/processed")
    output = Path("../data/phishing_db")
    load_all_json(input, output)


if __name__ == "__main__":
    main()
