import os
import re
import json

RULES_DIR = "rules"
OUTPUT_FILE = "parsed_rules.json"

CATEGORY_MAP = {
    "942": "sql_injection",
    "941": "xss",
    "930": "lfi",
    "931": "rfi",
    "932": "rce",
    "933": "php_injection",
    "944": "java_attack",
}

def get_category(filename):
    for code, category in CATEGORY_MAP.items():
        if code in filename:
            return category
    return "other"

def extract_patterns_from_file(filepath):
    patterns = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    rx_matches = re.findall(r'@rx\s+"?([^"\\n]+)"?', content)
    for pattern in rx_matches:
        pattern = pattern.strip().strip('"').strip("'")
        if len(pattern) > 3:
            patterns.append(pattern)
    rx_quoted = re.findall(r'@rx\s+"([^"]+)"', content)
    for pattern in rx_quoted:
        pattern = pattern.strip()
        if pattern not in patterns and len(pattern) > 3:
            patterns.append(pattern)
    return patterns

def validate_pattern(pattern):
    try:
        re.compile(pattern, re.IGNORECASE)
        return True
    except re.error:
        return False

def parse_all_rules():
    rules_by_category = {}
    if not os.path.exists(RULES_DIR):
        print(f"[ERREUR] Dossier '{RULES_DIR}' introuvable. Lance d'abord download_rules.py")
        return
    conf_files = [f for f in os.listdir(RULES_DIR) if f.endswith(".conf")]
    if not conf_files:
        print(f"[ERREUR] Aucun fichier .conf trouvé dans {RULES_DIR}/")
        return
    total_patterns = 0
    for filename in sorted(conf_files):
        filepath = os.path.join(RULES_DIR, filename)
        category = get_category(filename)
        print(f"[PARSE] {filename} → {category}")
        patterns = extract_patterns_from_file(filepath)
        valid_patterns = [p for p in patterns if validate_pattern(p)]
        unique_patterns = list(dict.fromkeys(valid_patterns))
        if category not in rules_by_category:
            rules_by_category[category] = []
        rules_by_category[category].extend(unique_patterns)
        total_patterns += len(unique_patterns)
        print(f"  {len(unique_patterns)} patterns extraits")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(rules_by_category, f, indent=2, ensure_ascii=False)
    print(f"\n {total_patterns} patterns sauvegardés dans '{OUTPUT_FILE}'")

if __name__ == "__main__":
    parse_all_rules()