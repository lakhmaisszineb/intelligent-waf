import os
import urllib.request

RULES_DIR = "rules"
OWASP_CRS_BASE = "https://raw.githubusercontent.com/coreruleset/coreruleset/v3.3/rules/"

RULE_FILES = [
    "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
    "REQUEST-941-APPLICATION-ATTACK-XSS.conf",
    "REQUEST-930-APPLICATION-ATTACK-LFI.conf",
    "REQUEST-931-APPLICATION-ATTACK-RFI.conf",
    "REQUEST-932-APPLICATION-ATTACK-RCE.conf",
    "REQUEST-933-APPLICATION-ATTACK-PHP.conf",
    "REQUEST-944-APPLICATION-ATTACK-JAVA.conf",
]

def download_rules():
    os.makedirs(RULES_DIR, exist_ok=True)
    for filename in RULE_FILES:
        url = OWASP_CRS_BASE + filename
        dest = os.path.join(RULES_DIR, filename)
        if os.path.exists(dest):
            print(f"[SKIP] {filename}")
            continue
        print(f"[DOWNLOAD] {filename} ...")
        try:
            urllib.request.urlretrieve(url, dest)
            print(f"[OK] {dest}")
        except Exception as e:
            print(f"[ERREUR] {filename} : {e}")
    print("\n Terminé !")

if __name__ == "__main__":
    download_rules()