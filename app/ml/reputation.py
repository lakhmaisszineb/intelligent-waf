from datetime import datetime, timedelta
from collections import defaultdict
import json
import os

class IPReputationEngine:
    
    def __init__(self, storage_path="logs/ip_lists.json"):
        self.storage_path = storage_path
        self.ip_scores = defaultdict(int)
        self.ip_offenses = defaultdict(int)
        self.ip_blocked_until = defaultdict(lambda: datetime.min)
        self.whitelist = set()
        self.blacklist = set()
        self._load_lists()

    def _load_lists(self):
        """Charge l'etat reputation (listes + score + offenses + ban) depuis le disque."""
        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return
        except Exception:
            return

        whitelist = data.get("whitelist", [])
        blacklist = data.get("blacklist", [])
        ip_scores = data.get("ip_scores", {})
        ip_offenses = data.get("ip_offenses", {})
        ip_blocked_until = data.get("ip_blocked_until", {})

        if isinstance(whitelist, list):
            self.whitelist = set(str(ip) for ip in whitelist if ip)
        if isinstance(blacklist, list):
            self.blacklist = set(str(ip) for ip in blacklist if ip)
        if isinstance(ip_scores, dict):
            loaded_scores = {}
            for ip, score in ip_scores.items():
                if not ip:
                    continue
                try:
                    loaded_scores[str(ip)] = int(score)
                except (TypeError, ValueError):
                    continue
            self.ip_scores = defaultdict(int, loaded_scores)
        if isinstance(ip_offenses, dict):
            loaded_offenses = {}
            for ip, offenses in ip_offenses.items():
                if not ip:
                    continue
                try:
                    loaded_offenses[str(ip)] = int(offenses)
                except (TypeError, ValueError):
                    continue
            self.ip_offenses = defaultdict(int, loaded_offenses)
        if isinstance(ip_blocked_until, dict):
            loaded_blocked_until = {}
            for ip, ts in ip_blocked_until.items():
                if not ip or not ts:
                    continue
                try:
                    loaded_blocked_until[str(ip)] = datetime.fromisoformat(str(ts))
                except (TypeError, ValueError):
                    continue
            self.ip_blocked_until = defaultdict(lambda: datetime.min, loaded_blocked_until)

    def _persist_lists(self):
        """Sauvegarde tout l'etat reputation sur disque pour survivre au redemarrage."""
        try:
            os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
            data = {
                "whitelist": sorted(self.whitelist),
                "blacklist": sorted(self.blacklist),
                "ip_scores": dict(sorted(self.ip_scores.items())),
                "ip_offenses": dict(sorted(self.ip_offenses.items())),
                "ip_blocked_until": {
                    ip: until.strftime('%Y-%m-%d %H:%M:%S')
                    for ip, until in sorted(self.ip_blocked_until.items())
                    if until and until != datetime.min
                },
                "updated_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            }
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            # Ne jamais casser le moteur WAF sur une erreur de persistence.
            pass
    
    def update_score(self, ip, is_attack, is_grey_zone, is_blocked):
        if ip in self.whitelist:
            return

        changed = False
        if is_blocked:
            self.ip_scores[ip] += 25
            self.ip_offenses[ip] += 1
            self._apply_ban(ip)
            changed = True
        elif is_grey_zone:
            self.ip_scores[ip] += 10
            changed = True
        elif not is_attack:
            self.ip_scores[ip] = max(0, self.ip_scores[ip] - 1)
            changed = True
        
        if self.ip_scores[ip] >= 100 and ip not in self.blacklist:
            self.add_blacklist(ip)
            changed = False

        if changed:
            self._persist_lists()
    
    def _apply_ban(self, ip):
        offense = self.ip_offenses[ip]
        if offense == 1:
            duration = 15
        elif offense == 2:
            duration = 60
        elif offense == 3:
            duration = 360
        elif offense == 4:
            duration = 1440
        elif offense >= 5:
            duration = 10080
        else:
            duration = 0
        self.ip_blocked_until[ip] = datetime.now() + timedelta(minutes=duration)
    
    def is_blocked(self, ip):
        if ip in self.blacklist:
            return True
        if ip in self.whitelist:
            return False
        if datetime.now() < self.ip_blocked_until.get(ip, datetime.min):
            return True
        return False
    
    def add_whitelist(self, ip):
        self.blacklist.discard(ip)
        self.whitelist.add(ip)
        self._persist_lists()
    
    def add_blacklist(self, ip):
        self.whitelist.discard(ip)
        self.blacklist.add(ip)
        self._persist_lists()

    def remove_whitelist(self, ip):
        if ip in self.whitelist:
            self.whitelist.discard(ip)
            self._persist_lists()
            return True
        return False

    def remove_blacklist(self, ip):
        if ip in self.blacklist:
            self.blacklist.discard(ip)
            self._persist_lists()
            return True
        return False
    
    def get_score(self, ip):
        return self.ip_scores.get(ip, 0)
    
    def get_offenses(self, ip):
        return self.ip_offenses.get(ip, 0)
    
    def unblock_ip(self, ip):
        if ip in self.ip_blocked_until:
            del self.ip_blocked_until[ip]
        self.ip_scores[ip]   = 0
        self.ip_offenses[ip] = 0
        self._persist_lists()
