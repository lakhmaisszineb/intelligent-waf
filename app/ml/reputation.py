from datetime import datetime, timedelta
from collections import defaultdict

class IPReputationEngine:
    
    def __init__(self):
        self.ip_scores = defaultdict(int)
        self.ip_offenses = defaultdict(int)
        self.ip_blocked_until = defaultdict(datetime)
        self.whitelist = set()
        self.blacklist = set()
    
    def update_score(self, ip, is_attack, is_grey_zone, is_blocked):
        if ip in self.whitelist:
            return
        if is_blocked:
            self.ip_scores[ip] += 25
            self.ip_offenses[ip] += 1
            self._apply_ban(ip)
        elif is_grey_zone:
            self.ip_scores[ip] += 10
        elif not is_attack:
            self.ip_scores[ip] = max(0, self.ip_scores[ip] - 1)
        
        if self.ip_scores[ip] >= 100:
            self.blacklist.add(ip)
    
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
        self.whitelist.add(ip)
    
    def add_blacklist(self, ip):
        self.blacklist.add(ip)