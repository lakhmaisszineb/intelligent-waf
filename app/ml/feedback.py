import json
import os
import uuid
from datetime import datetime

class FeedbackCollector:
    """
    Collecte les décisions du WAF et les validations administrateur
    pour le réentraînement futur des modèles (Active Learning)
    """
    
    def __init__(self, feedback_path='logs/feedback.jsonl'):
        self.feedback_path = feedback_path
        # Créer le fichier s'il n'existe pas
        if not os.path.exists(feedback_path):
            with open(feedback_path, 'w') as f:
                f.write('')
    
    def log_decision(self, request_str, prediction, score, zone, model, attack_type, client_ip):
        """Enregistre chaque décision ML dans le fichier feedback"""
        entry = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.now().isoformat(),
            'client_ip': client_ip,
            'request': request_str[:500],
            'prediction': prediction,
            'score': score,
            'zone': zone,
            'model': model,
            'attack_type': attack_type,
            'admin_validation': None,
            'validation_date': None
        }
        
        with open(self.feedback_path, 'a') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    
    def get_unvalidated(self, limit=50):
        """Récupère les décisions non encore validées par l'admin"""
        entries = []
        try:
            with open(self.feedback_path, 'r') as f:
                for line in f:
                    if line.strip():
                        entry = json.loads(line)
                        if entry['admin_validation'] is None:
                            entries.append(entry)
                            if len(entries) >= limit:
                                break
        except FileNotFoundError:
            pass
        return entries
    
    def validate_decision(self, entry_id: str, validation: str) -> bool:
        """
        Valide une décision (appelé depuis le dashboard) — match par UUID.
        validation : 'TP' | 'FP' | 'TN' | 'FN'
        Retourne True si l'entrée a été trouvée et mise à jour.
        """
        entries = []
        found = False
        try:
            with open(self.feedback_path, 'r') as f:
                for line in f:
                    if line.strip():
                        entry = json.loads(line)
                        if entry.get('id') == entry_id:
                            entry['admin_validation'] = validation
                            entry['validation_date'] = datetime.now().isoformat()
                            found = True
                        entries.append(entry)
        except FileNotFoundError:
            return False

        if found:
            with open(self.feedback_path, 'w') as f:
                for entry in entries:
                    f.write(json.dumps(entry, ensure_ascii=False) + '\n')
        return found

    def log_and_validate(self, request_str, prediction, score, zone,
                          model, attack_type, client_ip, validation) -> str:
        """
        Crée une nouvelle entrée et la valide immédiatement.
        Utilisé par le feedback direct depuis le dashboard (waf.log → feedback.jsonl).
        Retourne l'UUID de l'entrée créée.
        """
        now = datetime.now().isoformat()
        entry = {
            'id':               str(uuid.uuid4()),
            'timestamp':        now,
            'client_ip':        client_ip,
            'request':          request_str[:500],
            'prediction':       prediction,
            'score':            score,
            'zone':             zone,
            'model':            model,
            'attack_type':      attack_type,
            'admin_validation': validation,
            'validation_date':  now,
        }
        with open(self.feedback_path, 'a') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
        return entry['id']

    def delete_entry(self, entry_id: str) -> bool:
        """
        Supprime une entree du fichier feedback par UUID.
        Retourne True si une entree a ete supprimee, sinon False.
        """
        entries = []
        found = False
        try:
            with open(self.feedback_path, 'r') as f:
                for line in f:
                    if not line.strip():
                        continue
                    entry = json.loads(line)
                    if entry.get('id') == entry_id:
                        found = True
                        continue
                    entries.append(entry)
        except FileNotFoundError:
            return False

        if not found:
            return False

        with open(self.feedback_path, 'w') as f:
            for entry in entries:
                f.write(json.dumps(entry, ensure_ascii=False) + '\n')
        return True
    
    def get_labeled_data(self):
        """Récupère toutes les données validées pour réentraînement"""
        labeled = []
        try:
            with open(self.feedback_path, 'r') as f:
                for line in f:
                    if line.strip():
                        entry = json.loads(line)
                        if entry['admin_validation']:
                            labeled.append(entry)
        except FileNotFoundError:
            pass
        return labeled
    
    def get_statistics(self):
        """Statistiques pour le dashboard"""
        total = 0
        validated = 0
        tp = fp = tn = fn = 0
        
        try:
            with open(self.feedback_path, 'r') as f:
                for line in f:
                    if line.strip():
                        total += 1
                        entry = json.loads(line)
                        if entry['admin_validation'] == 'TP':
                            tp += 1
                            validated += 1
                        elif entry['admin_validation'] == 'FP':
                            fp += 1
                            validated += 1
                        elif entry['admin_validation'] == 'TN':
                            tn += 1
                            validated += 1
                        elif entry['admin_validation'] == 'FN':
                            fn += 1
                            validated += 1
        except FileNotFoundError:
            pass
        
        return {
            'total_decisions': total,
            'validated': validated,
            'pending': total - validated,
            'true_positives': tp,
            'false_positives': fp,
            'true_negatives': tn,
            'false_negatives': fn,
            'accuracy': (tp + tn) / validated if validated > 0 else 0
        }
