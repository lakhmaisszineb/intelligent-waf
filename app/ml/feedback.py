import json
import os
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
            'timestamp': datetime.now().isoformat(),
            'client_ip': client_ip,
            'request': request_str[:500],  # Tronquer pour éviter fichiers trop gros
            'prediction': prediction,       # True=bloqué, False=autorisé
            'score': score,
            'zone': zone,
            'model': model,
            'attack_type': attack_type,
            'admin_validation': None,       # Sera rempli plus tard par l'admin
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
    
    def validate_decision(self, timestamp, validation):
        """
        Valide une décision (appelé depuis le dashboard)
        validation : 'TP' (True Positive), 'FP' (False Positive), 
                     'TN' (True Negative), 'FN' (False Negative)
        """
        entries = []
        with open(self.feedback_path, 'r') as f:
            for line in f:
                if line.strip():
                    entry = json.loads(line)
                    if entry['timestamp'] == timestamp:
                        entry['admin_validation'] = validation
                        entry['validation_date'] = datetime.now().isoformat()
                    entries.append(entry)
        
        with open(self.feedback_path, 'w') as f:
            for entry in entries:
                f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    
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