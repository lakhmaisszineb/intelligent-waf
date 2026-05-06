import joblib
import numpy as np
from .feature_extractor import FeatureExtractor

class MLDetectionEngine:
    
    def __init__(self, models_path='pkis/'):
        self.models_path = models_path
        self.sqli_model = None
        self.xss_model = None
        self.master_model = None
        self.top3_names = None
        self.isolation_forest = None
        self.feature_extractor = FeatureExtractor()
        
    def load_models(self):
        self.sqli_model = joblib.load(f'{self.models_path}/sqli_expert_model.pkl')
        self.xss_model = joblib.load(f'{self.models_path}/xss_expert_model.pkl')
        self.master_model = joblib.load(f'{self.models_path}/master_model.pkl')
        self.top3_names = joblib.load(f'{self.models_path}/top3_models_names.pkl')
        
        try:
            self.isolation_forest = joblib.load(f'{self.models_path}/isolation_forest_model.pkl')
            self.feature_extractor.load_unsupervised_features(f'{self.models_path}/unsupervised_features.pkl')
            print("Modele Isolation Forest charge avec succes")
        except FileNotFoundError:
            self.isolation_forest = None
            print("Modele Isolation Forest non trouve")
        
        self.feature_extractor.load_feature_names(
            f'{self.models_path}/sqli_features.pkl',
            f'{self.models_path}/xss_features.pkl'
        )
        self.feature_extractor.load_master_features(f'{self.models_path}/master_features.pkl')
        
        print(f"Modele Master charge (Voting: {self.top3_names})")
        print("Modeles SQLi, XSS et Master charges avec succes")
    
    def detect_sqli(self, request):
        features = self.feature_extractor.extract_sqli_features(request)
        features_array = np.array(features).reshape(1, -1)
        score = self.sqli_model.predict_proba(features_array)[0][1]
        return score
    
    def detect_xss(self, request):
        features = self.feature_extractor.extract_xss_features(request)
        features_array = np.array(features).reshape(1, -1)
        score = self.xss_model.predict_proba(features_array)[0][1]
        return score
    
    def detect_master(self, request):
        features = self.feature_extractor.extract_master_features(request)
        features_array = np.array(features).reshape(1, -1)
        score = self.master_model.predict_proba(features_array)[0][1]
        return score
    
    def detect_anomaly(self, request):
        if self.isolation_forest is None:
            return False
        features = self.feature_extractor.extract_unsupervised_features(request)
        features_array = np.array(features).reshape(1, -1)
        prediction = self.isolation_forest.predict(features_array)
        return prediction[0] == -1
    
    def detect_attack(self, request):
        master_score = self.detect_master(request)

        if master_score >= 0.8:
            # Identifier quel expert confirme
            sqli_score = self.detect_sqli(request)
            xss_score  = self.detect_xss(request)

            if sqli_score >= 0.7:
                attack_type = "SQLi"
                model_name  = "SQLi_Expert"
            elif xss_score >= 0.7:
                attack_type = "XSS"
                model_name  = "XSS_Expert"
            else:
                attack_type = "General"
                model_name  = "Master_Model"

            return True, master_score, 'attack', model_name, attack_type

        elif master_score < 0.5:
            is_anomaly = self.detect_anomaly(request)
            if is_anomaly:
                return False, master_score, 'anomaly_alert', 'LOF', 'Anomalie'
            return False, master_score, 'normal', '', ''

        else:
            sqli_score = self.detect_sqli(request)
            xss_score  = self.detect_xss(request)
            max_expert_score = max(sqli_score, xss_score)

            if sqli_score >= xss_score:
                attack_type = "SQLi"
                model_name  = "SQLi_Expert"
            else:
                attack_type = "XSS"
                model_name  = "XSS_Expert"

            if max_expert_score >= 0.7:
                return True, max_expert_score, 'attack', model_name, attack_type
            elif max_expert_score < 0.4:
                return False, max_expert_score, 'normal', '', ''
            else:
                return None, max_expert_score, 'grey_zone', model_name, attack_type