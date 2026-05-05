import joblib
import numpy as np
from .feature_extractor import FeatureExtractor

class MLDetectionEngine:
    
    def __init__(self, models_path='pkis/'):
        self.models_path = models_path
        self.sqli_model = None
        self.xss_model = None
        self.master_model = None
        self.feature_extractor = FeatureExtractor()
        
    def load_models(self):
        self.sqli_model = joblib.load(f'{self.models_path}/sqli_expert_model.pkl')
        self.xss_model = joblib.load(f'{self.models_path}/xss_expert_model.pkl')
        self.master_model = joblib.load(f'{self.models_path}/master_model.pkl')
        self.feature_extractor.load_feature_names(
            f'{self.models_path}/sqli_features.pkl',
            f'{self.models_path}/xss_features.pkl'
        )
        print("Modeles ML charges avec succes")
    
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
        sqli_score = self.detect_sqli(request)
        xss_score = self.detect_xss(request)
        scores = np.array([[sqli_score, xss_score]])
        score = self.master_model.predict_proba(scores)[0][1]
        return score
    
    def detect_attack(self, request):
        master_score = self.detect_master(request)
        if master_score >= 0.7:
            return True, master_score, 'attack'
        elif master_score < 0.4:
            return False, master_score, 'normal'
        else:
            sqli_score = self.detect_sqli(request)
            xss_score = self.detect_xss(request)
            max_expert_score = max(sqli_score, xss_score)
            if max_expert_score >= 0.7:
                return True, max_expert_score, 'attack'
            elif max_expert_score < 0.4:
                return False, max_expert_score, 'normal'
            else:
                return None, max_expert_score, 'grey_zone'