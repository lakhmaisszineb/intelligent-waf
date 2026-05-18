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

        # Decision thresholds
        self.normal_th           = 0.50   # below → normal (no alert)
        self.attack_th           = 0.80   # combined(LOF+Master) → hard block
        self.expert_attack_th    = 0.70   # expert alone → block in grey zone
        self.category_confirm_th = 0.60   # expert score needed to confirm category in hard block
        self.alert_category_th   = 0.50   # expert score needed to label category in alerts

    def load_models(self):
        self.sqli_model = joblib.load(f'{self.models_path}/sqli_expert_model.pkl')
        self.xss_model = joblib.load(f'{self.models_path}/xss_expert_model.pkl')
        self.master_model = joblib.load(f'{self.models_path}/master_model.pkl')
        self.top3_names = joblib.load(f'{self.models_path}/top3_models_names.pkl')

        try:
            self.isolation_forest = joblib.load(f'{self.models_path}/isolation_forest_model.pkl')
            self.feature_extractor.load_unsupervised_features(f'{self.models_path}/unsupervised_features.pkl')
            print('Modele Isolation Forest charge avec succes')
        except FileNotFoundError:
            self.isolation_forest = None
            print('Modele Isolation Forest non trouve')

        self.feature_extractor.load_feature_names(
            f'{self.models_path}/sqli_features.pkl',
            f'{self.models_path}/xss_features.pkl'
        )
        self.feature_extractor.load_master_features(f'{self.models_path}/master_features.pkl')

        print(f'Modele Master charge (Voting: {self.top3_names})')
        print('Modeles SQLi, XSS et Master charges avec succes')

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

    def detect_anomaly_score(self, request):
        """
        Retourne un score continu entre 0 et 1 (1 = tres anormal).

        Notes:
        - Pour LOF novelty=True, decision_function > 0 => inlier (normal),
          decision_function < 0 => outlier.
        - Calibration conservative:
            * inlier / borderline (margin <= 0) -> 0.0
            * outlier margin > 0 -> croissance progressive vers 1.0
          Cela evite l'effet artificiel "50%" sur les requetes normales.
        """
        if self.isolation_forest is None:
            return 0.0

        features = self.feature_extractor.extract_unsupervised_features(request)
        features_array = np.array(features).reshape(1, -1)
        model = self.isolation_forest

        margin = 0.0

        # Preferred path for LOF novelty mode.
        if hasattr(model, "decision_function"):
            decision = float(model.decision_function(features_array)[0])
            # decision > 0: normal ; decision < 0: abnormal
            margin = -decision
        elif hasattr(model, "score_samples"):
            # Fallback for models exposing score_samples.
            raw_score = float(model.score_samples(features_array)[0])
            if hasattr(model, "offset_"):
                # For novelty estimators: decision_function ~= score_samples - offset_
                margin = float(model.offset_) - raw_score
            else:
                # Conservative default if no explicit threshold is available.
                margin = -raw_score
        else:
            return 0.0

        # margin <= 0 means inlier or on boundary => no anomaly risk.
        if margin <= 0.0:
            return 0.0

        # Smooth monotone mapping from positive margin to [0, 1):
        # small margins stay small (less false positives),
        # very large margins approach 1.
        anomaly_score = 1.0 - np.exp(-margin / 1.0)
        return float(np.clip(anomaly_score, 0.0, 1.0))

    def detect_attack(self, request):
        """
        Full pipeline: all four models always run.

        Hard blocks (LOF+Master combined high) pass through the expert models
        for category confirmation.  The returned `model` field lists every model
        that contributed to the decision so dashboards can display it accurately.

        Return tuple: (is_attack, score, zone, model, attack_type, details)
          zone values: 'attack' | 'grey_zone_normal' | 'normal'
        """
        master_score = self.detect_master(request)
        lof_score    = self.detect_anomaly_score(request)
        sqli_score   = self.detect_sqli(request)
        xss_score    = self.detect_xss(request)

        combined_score = (master_score + lof_score) / 2.0

        # Context-aware primary expert selection
        req_lc = request.lower()
        if '/xss' in req_lc:
            expert_score, attack_type, expert_model = xss_score, 'XSS',  'XSS_Expert'
        elif '/sqli' in req_lc:
            expert_score, attack_type, expert_model = sqli_score, 'SQLi', 'SQLi_Expert'
        elif sqli_score >= xss_score:
            expert_score, attack_type, expert_model = sqli_score, 'SQLi', 'SQLi_Expert'
        else:
            expert_score, attack_type, expert_model = xss_score,  'XSS',  'XSS_Expert'

        details = {
            'master_score':   master_score,
            'lof_score':      lof_score,
            'combined_score': combined_score,
            'expert_score':   expert_score,
            'sqli_score':     sqli_score,
            'xss_score':      xss_score,
            'hybrid_score':   (master_score + lof_score + expert_score) / 3.0,
        }

        # ── Hard block: LOF + Master combined score is high ──────────────
        if combined_score >= self.attack_th:
            blocking_models = ['Master_Model', 'LOF']
            # Try to confirm attack category via experts
            best_expert = max(sqli_score, xss_score)
            if best_expert >= self.category_confirm_th:
                if sqli_score >= xss_score:
                    blocking_models.append('SQLi_Expert')
                    category = 'SQLi'
                else:
                    blocking_models.append('XSS_Expert')
                    category = 'XSS'
            else:
                category = 'General'
            return True, combined_score, 'attack', '+'.join(blocking_models), category, details

        # ── Normal: clearly not an attack ────────────────────────────────
        if combined_score < self.normal_th:
            return False, combined_score, 'normal', '', '', details

        # ── Grey zone: expert decides ─────────────────────────────────────
        if expert_score >= self.expert_attack_th:
            # Expert confirms attack with specific category
            return True, expert_score, 'attack', expert_model, attack_type, details

        # ── Alert: suspicious but not confirmed ───────────────────────────
        # Model field reflects which individual models drove the alert, not the expert.
        alert_models = []
        if master_score >= self.normal_th:
            alert_models.append('Master_Model')
        if lof_score >= self.normal_th:
            alert_models.append('LOF')
        if expert_score >= self.alert_category_th:
            alert_models.append(expert_model)
        alert_type  = attack_type if expert_score >= self.alert_category_th else 'General'
        alert_model = '+'.join(alert_models) if alert_models else expert_model
        return False, combined_score, 'grey_zone_normal', alert_model, alert_type, details

