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

        # Production-oriented decision thresholds
        self.hard_block_th = 0.90
        self.lof_hard_th = 0.95
        self.support_th = 0.55
        self.ensemble_block_th = 0.75
        self.ensemble_alert_th = 0.45

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
        Ensemble decision flow (all models evaluated in parallel):
        1) Hard block if:
           - expert >= 0.90, or
           - master >= 0.90, or
           - lof >= 0.95 and (master >= 0.55 or expert >= 0.55)
        2) Otherwise compute equal-weight ensemble:
           ensemble = (master + lof + expert) / 3
           - ensemble >= 0.75 => block
           - 0.45 <= ensemble < 0.75 => alert
           - else => allow

        LOF-only spikes (high LOF without support) generate alert, not block.
        """
        master_score = self.detect_master(request)
        lof_score = self.detect_anomaly_score(request)
        sqli_score = self.detect_sqli(request)
        xss_score = self.detect_xss(request)
        expert_score = max(sqli_score, xss_score)

        if sqli_score >= xss_score:
            attack_type = 'SQLi'
            expert_model = 'SQLi_Expert'
        else:
            attack_type = 'XSS'
            expert_model = 'XSS_Expert'

        ensemble_score = (master_score + lof_score + expert_score) / 3.0

        details = {
            'master_score': master_score,
            'lof_score': lof_score,
            # Keep "combined_score" for dashboard backward compatibility:
            # it now represents the equal-weight ensemble score.
            'combined_score': ensemble_score,
            'expert_score': expert_score,
            'sqli_score': sqli_score,
            'xss_score': xss_score,
            'hybrid_score': None,
        }

        # 1) Hard blockers
        if expert_score >= self.hard_block_th:
            return True, expert_score, 'attack', expert_model, attack_type, details

        if master_score >= self.hard_block_th:
            return True, master_score, 'attack', 'Master_Model', 'General', details

        lof_supported = (
            lof_score >= self.lof_hard_th and
            (master_score >= self.support_th or expert_score >= self.support_th)
        )
        if lof_supported:
            return True, lof_score, 'attack', 'LOF+Support', 'Anomaly', details

        # 2) Equal-weight ensemble decision
        if ensemble_score >= self.ensemble_block_th:
            return True, ensemble_score, 'attack', 'Ensemble', attack_type, details

        # LOF alone can still raise alert even if ensemble is low.
        if lof_score >= self.lof_hard_th:
            return False, lof_score, 'grey_zone_normal', 'LOF', 'Anomaly', details

        if ensemble_score >= self.ensemble_alert_th:
            return False, ensemble_score, 'grey_zone_normal', 'Ensemble', attack_type, details

        return False, ensemble_score, 'normal', '', '', details

