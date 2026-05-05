import re
import numpy as np

class FeatureExtractor:
    
    def __init__(self):
        self.sqli_features_list = None
        self.xss_features_list = None
    
    def load_feature_names(self, sqli_path, xss_path):
        import joblib
        self.sqli_features_list = joblib.load(sqli_path)
        self.xss_features_list = joblib.load(xss_path)
    
    def extract_sqli_features(self, request):
        request = str(request).lower()
        features = {}
        features['length'] = len(request)
        features['num_special_chars'] = sum(1 for c in request if c in "'\"\\;(){}[]<>%$#@!`~")
        features['num_spaces'] = request.count(' ')
        keywords = ['select', 'union', 'where', 'from', 'insert', 'update', 'delete', 'drop', 'or', 'and', 'sleep', 'benchmark', 'substr', 'concat', 'order', 'by', 'having', 'like', 'exec', 'execute', 'pg_sleep', 'waitfor', 'delay', 'create', 'alter']
        features['num_keywords'] = sum(1 for kw in keywords if kw in request)
        features['num_quotes'] = request.count("'") + request.count('"')
        features['num_parentheses'] = request.count('(') + request.count(')')
        features['has_comment'] = int('--' in request or '#' in request or '/*' in request)
        features['has_encoding'] = int('%' in request and len(re.findall(r'%[0-9a-f]{2}', request)) > 0)
        features['has_equals'] = int('=' in request)
        features['has_semicolon'] = int(';' in request)
        features['has_double_dash'] = int('--' in request)
        features['has_union'] = int('union' in request)
        return [features[f] for f in self.sqli_features_list]
    
    def extract_xss_features(self, request):
        request = str(request).lower()
        features = {}
        features['length'] = len(request)
        features['num_special_chars'] = sum(1 for c in request if c in "<>\"'();&%$#@!`~")
        features['num_tags'] = request.count('<') + request.count('>')
        features['num_scripts'] = int('script' in request)
        xss_keywords = ['alert', 'onerror', 'onload', 'onclick', 'onmouseover', 'javascript', 'iframe', 'img', 'svg', 'body', 'eval', 'prompt', 'confirm', 'document', 'cookie', 'window', 'location']
        features['num_xss_keywords'] = sum(1 for kw in xss_keywords if kw in request)
        features['num_quotes'] = request.count("'") + request.count('"')
        features['num_parentheses'] = request.count('(') + request.count(')')
        features['has_script'] = int('script' in request)
        features['has_event'] = int('onerror' in request or 'onload' in request or 'onclick' in request)
        features['has_encoding'] = int('%' in request and len(re.findall(r'%[0-9a-f]{2}', request)) > 0)
        features['has_url_encoding'] = int('%3c' in request or '%3e' in request or '%3C' in request or '%3E' in request)
        return [features[f] for f in self.xss_features_list]

def extract_unsupervised_features(self, request):
    request = str(request).lower()
    features = {}
    features['length'] = len(request)
    features['num_special_chars'] = sum(1 for c in request if c in "'\"\\;(){}[]<>%$#@!`~")
    features['num_spaces'] = request.count(' ')
    features['num_quotes'] = request.count("'") + request.count('"')
    features['num_parentheses'] = request.count('(') + request.count(')')
    features['num_digits'] = sum(c.isdigit() for c in request)
    features['has_encoding'] = int('%' in request)
    return [features[f] for f in self.unsupervised_features]