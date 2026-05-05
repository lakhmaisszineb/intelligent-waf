import re
import numpy as np

class FeatureExtractor:
    
    def __init__(self):
        self.sqli_features_list = None
        self.xss_features_list = None
        self.master_features_list = None
        self.unsupervised_features_list = None
    
    def load_feature_names(self, sqli_path, xss_path):
        import joblib
        self.sqli_features_list = joblib.load(sqli_path)
        self.xss_features_list = joblib.load(xss_path)
    
    def load_master_features(self, master_path):
        import joblib
        self.master_features_list = joblib.load(master_path)
    
    def load_unsupervised_features(self, unsupervised_path):
        import joblib
        self.unsupervised_features_list = joblib.load(unsupervised_path)
    
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
        return [features[f] for f in self.unsupervised_features_list]
    
    def extract_master_features(self, request):
        request = str(request).lower()
        features = {}
        features['length'] = len(request)
        features['num_special_chars'] = sum(1 for c in request if c in "<>'\"();{}[]\\/%&*+=-@!`~|")
        features['num_dots'] = request.count('.')
        features['num_slashes'] = request.count('/') + request.count('\\')
        features['num_spaces'] = request.count(' ')
        features['has_traversal'] = int('../' in request or '..\\' in request or '%2e%2e' in request)
        features['has_etc_passwd'] = int('etc/passwd' in request or 'etc\\passwd' in request)
        features['has_proc'] = int('/proc/' in request)
        features['has_php_wrapper'] = int('php://' in request or 'zip://' in request or 'data://' in request)
        features['has_pipe'] = int('|' in request)
        features['has_semicolon'] = int(';' in request)
        features['has_backtick'] = int('`' in request)
        features['has_cmd_kw'] = int(any(kw in request for kw in ['cat ', 'ls ', 'whoami', 'id ', 'wget ', 'curl ', 'nc ', 'bash', 'sh ', 'cmd', 'ping ', 'nslookup', 'sleep ']))
        features['has_doctype'] = int('<!doctype' in request or '<!entity' in request)
        features['has_xml'] = int('<?xml' in request or '<xml' in request)
        features['has_entity'] = int('&' in request and ';' in request)
        features['has_template_kw'] = int(any(kw in request for kw in ['{{', '}}', '{%', '%}', '${', '#{', '<#', '#}', '@{', 'freemarker']))
        features['has_url_encoding'] = int(bool(re.search(r'%[0-9a-fA-F]{2}', request)))
        features['has_double_encoding'] = int(bool(re.search(r'%25[0-9a-fA-F]{2}', request)))
        entropy = 0
        if len(request) > 0:
            prob = [float(request.count(c)) / len(request) for c in set(request)]
            entropy = -sum(p * np.log2(p) for p in prob)
        features['payload_entropy'] = entropy
        features['special_char_ratio'] = sum(1 for c in request if c in "<>'\"();{}[]\\/%") / max(len(request), 1)
        return [features[f] for f in self.master_features_list]