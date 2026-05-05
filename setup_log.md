# Log des Étapes du Projet WAF Intelligent
## Date : 25 Février 2026 (Début du projet)

### Étape 1 : Création du dossier projet
- Commande : `mkdir intelligent-waf`
- Explication : Crée le dossier principal pour le projet.

### Étape 2 : Navigation dans le dossier
- Commande : `cd intelligent-waf`
- Explication : Entre dans le dossier pour travailler dedans.

### Étape 3 : Création du venv
- Commande : `python3 -m venv venv`
- Explication : Crée l'environnement virtuel pour isoler les paquets Python.

### Étape 4 : Activation du venv (pour fish shell)
- Commande : `source venv/bin/activate.fish`
- Explication : Active le venv – prompt change avec (venv). Résolu erreur fish en utilisant .fish au lieu de activate.

### Étape 5 : Installation des paquets de base
- Commande : `pip install fastapi uvicorn httpx`
- Explication : Installe FastAPI (framework), Uvicorn (serveur), Httpx (pour forwarding).

### Étape 6 : Génération de requirements.txt
- Commande : `pip freeze > requirements.txt`
- Explication : Sauvegarde la liste exacte des paquets installés (avec versions) pour partage. Contenu du fichier mis à jour régulièrement.

### Étape 7 : Structure du projet (création dossiers et fichiers)
- Date : 28 Février 2026
- Créé dossiers : app/
- Fichiers : __init__.py (vide), main.py (code reverse proxy), proxy.py (vide), README.md, setup_log.md
- Objectif : base du reverse proxy

### Étape 8 : Premier push sur GitHub
- Date : 28 février 2026
- Commandes :
  git init
  git add .gitignore && git commit -m "Ajout .gitignore"
  git add . && git commit -m "Structure initiale projet"
  git remote add origin https://github.com/lakhmaisszineb/intelligent-waf.git
  git branch -M main
  git push -u origin main
- Résultat : Projet synchronisé sur GitHub (privé), branche main trackée.

### Étape 9 : Reverse proxy basique fonctionnel (forwarding pur)
- Date : 3 mars 2026
- Modification : TARGET_URL configurable via .env ou dans le code
- Test avec site distant : https://httpbin.org (public, fiable, sans installation)
- Commande de lancement : uvicorn app.main:waf --reload --port 8000
- Résultat : 
  - http://localhost:8000/anything → JSON de httpbin.org (preuve de forwarding correct)
  - Logs Uvicorn montrent requêtes entrantes et réponses 200 OK
- Objectif atteint : reverse proxy simple transmet les requêtes sans modification

### Notes générales
- Shell utilisé : fish (d’où activate.fish)
- Serveur : Uvicorn sur port 8000 (développement)
- Site cible test : httpbin.org (public) pour éviter installations complexes
- Prochaines étapes : ajouter règles de détection (regex SQLi/XSS) + extraction dans rule_engine.py


#uvicorn app.main:waf --reload --host 0.0.0.0 --port 8000