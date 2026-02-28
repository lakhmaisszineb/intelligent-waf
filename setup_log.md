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
- Explication : Sauvegarde la liste exacte des paquets installés (avec versions) pour partage. Contenu du fichier .

### Étape suivante : Structure du projet
- Date : 28 Février 2026
- Créé dossiers : app/, logs/
- Fichiers : __init__.py (vide), main.py (code proxy), proxy.py (vide), README.md, setup_log.md
- Objectif : base du reverse proxy

