# Installation et configuration de l'environnement

# 1. Créer un environnement virtuel
Dans ton terminal VSCode :
```bash
python -m venv env
```

# 2. Activer l'environnement virtuel
Toujours dans le terminal VSCode, exécute la commande suivante :
```bash
# Si tu es sur Git Bash :
source env/Scripts/activate
# Si tu es sur Windows CMD :
env\Scripts\activate.bat
# Si tu es sur Windows PowerShell :
.\venv\Scripts\Activate.ps1
# Si tu es sur Linux ou MacOS :
source env/bin/activate
```

# 3. Installer les dépendances
Maintenant que le venv est actif :
```bash
pip install -r requirements.txt
```# security-testing
