# CyberSuite

Application de bureau de cybersécurité défensive pour Windows 11, en français.

## Modules

- **CyberScanner** : contrôle TCP limité à cinq ports courants sur une adresse IP privée, locale ou link-local explicitement saisie. Aucun balayage de plage, aucune exploitation.
- **PasswordChecker** : estimation locale indicative de robustesse. Le texte saisi est effacé après l'évaluation et n'est jamais enregistré ni envoyé.
- **LogAnalyzer** : recherche de motifs courants dans un fichier journal texte choisi localement.
- **PhishingDetector** : repérage heuristique d'indices suspects dans un message ou une URL. Aucun lien n'est ouvert.

## Lancer depuis les sources

1. Installer Python 3.11 ou supérieur.
2. Dans le dossier du projet :

```powershell
python main.py
```

Le projet n'utilise que la bibliothèque standard Python pour fonctionner.

## Obtenir l'exécutable Windows

Ouvre l'onglet **Actions** du dépôt et lance le workflow **Build Windows executable** avec **Run workflow**. Une fois terminé, télécharge `CyberSuite.exe` dans les artefacts du workflow.

Pour publier une version dans **Releases**, crée et pousse un tag de version, par exemple :

```powershell
git tag v1.0.0
git push origin v1.0.0
```

Le workflow construit alors `CyberSuite.exe` et l'ajoute à la release GitHub correspondante.

## Compilation manuelle

```powershell
python -m pip install --upgrade pip
python -m pip install pyinstaller
pyinstaller --noconfirm --clean --onefile --windowed --name CyberSuite main.py
```

L'exécutable se trouve dans `dist\CyberSuite.exe`.

## Utilisation responsable et limites

Utilise CyberSuite uniquement sur tes propres systèmes, fichiers et comptes, ou avec une autorisation explicite. CyberScanner n'accepte que des adresses IP privées/locales et réalise uniquement quelques connexions TCP de vérification. Les résultats sont indicatifs : ils ne constituent pas un audit complet et peuvent contenir des faux positifs ou des faux négatifs.

**PasswordChecker :** n'entre jamais un mot de passe réellement utilisé. L'évaluation est une heuristique locale, pas un contrôle contre des bases de mots de passe compromis.
