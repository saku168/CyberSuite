# Contribuer à CyberSuite

Merci de vouloir aider le projet !

## Avant de proposer un changement

- Ouvre une issue pour décrire le bug ou l'amélioration envisagée.
- Garde les fonctionnalités orientées vers la défense et l'analyse locale.
- N'ajoute pas de scan de masse, d'exploitation, de collecte de secrets ou d'envoi de données sans consentement.
- N'ajoute aucune dépendance sans expliquer pourquoi elle est nécessaire.

## Développement

1. Forke le dépôt et crée une branche dédiée.
2. Utilise Python 3.11 ou supérieur.
3. Lance l'application avec `python main.py`.
4. Vérifie la syntaxe avec `python -m py_compile main.py`.
5. Décris clairement les changements et leurs limites dans ta pull request.

## Qualité et confidentialité

- Ne commite jamais de mots de passe, jetons, journaux privés ou données personnelles.
- Les analyses doivent rester locales lorsque c'est possible.
- Les résultats heuristiques doivent être présentés comme indicatifs.
- Ajoute des tests pour toute nouvelle logique de détection lorsque c'est raisonnable.
