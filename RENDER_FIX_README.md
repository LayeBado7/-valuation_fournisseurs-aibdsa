# Render FIX — Évaluation Fournisseurs AIBD

Correction principale :
- `templates/error.html` sécurisé et présent dans le déploiement.
- Gestion robuste des erreurs Flask 403/404/413/500.
- `/favicon.ico` ne provoque plus une erreur 500 si le fichier n'existe pas.
- Le handler 500 dispose d'un fallback HTML si le template d'erreur ne peut pas être chargé.

## Déploiement
1. Remplacer/pousser les fichiers corrigés dans le dépôt GitHub.
2. Vérifier que `templates/error.html` est bien versionné.
3. Déclencher un nouveau déploiement Render.
4. Tester `/health`, puis `/login`.

Le endpoint `/health` doit continuer à retourner HTTP 200.
