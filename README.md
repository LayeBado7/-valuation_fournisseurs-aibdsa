# Évaluation Fournisseurs AIBD SA

Application Flask de gestion du risque cybersécurité des fournisseurs du Pôle SI, conçue sur le même principe que JustifAbsences-AIBD : authentification, rôles, base SQL, interface web, suivi et déploiement GitHub/Render.

## Fonctionnalités
- Un seul administrateur maître : aucun compte fournisseur ne peut être créé publiquement.
- Création des comptes fournisseurs par l'administrateur.
- 17 fournisseurs du fichier « LISTES DES FOURNISSEURS PSI » préchargés.
- Classification : Critique / Important / Standard / À classer.
- Questionnaire d'évaluation aligné sur la recommandation ANACIM 3.278.26.09/04.
- 9 domaines et pondération sur 100 points.
- Réponses Oui / Partiel / Non / N/A.
- Calcul automatique du score et du niveau de risque.
- Dépôt de pièces justificatives.
- Soumission par le fournisseur puis validation/correction par l'administrateur.
- Tableau de bord des fournisseurs.
- SQLite en local et PostgreSQL compatible Render.
- Python Render explicitement fixé à 3.14.3 et Psycopg 3.3.4 compatible Python 3.14.
- `render.yaml` prêt pour GitHub → Render.

## Démarrage local
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY='une-cle-secrete'
export ADMIN_USERNAME='admin'
export ADMIN_PASSWORD='ChangeMeNow!'
python app.py
```
Windows PowerShell : utiliser `$env:SECRET_KEY=...`.

URL locale : http://127.0.0.1:5000

## Déploiement Render
1. Pousser le projet sur GitHub.
2. Créer le service Render à partir du dépôt.
3. Ajouter `ADMIN_USERNAME`, `ADMIN_PASSWORD` et éventuellement `ADMIN_NAME` dans les variables d'environnement.
4. Le `render.yaml` crée le PostgreSQL et configure Gunicorn.

## Sécurité à renforcer avant production
- Stocker les uploads sur un stockage objet privé plutôt que dans le filesystem du Web Service.
- Activer HTTPS, politique de mots de passe forte et MFA administrateur.
- Ajouter journal d'audit immuable des actions administratives.
- Ajouter rotation/expiration des mots de passe fournisseurs.
- Ajouter export PDF/Excel et signature/validation formelle.
- Ajouter clauses contractuelles et workflow Achats/Juridique.
