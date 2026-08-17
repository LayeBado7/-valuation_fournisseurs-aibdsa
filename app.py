import csv, os, secrets
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, redirect, render_template, request, send_from_directory, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE = Path(__file__).resolve().parent
UPLOAD_DIR = BASE / 'static' / 'uploads'
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
db_url = os.getenv('DATABASE_URL', 'sqlite:///instance/aibd_fournisseurs.db')
if db_url.startswith('postgres://'):
    db_url = db_url.replace('postgres://', 'postgresql+psycopg://', 1)
elif db_url.startswith('postgresql://'):
    db_url = db_url.replace('postgresql://', 'postgresql+psycopg://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 10 * 1024 * 1024))
app.config['UPLOAD_FOLDER'] = str(UPLOAD_DIR)
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv', 'png', 'jpg', 'jpeg'}

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Veuillez vous connecter.'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='supplier')
    supplier_id = db.Column(db.Integer, db.ForeignKey('supplier.id'), nullable=True)
    full_name = db.Column(db.String(180), nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Supplier(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    numero = db.Column(db.Integer, unique=True)
    entreprise = db.Column(db.String(180), nullable=False)
    contact = db.Column(db.String(80))
    email = db.Column(db.String(255))
    agree = db.Column(db.String(120))
    description = db.Column(db.Text)
    criticality = db.Column(db.String(20), default='À classer')
    status = db.Column(db.String(30), default='Non évalué')
    score = db.Column(db.Float)
    risk_level = db.Column(db.String(30))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user = db.relationship('User', backref='supplier', uselist=False)
    evaluation = db.relationship('Evaluation', backref='supplier', uselist=False, cascade='all, delete-orphan')

class Evaluation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    supplier_id = db.Column(db.Integer, db.ForeignKey('supplier.id'), nullable=False, unique=True)
    status = db.Column(db.String(30), default='Brouillon')
    reviewer_note = db.Column(db.Text)
    submitted_at = db.Column(db.DateTime)
    reviewed_at = db.Column(db.DateTime)
    answers = db.relationship('EvaluationAnswer', backref='evaluation', cascade='all, delete-orphan')
    evidence = db.relationship('Evidence', backref='evaluation', cascade='all, delete-orphan')

class EvaluationAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    evaluation_id = db.Column(db.Integer, db.ForeignKey('evaluation.id'), nullable=False)
    code = db.Column(db.String(40), nullable=False)
    answer = db.Column(db.String(20), nullable=False, default='NA')
    comment = db.Column(db.Text)

class Evidence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    evaluation_id = db.Column(db.Integer, db.ForeignKey('evaluation.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

CRITERIA = [
    ('GOV-01', 'Gouvernance et conformité', 15, 'Politique de sécurité, responsabilités, conformité et certifications.'),
    ('SEC-01', 'Cybersécurité technique', 25, 'Protection des postes, réseaux, serveurs, vulnérabilités et sécurité opérationnelle.'),
    ('DAT-01', 'Protection des données', 15, 'Confidentialité, intégrité, sauvegarde, conservation et protection des données AIBD.'),
    ('ACC-01', 'Gestion des accès', 10, 'Comptes nominatifs, moindre privilège, MFA, traçabilité et retrait des accès.'),
    ('INC-01', 'Gestion des incidents', 10, 'Détection, notification, traitement et retour d’expérience des incidents.'),
    ('BCP-01', 'Continuité / PRA-PCA', 10, 'Continuité, reprise, sauvegardes et tests périodiques.'),
    ('SUP-01', 'Personnel et sous-traitants', 5, 'Sensibilisation, confidentialité et maîtrise des sous-traitants.'),
    ('DEV-01', 'Développement / produits', 5, 'Cycle de développement sécurisé, mises à jour et gestion des vulnérabilités.'),
    ('REV-01', 'Réversibilité et fin de contrat', 5, 'Restitution/destruction des données, retrait des comptes et réversibilité.'),
]

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        if current_user.role != 'admin':
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

def supplier_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        if current_user.role != 'supplier' or not current_user.supplier_id:
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def score_evaluation(evaluation):
    # Each criterion is scored: YES=100%, PARTIAL=50%, NO=0%, NA excluded and normalized.
    weighted = 0.0
    total = 0.0
    by_code = {a.code: a.answer for a in evaluation.answers}
    for code, _, weight, _ in CRITERIA:
        ans = by_code.get(code, 'NA')
        if ans == 'NA':
            continue
        factor = {'YES': 1.0, 'PARTIAL': 0.5, 'NO': 0.0}.get(ans, 0.0)
        weighted += weight * factor
        total += weight
    return round((weighted / total) * 100, 2) if total else None

def risk_from_score(score):
    if score is None: return None
    if score >= 80: return 'Faible'
    if score >= 65: return 'Modéré'
    if score >= 50: return 'Élevé'
    return 'Critique'

def seed_data():
    admin_username = os.getenv('ADMIN_USERNAME', 'admin')
    admin_password = os.getenv('ADMIN_PASSWORD', 'ChangeMeNow!')
    admin = User.query.filter_by(role='admin').first()
    if not admin:
        admin = User(username=admin_username, full_name=os.getenv('ADMIN_NAME', 'Administrateur Pôle SI'), role='admin')
        admin.set_password(admin_password)
        db.session.add(admin)
    seed_path = BASE / 'suppliers_seed.csv'
    existing = Supplier.query.count()
    if existing == 0 and seed_path.exists():
        with seed_path.open(encoding='utf-8-sig', newline='') as f:
            for row in csv.DictReader(f):
                db.session.add(Supplier(numero=int(row['numero']), entreprise=row['entreprise'], contact=row['contact'], email=row['email'], agree=row['agree'], description=row['description']))
    db.session.commit()

@app.context_processor
def inject_globals():
    return {'criteria': CRITERIA}

@app.route('/health')
def health():
    return {'status': 'ok', 'app': 'Evaluation Fournisseurs AIBD'}

@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username, active=True).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Identifiants invalides ou compte désactivé.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    suppliers = Supplier.query.order_by(Supplier.numero).all()
    if current_user.role == 'supplier':
        return redirect(url_for('supplier_evaluation'))
    stats = {
        'total': len(suppliers),
        'evaluated': sum(1 for s in suppliers if s.score is not None),
        'pending': sum(1 for s in suppliers if s.evaluation and s.evaluation.status == 'Soumise'),
        'critical': sum(1 for s in suppliers if s.risk_level == 'Critique'),
    }
    return render_template('dashboard.html', suppliers=suppliers, stats=stats)

@app.route('/admin/suppliers/new', methods=['GET', 'POST'])
@admin_required
def new_supplier():
    if request.method == 'POST':
        company = request.form.get('entreprise', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not company or not username or not password:
            flash('Entreprise, identifiant et mot de passe sont obligatoires.', 'danger')
            return render_template('supplier_form.html')
        if User.query.filter_by(username=username).first():
            flash('Cet identifiant existe déjà.', 'danger')
            return render_template('supplier_form.html')
        supplier = Supplier(entreprise=company, contact=request.form.get('contact','').strip(), email=request.form.get('email','').strip(), description=request.form.get('description','').strip(), criticality=request.form.get('criticality','À classer'))
        db.session.add(supplier); db.session.flush()
        user = User(username=username, full_name=company, role='supplier', supplier_id=supplier.id)
        user.set_password(password)
        db.session.add(user); db.session.commit()
        flash('Compte fournisseur créé. Le fournisseur peut maintenant se connecter.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('supplier_form.html')

@app.route('/admin/suppliers/<int:supplier_id>')
@admin_required
def supplier_detail(supplier_id):
    supplier = db.get_or_404(Supplier, supplier_id)
    evaluation = supplier.evaluation
    score = score_evaluation(evaluation) if evaluation else None
    return render_template('supplier_detail.html', supplier=supplier, evaluation=evaluation, score=score)

@app.route('/supplier/evaluation', methods=['GET', 'POST'])
@supplier_required
def supplier_evaluation():
    supplier = current_user.supplier
    evaluation = supplier.evaluation
    if not evaluation:
        evaluation = Evaluation(supplier_id=supplier.id)
        db.session.add(evaluation); db.session.commit()
    if request.method == 'POST':
        for code, _, _, _ in CRITERIA:
            answer = request.form.get(f'answer_{code}', 'NA')
            comment = request.form.get(f'comment_{code}', '').strip()
            item = next((a for a in evaluation.answers if a.code == code), None)
            if not item:
                item = EvaluationAnswer(evaluation_id=evaluation.id, code=code)
                db.session.add(item)
            item.answer = answer
            item.comment = comment
        if request.form.get('submit') == '1':
            evaluation.status = 'Soumise'
            evaluation.submitted_at = datetime.utcnow()
            supplier.status = 'En attente de validation'
        else:
            evaluation.status = 'Brouillon'
            supplier.status = 'En cours'
        db.session.commit()
        flash('Évaluation enregistrée.' if evaluation.status == 'Brouillon' else 'Évaluation soumise à l’administrateur.', 'success')
        return redirect(url_for('supplier_evaluation'))
    answers = {a.code: a for a in evaluation.answers}
    return render_template('evaluation.html', supplier=supplier, evaluation=evaluation, answers=answers)

@app.route('/admin/suppliers/<int:supplier_id>/review', methods=['POST'])
@admin_required
def review_supplier(supplier_id):
    supplier = db.get_or_404(Supplier, supplier_id)
    evaluation = supplier.evaluation
    if not evaluation:
        flash('Aucune évaluation à valider.', 'danger')
        return redirect(url_for('supplier_detail', supplier_id=supplier.id))
    score = score_evaluation(evaluation)
    evaluation.reviewer_note = request.form.get('reviewer_note', '').strip()
    evaluation.reviewed_at = datetime.utcnow()
    decision = request.form.get('decision')
    if decision == 'approve':
        evaluation.status = 'Validée'
        supplier.score = score
        supplier.risk_level = risk_from_score(score)
        supplier.status = 'Évalué'
    elif decision == 'reject':
        evaluation.status = 'À corriger'
        supplier.status = 'À corriger'
    else:
        evaluation.status = 'Soumise'
    db.session.commit()
    flash('Revue enregistrée.', 'success')
    return redirect(url_for('supplier_detail', supplier_id=supplier.id))

@app.route('/admin/suppliers/<int:supplier_id>/upload', methods=['POST'])
@admin_required
def admin_upload(supplier_id):
    supplier = db.get_or_404(Supplier, supplier_id)
    evaluation = supplier.evaluation
    if not evaluation:
        evaluation = Evaluation(supplier_id=supplier.id)
        db.session.add(evaluation); db.session.flush()
    file = request.files.get('evidence')
    if not file or not file.filename or not allowed_file(file.filename):
        flash('Fichier non autorisé.', 'danger')
        return redirect(url_for('supplier_detail', supplier_id=supplier.id))
    original = secure_filename(file.filename)
    stored = f'{secrets.token_hex(16)}_{original}'
    file.save(UPLOAD_DIR / stored)
    db.session.add(Evidence(evaluation_id=evaluation.id, filename=original, stored_name=stored))
    db.session.commit()
    flash('Pièce justificative ajoutée.', 'success')
    return redirect(url_for('supplier_detail', supplier_id=supplier.id))

@app.route('/supplier/evidence', methods=['POST'])
@supplier_required
def supplier_evidence():
    supplier = current_user.supplier
    evaluation = supplier.evaluation
    if not evaluation:
        evaluation = Evaluation(supplier_id=supplier.id)
        db.session.add(evaluation); db.session.flush()
    file = request.files.get('evidence')
    if not file or not file.filename or not allowed_file(file.filename):
        flash('Fichier non autorisé.', 'danger')
        return redirect(url_for('supplier_evaluation'))
    original = secure_filename(file.filename)
    stored = f'{secrets.token_hex(16)}_{original}'
    file.save(UPLOAD_DIR / stored)
    db.session.add(Evidence(evaluation_id=evaluation.id, filename=original, stored_name=stored))
    db.session.commit()
    flash('Pièce justificative ajoutée.', 'success')
    return redirect(url_for('supplier_evaluation'))

@app.route('/evidence/<int:evidence_id>')
@login_required
def evidence(evidence_id):
    item = db.get_or_404(Evidence, evidence_id)
    if current_user.role == 'supplier' and item.evaluation.supplier_id != current_user.supplier_id:
        abort(403)
    return send_from_directory(app.config['UPLOAD_FOLDER'], item.stored_name, as_attachment=True, download_name=item.filename)

@app.errorhandler(403)
def forbidden(_):
    return render_template('error.html', code=403, message='Accès interdit.'), 403

@app.errorhandler(404)
def not_found(_):
    return render_template('error.html', code=404, message='Ressource introuvable.'), 404

with app.app_context():
    db.create_all()
    seed_data()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=True)
