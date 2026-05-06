import os
from datetime import datetime, date
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from sqlalchemy.orm import relationship
from sqlalchemy import Enum, func
import enum

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///task_manager.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Enums
class PriorityEnum(enum.Enum):
    Low = 'Low'
    Medium = 'Medium'
    High = 'High'

class StatusEnum(enum.Enum):
    Todo = 'To Do'
    InProgress = 'In Progress'
    Done = 'Done'

class RoleEnum(enum.Enum):
    Admin = 'Admin'
    Member = 'Member'

# Association table for User-Project with role
user_project = db.Table('user_project',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('project_id', db.Integer, db.ForeignKey('project.id'), primary_key=True),
    db.Column('role', db.Enum(RoleEnum), default=RoleEnum.Member)
)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    
    # Relationships
    projects = db.relationship('Project', secondary=user_project, back_populates='members')
    created_projects = db.relationship('Project', backref='creator', foreign_keys='Project.creator_id')
    assigned_tasks = db.relationship('Task', foreign_keys='Task.assigned_user_id', backref='assignee')
    
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def is_admin_of(self, project):
        """Check if user is admin of given project"""
        membership = db.session.query(user_project).filter(
            user_project.c.user_id == self.id,
            user_project.c.project_id == project.id
        ).first()
        return membership and membership.role == RoleEnum.Admin
    
    def is_member_of(self, project):
        """Check if user is member (any role) of project"""
        return db.session.query(user_project).filter(
            user_project.c.user_id == self.id,
            user_project.c.project_id == project.id
        ).first() is not None

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    members = db.relationship('User', secondary=user_project, back_populates='projects')
    tasks = db.relationship('Task', backref='project', cascade='all, delete-orphan')
    
    def get_user_role(self, user):
        membership = db.session.query(user_project).filter(
            user_project.c.user_id == user.id,
            user_project.c.project_id == self.id
        ).first()
        return membership.role if membership else None

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    due_date = db.Column(db.Date, nullable=False)
    priority = db.Column(Enum(PriorityEnum), default=PriorityEnum.Medium)
    status = db.Column(Enum(StatusEnum), default=StatusEnum.Todo)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Foreign keys
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    assigned_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    def is_overdue(self):
        if self.status == StatusEnum.Done:
            return False
        return self.due_date and self.due_date < date.today()
    
    def get_priority_value(self):
        order = {'Low': 1, 'Medium': 2, 'High': 3}
        return order.get(self.priority.value, 2)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper decorators
def project_member_required(f):
    @wraps(f)
    def decorated_function(project_id, *args, **kwargs):
        project = Project.query.get_or_404(project_id)
        if not current_user.is_member_of(project):
            flash('You are not a member of this project.', 'danger')
            return redirect(url_for('dashboard'))
        return f(project_id, *args, **kwargs)
    return decorated_function

def project_admin_required(f):
    @wraps(f)
    def decorated_function(project_id, *args, **kwargs):
        project = Project.query.get_or_404(project_id)
        if not current_user.is_admin_of(project):
            flash('Admin access required for this action.', 'danger')
            return redirect(url_for('project_detail', project_id=project_id))
        return f(project_id, *args, **kwargs)
    return decorated_function

def task_access_required(f):
    @wraps(f)
    def decorated_function(task_id, *args, **kwargs):
        task = Task.query.get_or_404(task_id)
        project = task.project
        if not current_user.is_member_of(project):
            flash('Access denied.', 'danger')
            return redirect(url_for('dashboard'))
        # Member can only access their own tasks for editing
        if not current_user.is_admin_of(project) and task.assigned_user_id != current_user.id:
            flash('You can only access tasks assigned to you.', 'danger')
            return redirect(url_for('project_detail', project_id=project.id))
        return f(task_id, *args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([name, email, password]):
            flash('All fields are required.', 'danger')
        elif password != confirm_password:
            flash('Passwords do not match.', 'danger')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
        else:
            user = User(name=name, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash(f'Welcome back, {user.name}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get all projects where user is member
    user_projects = current_user.projects
    
    # All tasks from those projects that user has access to
    accessible_tasks = []
    tasks_by_status = {status.value: 0 for status in StatusEnum}
    overdue_tasks = []
    total_tasks = 0
    
    for project in user_projects:
        if current_user.is_admin_of(project):
            project_tasks = project.tasks
        else:
            # Member: only see assigned tasks
            project_tasks = [t for t in project.tasks if t.assigned_user_id == current_user.id]
        
        for task in project_tasks:
            accessible_tasks.append(task)
            tasks_by_status[task.status.value] += 1
            total_tasks += 1
            if task.is_overdue():
                overdue_tasks.append(task)
    
    # Tasks per user (only for projects where user is admin)
    tasks_per_user = {}
    if any(current_user.is_admin_of(p) for p in user_projects):
        for project in user_projects:
            if current_user.is_admin_of(project):
                for member in project.members:
                    member_tasks = [t for t in project.tasks if t.assigned_user_id == member.id]
                    if member.name not in tasks_per_user:
                        tasks_per_user[member.name] = 0
                    tasks_per_user[member.name] += len(member_tasks)
    
    # User's own tasks (for quick view)
    my_tasks = [t for t in accessible_tasks if t.assigned_user_id == current_user.id]
    
    return render_template('dashboard.html', 
                         projects=user_projects,
                         total_tasks=total_tasks,
                         tasks_by_status=tasks_by_status,
                         overdue_tasks=overdue_tasks,
                         tasks_per_user=tasks_per_user,
                         my_tasks=my_tasks[:10])  # limit to 10

@app.route('/project/create', methods=['GET', 'POST'])
@login_required
def create_project():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        
        if not name:
            flash('Project name is required.', 'danger')
        else:
            project = Project(name=name, description=description, creator_id=current_user.id)
            db.session.add(project)
            db.session.commit()
            
            # Add creator as admin
            stmt = user_project.insert().values(
                user_id=current_user.id,
                project_id=project.id,
                role=RoleEnum.Admin
            )
            db.session.execute(stmt)
            db.session.commit()
            
            flash(f'Project "{name}" created successfully!', 'success')
            return redirect(url_for('project_detail', project_id=project.id))
    
    return render_template('create_project.html')

@app.route('/project/<int:project_id>')
@login_required
@project_member_required
def project_detail(project_id):
    project = Project.query.get_or_404(project_id)
    is_admin = current_user.is_admin_of(project)
    
    if is_admin:
        tasks = project.tasks
    else:
        tasks = [t for t in project.tasks if t.assigned_user_id == current_user.id]
    
    # Sort tasks
    tasks.sort(key=lambda t: (t.status != StatusEnum.Todo, t.get_priority_value()), reverse=True)
    
    members = project.members
    return render_template('project_detail.html', 
                         project=project, 
                         tasks=tasks, 
                         is_admin=is_admin,
                         members=members,
                         StatusEnum=StatusEnum)

@app.route('/project/<int:project_id>/members', methods=['GET', 'POST'])
@login_required
@project_admin_required
def manage_members(project_id):
    project = Project.query.get_or_404(project_id)
    
    if request.method == 'POST':
        action = request.form.get('action')
        email = request.form.get('email')
        
        if action == 'add' and email:
            user = User.query.filter_by(email=email).first()
            if not user:
                flash(f'User with email {email} not found.', 'danger')
            elif user in project.members:
                flash(f'{user.name} is already a member.', 'warning')
            else:
                stmt = user_project.insert().values(
                    user_id=user.id,
                    project_id=project.id,
                    role=RoleEnum.Member
                )
                db.session.execute(stmt)
                db.session.commit()
                flash(f'{user.name} added as member.', 'success')
        
        elif action == 'remove' and request.form.get('user_id'):
            user_id = int(request.form.get('user_id'))
            user = User.query.get(user_id)
            if user == project.creator:
                flash('Cannot remove the project creator.', 'danger')
            else:
                stmt = user_project.delete().where(
                    user_project.c.user_id == user_id,
                    user_project.c.project_id == project_id
                )
                db.session.execute(stmt)
                db.session.commit()
                flash(f'{user.name} removed from project.', 'success')
        
        return redirect(url_for('manage_members', project_id=project_id))
    
    members = project.members
    return render_template('manage_members.html', project=project, members=members)

@app.route('/project/<int:project_id>/task/create', methods=['GET', 'POST'])
@login_required
@project_admin_required
def create_task(project_id):
    project = Project.query.get_or_404(project_id)
    members = project.members
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        due_date_str = request.form.get('due_date')
        priority = request.form.get('priority')
        assigned_user_id = request.form.get('assigned_user_id')
        status = request.form.get('status')
        
        if not title or not due_date_str:
            flash('Title and due date are required.', 'danger')
        else:
            try:
                due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
                task = Task(
                    title=title,
                    description=description,
                    due_date=due_date,
                    priority=PriorityEnum(priority),
                    status=StatusEnum(status),
                    project_id=project_id,
                    assigned_user_id=int(assigned_user_id) if assigned_user_id else None
                )
                db.session.add(task)
                db.session.commit()
                flash('Task created successfully!', 'success')
                return redirect(url_for('project_detail', project_id=project_id))
            except Exception as e:
                flash(f'Error creating task: {str(e)}', 'danger')
    
    return render_template('create_task.html', project=project, members=members, 
                         PriorityEnum=PriorityEnum, StatusEnum=StatusEnum)

@app.route('/task/<int:task_id>/edit', methods=['GET', 'POST'])
@login_required
@task_access_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    project = task.project
    is_admin = current_user.is_admin_of(project)
    
    if not is_admin and task.assigned_user_id != current_user.id:
        abort(403)
    
    if request.method == 'POST':
        if is_admin:
            # Admin can edit all fields
            task.title = request.form.get('title')
            task.description = request.form.get('description')
            due_date_str = request.form.get('due_date')
            if due_date_str:
                task.due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
            task.priority = PriorityEnum(request.form.get('priority'))
            task.status = StatusEnum(request.form.get('status'))
            task.assigned_user_id = int(request.form.get('assigned_user_id')) if request.form.get('assigned_user_id') else None
        else:
            # Member can only update status
            task.status = StatusEnum(request.form.get('status'))
        
        db.session.commit()
        flash('Task updated successfully!', 'success')
        return redirect(url_for('project_detail', project_id=project.id))
    
    members = project.members
    return render_template('edit_task.html', task=task, project=project, 
                         is_admin=is_admin, members=members,
                         PriorityEnum=PriorityEnum, StatusEnum=StatusEnum)

@app.route('/task/<int:task_id>/delete')
@login_required
@project_admin_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    project_id = task.project_id
    db.session.delete(task)
    db.session.commit()
    flash('Task deleted successfully.', 'success')
    return redirect(url_for('project_detail', project_id=project_id))

# Create tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)