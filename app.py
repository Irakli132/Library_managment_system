import os
from flask import Flask, jsonify, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_wtf.csrf import generate_csrf, CSRFProtect
from flask_bcrypt import Bcrypt
from functools import wraps
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')


db = SQLAlchemy(app)
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)

    def serialize(self):
        return {"id": self.id, "username": self.username, "role": self.role}

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_image(file):
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return filename
    return None

class Books(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    image = db.Column(db.String(100), nullable=True)
    rented = db.Column(db.Boolean, default=False)
    rented_at = db.Column(db.DateTime)
    rented_by = db.Column(db.String(50))

    def serialize(self):
        return {"id": self.id, "username": self.title, "role": self.author}

def not_user_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        username = session.get("username")

        user = Users.query.filter_by(username=username).first()
        if not user or (user.role != "admin" and user.role != "librarian"):
            return {"error": "unautorized access"}, 401
        return f(*args, **kwargs)

    return decorated_function


def is_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        username = session.get("username")

        user = Users.query.filter_by(username=username).first()

        if not user or user.role != "admin":
            return {"error": "only admins can register users"}, 401

        return f(*args, **kwargs)

    return decorated_function

def is_librarian(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        username = session.get("username")

        user = Users.query.filter_by(username=username).first()

        if not user or user.role != "librarian":
            return {"error": "only admins can register users"}, 401

        return f(*args, **kwargs)

    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = Users.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username  
            session['role'] = user.role
            flash('Login successful.', 'success')
            print("Username in session:", session['username'])  
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password. Please try again.', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/')
def index():
    if 'user_id' in session:
        
        user_id = session['user_id']
        
        admin_count = Users.query.filter_by(role='admin').count()
        
        # If there are no admin users, create one
        if admin_count == 0:
            admin_username = 'admin'
            admin_password = 'admin'  
            admin_role = 'admin'
            admin_user = Users(username=admin_username, role=admin_role)
            admin_user.set_password(admin_password)
            db.session.add(admin_user)
            db.session.commit()
            flash("No admin user found. New admin user created.", "success")

        users = Users.query.all()
        books = Books.query.all()
        
        return render_template('index.html', users=users, books=books, user_id=user_id)
    else:
        return redirect(url_for('login'))
    
@app.route('/search_users')
def search_users():
    query = request.args.get('q', '').strip().lower()

    if query:
        users = Users.query.filter(Users.username.ilike(f'{query}%')).all()
        user_data = [{'id': user.id, 'username': user.username} for user in users]
        return jsonify(user_data)
    else:
        return jsonify([])

@app.route('/create_user', methods=['GET', 'POST'])
@not_user_auth
def create_user():
    if 'user_id' in session:
        users = Users.query.all()
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            role = request.form['role']
            new_user = Users(username=username, role=role)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('User added successfully.', 'success')
            return redirect(url_for('create_user'))
        return render_template('create_user.html', users=users)
    else:
        return redirect(url_for('login'))

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@not_user_auth
def edit_user(user_id):
    if 'user_id' in session:
        user = Users.query.get_or_404(user_id)
        if request.method == 'POST':
            new_username = request.form['username']  
            new_password = request.form['password']  
            user.username = new_username  
            user.password = new_password 
            db.session.commit()  
            flash('User updated successfully.', 'success')
            return redirect(url_for('create_user'))
        return render_template('edit_user.html', user=user)
    else:
        return redirect(url_for('login'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@not_user_auth
def delete_user(user_id):
    if 'user_id' in session:
        user = Users.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully.', 'success')
        session.clear()
        return redirect(url_for('create_user'))
    else:
        return redirect(url_for('login'))
    
@app.route('/delete_admin_or_librarian/<int:user_id>', methods=['POST'])
@is_admin
def delete_admin_or_librarian(user_id):
    user = Users.query.get_or_404(user_id)
    if user.role in ["admin", "librarian"]:
        db.session.delete(user)
        db.session.commit()
        flash('Admin or librarian deleted successfully.', 'success')
    else:
        flash('Only admins can delete other admins and librarians.', 'danger')
    return redirect(url_for('create_user'))

#BOOKS
@app.route('/add_book', methods=['GET', 'POST'])
@is_librarian
def add_book():
    if 'user_id' in session:
        if request.method == 'POST':
            if 'title' in request.form and 'author' in request.form:
                title = request.form['title']
                author = request.form['author']

                if 'image' in request.files:
                    image_file = request.files['image']
                    if image_file and allowed_file(image_file.filename):
                        image_path = save_image(image_file)
                        if image_path:
                            new_book = Books(title=title, author=author, image=image_path)
                        else:
                            new_book = Books(title=title, author=author)
                    else:
                        new_book = Books(title=title, author=author)
                else:
                    new_book = Books(title=title, author=author)

                db.session.add(new_book)
                db.session.commit()
                flash('Book added successfully.', 'success')
                return redirect(url_for('index'))
            else:
                flash('Title or author not provided.', 'danger')
        return render_template('add_book.html')
    else:
        return redirect(url_for('login'))

@app.route('/edit_book/<int:book_id>', methods=['GET', 'POST'])
@is_librarian
def edit_book(book_id):
    if 'user_id' in session:
        book = Books.query.get_or_404(book_id)
        if request.method == 'POST':
            if 'title' in request.form and 'author' in request.form:
                new_title = request.form['title']
                new_author = request.form['author']

                if 'image' in request.files:
                    image_file = request.files['image']
                    if image_file and allowed_file(image_file.filename):
                        image_path = save_image(image_file)
                        if image_path:
                            book.image = image_path

                book.title = new_title
                book.author = new_author
                db.session.commit()
                flash('Book updated successfully.', 'success')
                return redirect(url_for('index'))
            else:
                flash('Title or author not provided.', 'danger')
        return render_template('edit_book.html', book=book)
    else:
        return redirect(url_for('login'))

@app.route('/delete_book/<int:book_id>', methods=['POST'])
@is_librarian
def delete_book(book_id):
    if 'user_id' in session:
        book = Books.query.get_or_404(book_id)
        db.session.delete(book)
        db.session.commit()
        flash('Book deleted successfully.', 'success')
        return redirect(url_for('index'))
    else:
        return redirect(url_for('login'))

@app.route('/assign_book/<int:book_id>', methods=['POST'])
@is_librarian
def assign_book(book_id):
    if 'user_id' in session and session.get('role') == 'librarian': 
        user_id = request.form.get('selected_user_id')
        book = Books.query.get_or_404(book_id) 
        if not book.rented:
            user = Users.query.get_or_404(user_id)
            book.rented = True
            book.rented_by = user.username
            book.rented_at = datetime.now()
            db.session.commit()
            flash(f'Book assigned to {user.username} successfully.', 'success')
        else:
            flash('Book is already assigned.', 'warning')  
    else:
        flash('You are not authorized to perform this action.', 'danger')
    return redirect(url_for('index')) 

@app.route('/return_book/<int:book_id>', methods=['POST'])
@is_librarian
def return_book(book_id):
    if 'user_id' in session and session.get('role') == 'librarian': 
        book = Books.query.get_or_404(book_id) 
        if book.rented:
            book.rented = False
            book.rented_by = None
            book.rented_at = None
            db.session.commit()
            flash(f'Book returned successfully.', 'success')
        else:
            flash('Book is already available.', 'warning')  
    else:
        flash('You are not authorized to perform this action.', 'danger')
    return redirect(url_for('index')) 

@app.route('/show_info/<int:book_id>', methods=['GET'])
def show_info(book_id):
    book = Books.query.get(book_id)
    if not book:
        return {"error" : "book not found"}, 404

    rented_by = None
    rented_at = None
    if book.rented:
        user_id = book.rented_by  
        rented_by = user_id
        rented_at = book.rented_at.strftime('%Y-%m-%d %H:%M:%S')

    return render_template('show_book.html', book=book, rented_by=rented_by, rented_at=rented_at)


@app.route('/logout')
def logout():
    session.clear()
    session.pop('user_id', None)
    return redirect(url_for('login'))

with app.app_context():
    db.create_all()

    if not Users.query.filter_by(role='admin').first():
        admin_username = 'admin'
        admin_password = 'admin'  
        admin_role = 'admin'
        admin_user = Users(username=admin_username, role=admin_role)
        admin_user.set_password(admin_password)
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created.")
    app.run(debug=True)

if __name__ == '__main__':
    app.run(debug=True)