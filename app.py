from flask import Flask, jsonify, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_wtf.csrf import generate_csrf, CSRFProtect


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
app.secret_key = b'_53oi3uriq9pifpff;apl'
csrf = CSRFProtect(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)


class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    rented = db.Column(db.Boolean, default=False)
    rented_at = db.Column(db.DateTime)
    rented_by = db.Column(db.String(50))

@app.route('/')
def index():
    if 'user_id' in session:
        
        user_id = session['user_id']
        
        users = User.query.all()
        books = Book.query.all()
        
       
        return render_template('index.html', users=users, books=books, user_id=user_id)
    else:
        return redirect(url_for('login'))
    
@app.route('/search_users')
def search_users():
    query = request.args.get('q', '').strip().lower()

    if query:
        users = User.query.filter(User.username.ilike(f'{query}%')).all()
        user_data = [{'id': user.id, 'username': user.username} for user in users]
        return jsonify(user_data)
    else:
        return jsonify([])

@app.route('/create_user', methods=['GET', 'POST'])
def create_user():
    if 'user_id' in session and session.get('role') == 'admin':
        users = User.query.all()
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            role = request.form['role']
            new_user = User(username=username, password=password, role=role)
            db.session.add(new_user)
            db.session.commit()
            flash('User added successfully.', 'success')
            return redirect(url_for('create_user'))
        return render_template('create_user.html', users=users)
    else:
        return redirect(url_for('login'))

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user_id' in session and session.get('role') == 'admin':
        user = User.query.get_or_404(user_id)
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
def delete_user(user_id):
    if 'user_id' in session and session.get('role') == 'admin':
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully.', 'success')
        session.clear()
        if not User.query.filter(User.username != 'admin').first():
            
            admin_user = User(username='admin', password='admin', role='admin')
            db.session.add(admin_user)
            db.session.commit()
            flash('Admin user created.', 'success')
        return redirect(url_for('create_user'))
    else:
        return redirect(url_for('login'))
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user:
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


@app.route('/logout')
def logout():
    session.clear()
    session.pop('user_id', None)
    return redirect(url_for('login'))


@app.route('/add_book', methods=['GET', 'POST'])
def add_book():
    if 'user_id' in session:
        if request.method == 'POST':
            title = request.form['title']
            author = request.form['author']
            new_book = Book(title=title, author=author)
            db.session.add(new_book)
            db.session.commit()
            flash('Book added successfully.', 'success')
            return redirect(url_for('index'))
        return render_template('add_book.html')
    else:
        return redirect(url_for('login'))

@app.route('/edit_book/<int:book_id>', methods=['GET', 'POST'])
def edit_book(book_id):
    if 'user_id' in session and session.get('role') == 'admin':
        book = Book.query.get_or_404(book_id)
        if request.method == 'POST':
            if 'title' in request.form and 'author' in request.form:
                new_title = request.form['title']
                new_author = request.form['author']
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
def delete_book(book_id):
    if 'user_id' in session:
        book = Book.query.get_or_404(book_id)
        db.session.delete(book)
        db.session.commit()
        flash('Book deleted successfully.', 'success')
        return redirect(url_for('index'))
    else:
        return redirect(url_for('login'))


@app.route('/assign_book/<int:book_id>', methods=['POST'])
def assign_book(book_id):
    if 'user_id' in session and session.get('role') == 'admin': 
        user_id = request.form.get('selected_user_id')
        book = Book.query.get_or_404(book_id) 
        if not book.rented:
            user = User.query.get_or_404(user_id)
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
def return_book(book_id):
    if 'user_id' in session and session.get('role') == 'admin': 
        book = Book.query.get_or_404(book_id) 
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

with app.app_context():
    db.create_all()

    if not User.query.filter_by(role='admin').first():
        admin_username = 'admin'
        admin_password = 'admin'  
        admin_role = 'admin'
        admin_user = User(username=admin_username, password=admin_password, role=admin_role)
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created.")
    app.run(debug=True)

if __name__ == '__main__':
    app.run(debug=True)