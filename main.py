import requests
from flask import Flask, Blueprint, render_template, redirect, url_for, request, flash
from flask_login import UserMixin, LoginManager, login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import random


 
db = SQLAlchemy()
app = Flask(__name__)
app.app_context().push()
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///final.db"
app.config["SECRET_KEY"] = 'jackedninjamonkeys'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    username = db.Column(db.String(100))
    adminstatus = db.Column(db.Boolean)

class Suggestions(db.Model):
    id = db.Column(db.Integer, primary_key= True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    name = db.Column(db.String)
    content = db.Column(db.Text)
    image = db.Column(db.String)

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = bool(request.form.get('remember'))
    user = User.query.filter_by(email=email).first()
    if user:
        if check_password_hash(user.password, password):
            login_user(user, remember=remember)
            return redirect('/profile')
        else:
            flash('Wrong email or password')
            return render_template('login.html')
    else:
        flash('User does not exist')

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    username = request.form.get('name')
    password = request.form.get('password')
    confpass = request.form.get('confpass')

    user = User.query.filter_by(email=email).first()

    if not user:
        if password == confpass:
            new_user = User(email=email, username=username, password=generate_password_hash(password, method='sha256'),
                            adminstatus=False)
            db.session.add(new_user)
            db.session.commit()
        else:
            flash('Wrong confirmation password')
            return redirect(url_for('signup'))
    else:
        flash('Email already exists')
        return redirect(url_for('signup'))
    return redirect(url_for('login'))

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/profile')
@login_required
def profile():
    url = 'https://swapi.dev/api/people/'
    dice = random.randint(1, 83)
    r = requests.get(url + str(dice))
    cname = r.json()['name']
    cheigh = r.json()['height']
    chair = r.json()['hair_color']
    cgen = r.json()['gender']

    return render_template('profile.html', name=current_user.username, cname=cname, cheigh=cheigh,  chair=chair,cgen=cgen)

@app.route('/add')
@login_required
def add():
    return render_template('add.html')

@app.route('/add', methods=['POST'])
@login_required
def add_post():
    user_id = current_user.id
    name = request.form.get('name')
    content = request.form.get('content')
    imageurl = request.form.get('imageurl')
    new_suggestions = Suggestions(user_id=user_id, name=name, content=content, image=imageurl)
    db.session.add(new_suggestions)
    db.session.commit()
    return redirect(url_for('posts'))

@app.route('/posts', methods=['GET', 'POST'])
def posts():
    suggestions = Suggestions.query.all()
    return render_template('posts.html', suggestions=suggestions)

@app.route('/delete', methods=['GET', 'POST'])
def delete():
    post_id = request.form.get('post_id')
    print(post_id)
    db.session.delete(Suggestions.query.filter_by(id=post_id).first())
    db.session.commit()
    return redirect(url_for('posts'))

@app.route('/edit', methods=['GET', 'POST'])
def edit():
    post_id = request.form.get('post_id')
    print(post_id)
    prev = Suggestions.query.filter_by(id=post_id).first()
    if request.method == 'POST':
        name = request.form.get('name')
        content = request.form.get('content')
        image = request.form.get('imageurl')
        post_id = request.form.get('post_id')
        new = Suggestions.query.filter_by(id=1).first()
        new.name = name
        new.content = content
        new.image = image
        db.session.commit()
        return redirect(url_for('posts'))
    return render_template('edit.html', post_id=post_id, name=prev.name, content=prev.content, image=image)

if __name__ =='__main__':
    app.run(debug=True)