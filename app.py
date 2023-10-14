# from crypt import methods
# pip  install --user scikit-learn==0.24.2 (imp)
import pickle
import sqlite3
import numpy as np
import pandas as pd
from flask import Flask, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from sqlalchemy import create_engine
# from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool
from sqlalchemy import Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from flask import jsonify

app = Flask(__name__)

app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://mqp3lc1kh80w8wggb75d:pscale_pw_KnfaLwIurrxvdzuoKSmaYsAP5m1J3IQInYv9gDVWYjB@aws.connect.psdb.cloud/database_ver_1?charset=utf8mb4'

app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'poolclass': NullPool,
    'connect_args': {
        'ssl': {
            'ssl_ca': 'path/to/ca.pem',
            'ssl_cert': 'path/to/client-cert.pem',
            'ssl_key': 'path/to/client-key.pem'
        }
    }
}


engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'], **app.config['SQLALCHEMY_ENGINE_OPTIONS'])

bootstrap = Bootstrap(app)


db = SQLAlchemy()
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    __tablename__ = 'User'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
# Base = declarative_base()


class HouseData(db.Model):
    __tablename__ = 'house_data'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    area_type = db.Column(db.String(400), nullable=False)
    availability = db.Column(db.String(400), nullable=False)
    location = db.Column(db.String(400), nullable=False)
    bhk = db.Column(db.Integer, nullable=False)
    bath = db.Column(db.Integer, nullable=False)
    Total_sqft = db.Column(db.Integer, nullable=False)

    def __init__(self, area_type, availability, location, bhk, bath, Total_sqft):
        self.area_type = area_type
        self.availability = availability
        self.location = location
        self.bhk = bhk
        self.bath = bath
        self.Total_sqft = Total_sqft


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


@app.route('/')
def indexx():
    return render_template('indexlog.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'
        # return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        # return '<h1>New user has been created!</h1>'
        return render_template('indexlog.html')
        # return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

def getusers(offset):
    try:
        # Fetch 50 rows starting from the given offset
        data = HouseData.query.offset(offset).limit(100).all()
        return data
    except Exception as e:
        print("Error querying the database:", e)
        return []

@app.route('/get_more_data', methods=['GET'])
def get_more_data():
    offset = int(request.args.get('offset', 0))  # Get the offset from the URL
    # Retrieve the next 50 rows of data, starting from the given offset
    data = getusers(offset)  # You should implement this function

    # Convert the data to a format that can be sent as JSON
    data_json = [{'area_type': row.area_type, 'availability': row.availability, 'location': row.location, 'bhk': row.bhk, 'bath': row.bath, 'Total_sqft': row.Total_sqft} for row in data]

    return jsonify(data_json)



@app.route('/dashboard')
@login_required
def dashboard():
    offset = request.args.get('offset', default=0, type=int)  # Get the offset from the URL
    userss = getusers(offset)
    return render_template('dashboard.html', name=current_user.username, usr=userss, offset=offset)


data = pd.read_csv('Cleaned_data_ver_6.csv')
pipe = pickle.load(open("RidgeModel_ver_6.pkl", 'rb'))


@app.route('/indexr', methods=['GET', 'POST'])
def index():
    area_types = sorted(data['area_type'].unique())
    availabilitys = sorted(data['availability'].unique())
    locations = sorted(data['location'].unique())
    return render_template('index.html', area_types=area_types, availabilitys=availabilitys, locations=locations)


@app.route('/predict', methods=['GET', 'POST'])
def predict():
    try:
        area_type = request.form.get('area_type')
        availability = request.form.get('availability')
        location = request.form.get('location')
        bhk = request.form.get('bhk')
        bhk = float(bhk)
        bath = request.form.get('bath')
        bath = float(bath)
        sqft = request.form.get('Total_sqft')
        print(area_type, location, availability, bhk, bath, sqft)
        input = pd.DataFrame([[area_type, availability, location, sqft, bath, bhk]],
                             columns=['area_type', 'availability', 'location', 'total_sqft', 'bath', 'bhk'])
        prediction = pipe.predict(input)[0] * 1e5
        return str(np.round(prediction, 2))
    except ValueError:
        return "Please Enter The Values"



@app.route('/indexr', methods=['GET', 'POST'])
@login_required
def indexr():
    # index()
    # predict()
    return render_template('index.html')


@app.route('/reports')
@login_required
def reports():
    return render_template('report.html')


@app.route('/feature')
@login_required
def feature():
    return render_template('jupyter_SE_project_ver_1.html')


@app.route('/analysis')
@login_required
def analysis():
    return render_template('analysis.html')

@app.route('/aboutus')
@login_required
def aboutus():
    return render_template('aboutus.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return render_template('indexlog.html')


if __name__ == '__main__':
    app.run(debug=True, port=5001)
