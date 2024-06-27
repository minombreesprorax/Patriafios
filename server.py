from flask import Flask, render_template, redirect, send_file, url_for, request, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_bcrypt import Bcrypt
from datetime import date
import pandas as pd
import threading
import time
import io

app = Flask(__name__)
app.secret_key = 'P4p4Fr17uR@'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class LastRun(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)                            # The user Identifier.
    displayname = db.Column(db.String(20), unique=False, nullable=False)    # The name displayed (only admin assignable).
    username = db.Column(db.String(20), unique=True, nullable=False)        # The real name, used to log in, can't be changed by admins.
    email = db.Column(db.String(40), unique=True, nullable=False)           # The email to log in, it's sole purpose is to evict multiple accounts.
    password = db.Column(db.String(60), nullable=False)                     # The password, not too much to explain about this one.
    isadmin = db.Column(db.Boolean, nullable=False, default=False)          # If the user has admin priviliges.
    points = db.Column(db.Integer, nullable=False, default=0)               # The ammount of points this user has.
    lastanswer = db.Column(db.String(200), nullable=True)                   # The answer to the long question (first one).
    lastsecondanswer = db.Column(db.Boolean, nullable=True)                 # The answer to the multiple choice question (last one).
    answered = db.Column(db.Boolean, nullable=False, default=False)         # If this user has already answered.
    givenfirstquestion = db.Column(db.String(200), nullable=True)           # The long question that was given to the user.
    givensecondquestion = db.Column(db.String(200), nullable=True)          # The multiple choice question that was given to the user.
    isbanned = db.Column(db.Boolean, nullable=False, default=False)         # If the user is banned and can't log in.

def check_and_update_date():
    last_run = LastRun.query.first()
    today = date.today()

    print(" * HourCheck running!")
    if last_run:
        print(f" * {last_run.date} < {today}")
    else:
        print("Warning! DB doesn't contain lastrun info, making...")

    if not last_run:
        last_run = LastRun(date=today)
        db.session.add(last_run)
        db.session.commit()
    elif last_run.date < today:
        User.query.update(
            {
            User.answered: False,
            User.lastanswer: None,
            User.lastsecondanswer: None,
            User.givenfirstquestion: None,
            User.givensecondquestion: None
            })
        last_run.date = today
        print("The day has changed! all data regarding questions reset.")
        db.session.commit()
    
    if last_run.date > today:
        last_run.date = today
        print("Warning. It has been detected the last run is higher than today, is the internal clock wrong?")
        db.session.commit()
    
def date_check_background():
    while True:
        time.sleep(900)  # Check every 15 minutes
        with app.app_context():
            check_and_update_date()

@app.route('/')
def main_page():
    return redirect(url_for('intro'))

@app.route('/info')
def info():
    return render_template('25demayo.html')

@app.route('/intro')
def intro():
    return render_template('intro.html')

@app.route('/home')
def home():
    username = session.get('username')
    return render_template('home.html', username=username)

@app.route('/authors')
def authors():
    return render_template('authors.html')

@app.route('/login-register', methods=['GET', 'POST'])
def login_register():
    login_message = None
    register_message = None
    
    if request.method == 'POST':
        if 'login_register' in request.form:
            username = request.form['username']
            password = request.form['password']
            user = User.query.filter_by(username=username).first()
            print("registering")
            print(username)
            print(password)
            if user and bcrypt.check_password_hash(user.password, password):
                if user.isbanned:
                    return redirect(url_for('banned'))
                else:
                    session['username'] = username
                    login_message = {'text': 'Login successful!', 'category': 'success'}
                    print(f"{username} logged in!")
                    return redirect(url_for('account'))
            else:
                error_message = 'Nombre de usuario o contraseña incorrecta.'
                print("Not succesful.")
                return render_template("login_register.html", error_message=error_message)
        # Existing code...
        elif 'register' in request.form:
            username = request.form['new_username']
            email = request.form['new_email']
            password = request.form['new_password']
            # Set default displayname for regular users
            displayname = username
            # Check if username already exists
            existing_user = User.query.filter_by(username=username).first()
            existing_email = User.query.filter_by(email=email).first()
            if existing_user:
                error_message = 'Nombre de usuario en uso, intente con otro.'
                print("username already in use.")
                return render_template("login_register.html", error_message=error_message)
            if existing_email:
                error_message = 'Este email ya fue registrado.'
                print("email already in use.")
                return render_template("login_register.html", error_message=error_message)
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            if username == "Alec Nielsen" or username == "Francisco Fernandez" or username == "Thiago Hernandez":
                # Set isadmin to True for the admin user
                user = User(username=username, email=email, password=hashed_password, isadmin=True, displayname=displayname)
            else:
                user = User(username=username, email=email, password=hashed_password, displayname=displayname)
            db.session.add(user)
            db.session.commit()
            session['username'] = username
            register_message = {'text': 'Registration successful!', 'category': 'success'}
            print("register succesful!")
            return redirect(url_for('account'))

    # Render the template and pass messages as template variables
    return render_template('login_register.html', login_message=login_message, register_message=register_message)


@app.route('/account', methods=['GET', 'POST'])
def account():
    if 'username' in session:
        username = session['username']
        user = User.query.filter_by(username=username).first()
        if user:
            if user.isbanned:
                return redirect(url_for('banned'))
            else:
                if user.answered:
                    return render_template('account.html', username=username, dsn=user.displayname, pnt=user.points, isadmin=user.isadmin, error_message=f"Ya has respondido el patriafío de hoy! {"Ademas, respondiste bien la respuesta de multiple opción, ya que ganas 3 puntos!" if user.lastsecondanswer else "Lamentablemente, respondsite mal la multiple opción así que no ganas ningun punto."}")
                else:
                    return render_template('account.html', username=username, dsn=user.displayname, pnt=user.points, isadmin=user.isadmin)
        else:
            return redirect(url_for('login_register'))
    else:
        return redirect(url_for('login_register'))

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    print(f"{session.get('username')} logged out!")
    session.pop('username', None)
    return redirect(url_for('home'))

@app.route('/adminpanel', methods=['GET', 'POST'])
def adminpanel():
    if 'username' in session:
        username = session['username']
        user = User.query.filter_by(username=username).first()
        if user:
            if user.isadmin and not user.isbanned:
                # Fetch all users from the database
                users = User.query.all()
                return render_template('adminpanel.html', users=users)
            else:
                return render_template('404.html'), 404
        else:
            return render_template('404.html'), 404
    else:
        return render_template('404.html'), 404

@app.route('/update_user/<int:user_id>', methods=['POST'])
def update_user(user_id):
    data = request.json
    field = data.get('field')
    new_data = data.get('new_data')

    # Query the user from the database
    user = User.query.get(user_id)

    if user:
        # Update user data based on the field received
        if field == 'username':
            user.username = new_data
        elif field == 'displayname':
            user.displayname = new_data
        elif field == 'email':
            user.email = new_data
        elif field == 'password':
            # Handle password change separately
            hashed_password = bcrypt.generate_password_hash(new_data).decode('utf-8')
            user.password = hashed_password
        elif field == 'isadmin':
            # Convert new_data to boolean before assigning
            user.isadmin = True if new_data.lower() == 'si' or new_data.lower() == 's' else False
        elif field == 'points':
            # Convert new_data to integer before assigning
            user.points = int(new_data)
        elif field == 'pointsadditive':
            # Convert new_data to integer before assigning
            user.points = int(new_data) + user.points
        elif field == 'answered':
            # Convert new_data to boolean before assigning
            user.answered = True if new_data.lower() == 'si' or new_data.lower() == 's' else False
        elif field == 'isbanned':
            user.isbanned = True if new_data.lower() == 'si' or new_data.lower() == 's' else False

        db.session.commit()
        return jsonify({'message': 'Datos actualizados!'})
    else:
        return jsonify({'error': 'Usuario no existente'}), 404

@app.route('/adminuserchecker/<int:user_id>', methods=['GET', 'POST'])
def adminuserchecker(user_id):
    if 'username' in session:
        username = session['username']
        user = User.query.filter_by(username=username).first()
        if user:
            if user.isadmin and not user.isbanned:
                # Fetch all users from the database
                usercheck = User.query.get(user_id)
                return render_template('adminuserchecker.html', user=usercheck)
            else:
                return render_template('404.html'), 404
        else:
            return render_template('404.html'), 404
    else:
        return render_template('404.html'), 404

@app.route('/challenge')
def challenge():
    if 'username' in session:
        username = session['username']
        user = User.query.filter_by(username=username).first()
        if user.isbanned:
            return redirect(url_for('banned'))
        elif user.answered:
            return redirect(url_for('account'))
        else:
            if user:
                return render_template('patriafio.html', username=username, dsn=user.displayname)
            else:
                flash('User not found.', 'error')
                return redirect(url_for('login_register'))
    else:
        flash('You are not logged in. Please log in to access your account.', 'error')
        return redirect(url_for('login_register'))

@app.route('/senddata', methods=['POST'])
def send_data():
    if 'username' in session:
        username = session['username']
        user = User.query.filter_by(username=username).first()
        if user:
            data = request.json
            answer = data.get('answer')
            q1 = data.get('q1')
            q2 = data.get('q2')
            right = data.get('right')
            
            # Update user's answers and given questions
            user.lastanswer = answer
            user.lastsecondanswer = right
            user.answered = True
            user.givenfirstquestion = q1
            user.givensecondquestion = q2

            if right == True:
                user.points += 3
            
            # Commit changes to the database
            db.session.commit()
            
            return jsonify({'message': 'Se ha enviado tu respuesta.'})
        else:
            return jsonify({'error': 'Usuario no existente.'}), 404
    else:
        return jsonify({'error': 'No tienes permisos.'}), 401

@app.route('/clearanswer/<int:user_id>', methods=['POST'])
def clear_answer(user_id):
    if 'username' in session:
        username = session['username']
        user = User.query.filter_by(username=username).first()
        if user:
            if user.isadmin and not user.isbanned:
                # Fetch all users from the database
                usercheck = User.query.get(user_id)
                usercheck.lastanswer = None
                usercheck.lastsecondanswer = None
                usercheck.answered = False
                usercheck.givenfirstquestion = None
                usercheck.givensecondquestion = None
                db.session.commit()
                return '', 200  # Return an empty response with status code 200
            else:
                return render_template('404.html'), 404
        else:
            return render_template('404.html'), 404
    else:
        return render_template('404.html'), 404

@app.route('/banned')
def banned():
    return render_template('banned.html')

@app.route('/download_excel')
def download_excel():
    # Query all users
    users = User.query.all()
    user_data = [{
        "ID": user.id,
        "Username": user.username,
        "Displayname": user.displayname,
        "Email": user.email,
        "Password (Encrypted)": user.password,
        "Is Admin": user.isadmin,
        "Points": user.points,
        "Last Answer": user.lastanswer,
        "Last Second Answer": user.lastsecondanswer,
        "Answered": user.answered,
        "Given First Question": user.givenfirstquestion,
        "Given Second Question": user.givensecondquestion,
        "Is Banned": user.isbanned
    } for user in users]

    # Create DataFrame
    df = pd.DataFrame(user_data)
    
    # Use BytesIO to save the DataFrame to an in-memory buffer
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Users')
        writer.close()  # Save the writer content to the buffer

    # Set the pointer to the beginning of the stream
    output.seek(0)
    
    # Send the file to the client
    return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', as_attachment=True, download_name="Users.xlsx")

# Define a route for handling undefined subpages
@app.route('/<path:subpath>')
def handle_subpage(subpath):
    # Check if the requested subpage exists, otherwise serve 404 page
    return render_template('404.html'), 404

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        check_and_update_date()
    date_check_thread = threading.Thread(target=date_check_background)
    date_check_thread.daemon = True
    date_check_thread.start()
    app.run(debug=True, port=25565)