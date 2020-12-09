import string
from flask import Flask, request, render_template, session, redirect, flash
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, ColumnDefault, ForeignKey, select

from helpers import apology, login_required

app = Flask(__name__)
engine = create_engine('sqlite:///handout_maker.db')
metadata = MetaData(bind=engine)

app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


user_table = Table('users', metadata,
                   Column('id', Integer, primary_key=True, autoincrement=True),
                   Column('username', String(30), index=True, nullable=False, unique=True),
                   Column('hash', String, nullable=False),
                   Column('name', String(30), nullable=False),
                   Column('last_name', String(30), nullable=False),
                   Column('handouts', Integer))    

handout_table = Table('handouts', metadata,
                   Column('id', Integer, primary_key=True, autoincrement=True),                   
                   Column('handout_name', String(30), index=True, nullable=False),     
                   Column('language', String(30), index=True, nullable=False),                   
                   Column('level', Integer, nullable=False),
                   Column('desc_csv', String, nullable=False))

lesson_table = Table('lessons', metadata,
                   Column('id', Integer, primary_key=True, autoincrement=True),                   
                   Column('lesson_num', Integer, index=True, nullable=False),
                   Column('title', String(30), index=True, nullable=False),
                   Column('text', String, nullable=False),
                   Column('exercise', String),
                   Column('text_two', String),
                   Column('morphology', String),
                   Column('syntax', String),
                   Column('tips', String))

vocabulary_table = Table('vocabularies', metadata,
                   Column('id', Integer, primary_key=True, autoincrement=True),
                   Column('language', String(45)),                   
                   Column('type', String(20)),            
                   Column('gen', String(1)),
                   Column('translate', String(46)))    



@app.route("/login", methods=['GET', 'POST'])
def login():
    session.clear()

    if request.method == "POST":
        
        if not request.form.get("username"):
            return apology("must provide username", 403)

        elif not request.form.get("password"):
            return apology("must provide password", 403)

        rows = engine.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username")).fetchall()

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        session["user_id"] = rows[0]["id"]

        return redirect("/myhandout")
    
    return render_template("login.html")

@app.route("/register", methods=['GET', 'POST'])
def register():
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        name = request.form.get("name")
        last_name = request.form.get("last_name")
        user = request.form.get("username")
        password = request.form.get("password")
        passwordagain = request.form.get("passwordagain")
        handouts = 0

        # Ensure password not equals password
        if password != passwordagain:
            return apology("password not equals", 404)

        passhash = generate_password_hash(password)

        # Ensure username was submitted
        if not user:
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 403)

        else:
            with engine.connect() as conn:
                db = conn.execute("INSERT INTO users(username, hash, name, last_name, handouts) VALUES(:username, :password, :name, :last_name, :handouts)", 
                        username=user, password=passhash, name=name, last_name=last_name, handouts=handouts)

                # Query database for username
                rows = conn.execute("SELECT * FROM users WHERE username = :username",
                                           username=request.form.get("username")).fetchall()
                       
                if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
                    return apology("invalid username and/or password", 403)

            session["user_id"] = rows[0]["id"]
            return redirect("/myhandout")

    return render_template("/register.html")

@app.route("/logout")
def logout():
    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/myhandout")

@app.route("/new", methods=['GET', 'POST'])
@login_required
def create_handout():    
    if request.method == "POST":
        handout_name = request.form.get("handout_name")             
        level = request.form.get("level")   
        language = request.form.get("language")        
        desc_csv = request.form.get("desc_csv")        
        with engine.connect() as conn:
            conn.execute("INSERT INTO handouts(handout_name, language, level, desc_csv) VALUES(:handout_name, :language, :level, :desc_csv)",
                                                handout_name=handout_name, language=language, level=level, desc_csv=desc_csv)
            select = conn.execute("SELECT handouts FROM users WHERE id = :user_id",
                                    user_id=session["user_id"])
        flash(select)
        return 'hello world'
         
    return render_template("new_handout.html")  
    
@app.route("/myhandout")
@login_required
def myhandout():
    return render_template("myhandout.html")

@app.route("/readability", methods=["GET", "POST"])
def readability():
    if request.method == "POST":
        text = request.form.get("text")
        if len(text) == 0:
            grade = "Input a text"
        else:     
            # Lenght of Letters
            count_punctuation = 0
            for p in range(len(text)):
                if (text[p] in string.punctuation):
                    count_punctuation += 1

            letters = len(text) - text.count(" ") - count_punctuation

            # Lenght of sentences
            sentences = 0
            for p in range(len(text)):
                if (text[p] == ".") or (text[p] == "!") or (text[p] == "?"):
                    sentences += 1

            # Lenght of words
            words = len(text.split())

            # Index Coleman-Liau
            L = letters / words * 100
            S = sentences / words * 100
            CLI = (0.0588 * L) - (0.296 * S) - 15.8
            CLI = round(CLI)
            
            # Output 
            if CLI <= 1:
                grade = "Before Grade 1"
            elif CLI >= 16:
                grade = "Grade 16+"
            else:
                grade = f"Grade {CLI}"
        return render_template('readability.html', text=text, grade=grade)

    return render_template('readability.html')


if __name__ == "__main__":
    metadata.create_all()
    app.run(port=8080, host='127.0.0.1', debug=True, threaded=True)
