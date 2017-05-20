# main.py
# Main Python Flask application

#===================#
#===== MODULES =====#
#===================#

from flask import Flask, flash, redirect, render_template, request, session, abort, g, url_for, escape, jsonify
from hashlib import sha512
import string
import sqlite3
import os
import re

#=================#
#===== MAIN ======#
#=================#

app = Flask(__name__)

#generates pseudorandom secret key
app.secret_key = os.urandom(32)

# Database set up
DATABASE = "main.db"

# initial connect
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        # wrap the connection with a row factory to gain the ability
        # to reference query results using column names
        db.row_factory = sqlite3.Row
    return db

# function to simplify querries
# set commit=True if you want to make changes to the DB (versus just querrying it)
def query_db(query, args=(),commit=False, one=False):
    db = get_db()
    cur = db.execute(query, args)
    rv = cur.fetchall()

    if commit:
        db.commit()

    cur.close()

    #returns a TUPLE, NOT DICT
    return (rv[0] if rv else None) if one else rv


#===================#
#== INTERCEPTORS ==#
#===================#
# annotation sets this function to run after each request
@app.after_request
def configure_headers(response):
    # disable pages from being loaded in iframes (clickjacking attacks)
    response.headers["X-Frame-Options"] = "NONE"
    response.headers["Server"] = ""
    return response


#==================#
#===== ROUTES =====#
#==================#

# index
@app.route('/')
def index():
    return render_template("index.html")

# login
# route limits access to POST
@app.route("/login", methods=["POST","GET"])
def login():

    #if POST, i.e. form has been submitted with login information
    if request.method == "POST":

        # remove non alphanumeric characters from form, after convverting unicode --> ascii
        #sha512 hash for password
        username = filter(str.isalnum,request.form["username"].encode("ascii","replace"))
        password = sha512(filter(str.isalnum,request.form["password"].encode("ascii","replace"))).hexdigest()

        if not username or not password:
            flash("Fields cannot be empty or contain non alphanumeric characters.")
            return redirect(url_for("login"))

        else:

            if isUserLockedOut(username) == True:
                flash("This user account is locked")
                return render_template("login.html")

            # parameterized query
            query = "select * from users where password = ? and username = ?;"
            args = [password, username]

            response = query_db(query,args,one=True)

            if response is None:
                # potentially lock out an attacker who is trying
                # to brute force / DoS our application
                anti_brute_force_measures(username)
                # don't tell user which one is incorrect
                # otherwise, user can discern info on users in database
                flash("Wrong username/password combination!")
                return redirect(url_for("login"))

            else:
                reset_login_attempts(username)

                #set session variables
                session['username'] = response[0]
                session['lastName'] = response[2]
                session['firstName'] = response[3]
                session['balance'] = "%.2f" % response[4]

                return redirect(url_for("index"))

    #if GET, i.e. user is trying to get to login page
    else:
        return render_template("login.html")


def isUserLockedOut(username):
    query = "select * from users where username = ? AND (lockout_ts is NULL OR lockout_ts < CURRENT_TIMESTAMP);"
    user = query_db(query, [username], one=True)
    if user is None:
        return True
    return False

def anti_brute_force_measures(username):
    update_lockout_ts = "update users set lockout_ts = datetime('now', '+5 minutes') where username = ?;"
    bad_login_attempts = get_user(username)['badloginattempts'] + 1
    update_login_attempts(username, bad_login_attempts)

    if bad_login_attempts >= 5:
        flash("This user account is locked for 5 minutes")
        query_db(update_lockout_ts, [username], one=True, commit=True)

def reset_login_attempts(username):
    update_login_attempts(username, 0)

def update_login_attempts(username, bad_login_attempts):
    query = "update users set badloginattempts = ? where username = ?;"
    query_db(query, [bad_login_attempts, username], one=True, commit=True)

# logout
@app.route("/logout")
def logout():
    session.pop('username', None)
    flash("You have been succesfully logged out.")
    return redirect(url_for('index'))

@app.route("/register", methods=["GET","POST"])
def register():

    #if POST, i.e. form data being submitted
    if request.method == "POST":

        # Password validations
        if request.form["password"] != request.form["confirm"]:
            flash("Passwords do not match")
            return render_template("register.html")
        password_validation_message = verify_password_policy_compliance(request.form["password"])
        if password_validation_message is not None:
            flash(password_validation_message)
            return render_template("register.html")

        # remove non alphanumeric characters from form, after convverting unicode --> ascii
        #sha512 hash (hex) for password
        username = filter(str.isalnum,request.form["username"].encode("ascii","replace"))
        password = sha512(filter(str.isalnum,request.form["password"].encode("ascii","replace"))).hexdigest()
        lastName = filter(str.isalnum,request.form["lastName"].encode("ascii","replace"))
        firstName = filter(str.isalnum,request.form["firstName"].encode("ascii","replace"))

        #if any field is empty, this is return true and execute
        if not username or not password or not firstName or not lastName:
            flash("Fields cannot be empty or contain non alphanumeric characters.")
            return redirect(url_for("register"))

        #otherwise, commit to db
        else:
            if get_user(username) is not None:
                flash("A user already exists with this username")
                return render_template("register.html")

            # parameterized query
            query = "insert into users (username,password,lastname,firstname, balance) values (?,?,?,?,?)"
            args = [username,password,lastName,firstName,0.00]

            response = query_db(query,args,commit=True,one=True)

            # return str(response)

            flash("Account successfully created. You may now login.")
            # flash("Account succesfully created! Please login!")

            return redirect(url_for("login"))

    #if GET, return register page
    else:
        return render_template("register.html")

@app.route("/addCredits", methods=["POST"])
def add_credits():
    # break if the user attempts to make the API call without 
    # authenticating first
    if session is None or 'username' not in session:
        flash("Please login first")
        return render_template("login.html")

    if not isfloat(request.form['amount']) or float(request.form['amount']) < 0:
        flash("Invalid amount")
        return render_template("index.html")

    amount = float(request.form['amount'])
    user = get_user(session['username'])
    deposit(user, amount)
    log_transaction(session['username'], None, amount, "deposit")

    flash("Funds successfully deposited into your account")
    return render_template("index.html")

@app.route("/transferCredits", methods=["POST"])
def transfer_credits():
    if session is None or 'username' not in session:
        flash("Please login first")
        return render_template("login.html")

    # input validation
    if not request.form['username']:
        flash("Please enter the username of the account to which you wish to transfer funds")
        return render_template("index.html")
    if not request.form['amount']:
        flash("Please enter the number of credits to be transfered")
        return render_template("index.html")
    if not isfloat(request.form['amount']) or float(request.form['amount']) < 0:
        flash("Invalid amount")
        return render_template("index.html")

    source_acct = session['username']
    dest_acct = sanitize(request.form['username'])
    amount = float(request.form['amount'])

    # transferring credits to your own account should be an
    # idempotent operation
    if source_acct == dest_acct:
        flash("Transfer successful")
        return render_template("index.html")

    source_user = get_user(source_acct)
    if not withdraw(source_user, amount):
        flash("Insufficient funds")
        return render_template("index.html")
    log_transaction(source_acct, dest_acct, amount, "outgoing_transfer")

    dest_user = get_user(dest_acct)
    if dest_user is not None:
        # if we error out, we will inform the user whether or not
        # the username they entered was valid and they'd be able to
        # brute force all usernames in the db.
        # rather than reveal that information, let's just withdraw
        # money from the user's account and not deposit it.
        deposit(dest_user, amount)
        log_transaction(source_acct, dest_acct, amount, "incoming_transfer")

    flash("Transfer successful")
    return render_template("index.html")

@app.route("/transactions/view", methods=["GET"])
def get_transactions():
    # break if the user attempts to make the API call without 
    # authenticating first
    if session is None or 'username' not in session:
        response = jsonify({"errorMsg":"User not logged in"})
        response.status_code = 401
        return response

    query = "select * from transactions where username=? order by crt_ts desc limit 25;"
    transactions = query_db(query, [session['username']],
         commit=False, one=False)

    transaction_list = []
    for transaction in transactions: 
        obj = { "description": str(transaction['description']), "amount": str(transaction['amount']),
            "time": str(transaction['crt_ts']) }
        transaction_list.append(obj)
    return jsonify(transaction_list)


@app.route("/transactions", methods=["GET"])
def view_transactions():
    # break if the user attempts to make the API call without 
    # # authenticating first
    if session is None or 'username' not in session:
        flash("Please login first")
        return render_template("login.html")

    return render_template("transactions.html")

@app.route("/test", methods=["GET"])
def test():
    return jsonify({"result":verify_password_policy_compliance(request.args.get("password"))})


def verify_password_policy_compliance(password):
    password_pattern = re.compile('[~!@#$%^&*_\\-+=`|\(\)\{\}\[\]:;"\'<>,.?\]]')
    if password is None:
        return "Please provide a password"
    # verify length
    if len(password) < 8:
        return "Password must be longer than 8 characters"
    # check for special characters
    if password_pattern.search(password) is None:
        return "Password must contain at least one special character"
    if re.compile('[A-Z]').search(password) is None:
        return "Password must contain at least one upper case character"
    if re.compile('[a-z]').search(password) is None:
        return "Password must contain at least one lower case character"
    if re.compile('[0-9]').search(password) is None:
        return "Password must contain at least one digit"
    return None


def withdraw(user, amount):
    balance = user['balance']
    update_query = "update users set balance = ? where username= ?;"
    if balance < amount:
        return False
    new_balance = balance - amount
    query_db(update_query, [new_balance, user['username']],
         commit=True, one=True)
    return True

def deposit(user, amount):
    update_query = "update users set balance = ? where username= ?;"
    new_balance = user['balance'] + amount
    query_db(update_query, [new_balance, user['username']],
         commit=True, one=True)
    return True

def get_user(username):
    query = "select * from users where username = ?;"
    return query_db(query, [username], commit=False, one=True)

def log_transaction(source_username, dest_username, amount, transaction_type):
    query = "insert into transactions (username, description, amount) values (?, ?, ?);"
    description = None
    user = None
    amount_formatted = None

    if transaction_type == "deposit":
        description = 'Credit Deposit'
        user = source_username
        amount_formatted = "+${:.2f}".format(amount)
    elif transaction_type == "outgoing_transfer":
        description = "Outgoing transfer to user '{}'".format(dest_username)
        user = source_username
        amount_formatted = "-${:.2f}".format(amount)
    elif transaction_type == "incoming_transfer":
        description = "Incoming transfer from user '{}'".format(source_username)
        user = dest_username
        amount_formatted = "+${:.2f}".format(amount)
    else:
        raise ValueError("Invalid transaction type")

    query_db(query, [user, description, amount_formatted], commit=True, one=True)


@app.context_processor
def context_utils():
    # defined functions are made accessible in jinja template
    def get_balance(username):
        query = "select * from users where username = ?;"
        result = query_db(query, [username], commit=False, one=True)
        if result is None:
            return 0.0
        return result['balance']

    return dict(get_balance=get_balance)

# tear down
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def sanitize(string):
    filter(str.isalnum, string.encode("ascii","replace"))
    return string

def isfloat(string):
    try:
        float(string)
        return True
    except ValueError:
        return False

#=====================================#
#===== CONDITIONAL RUN VARIABLES =====#
#=====================================#

# we probably won't need this, so it's commented out for now

# this will only run if the applicaiotn is being run as an applicaiton
# (versus being imported as a moedule)
# if __name__ == "__main__":
#     app.run(debug=True,host='0.0.0.0', port=5000)
