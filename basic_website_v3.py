# basic_website_v3.py
"""
Creates and hosts a basic website to demonstrate capabilities of flask and Python.
Content is basic information about Video Game console generations.

Will Feighner
2021 05 08
"""
import csv
import datetime
import os
import socket
import string
import sys

from flask import Flask, render_template, request, flash, redirect, url_for
from passlib.hash import sha256_crypt

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'


def get_date_time():
    """Returns current local date and time"""
    return datetime.datetime.today().strftime("%m-%d-%Y %H:%M:%S")


@app.route('/')
def show_home():
    """Create and render Home page"""
    return render_template('home.html', datetime=get_date_time())


@app.route('/previous_generations/')
def show_previous():
    """Create and render previous generation console listings"""
    return render_template('previous.html')


@app.route('/8thgen/')
def show_8th_gen():
    """Create and render previous generation console listing"""
    return render_template('8thgen.html')


@app.route('/about/')
def show_about():
    """Create and render about info page"""
    return render_template('about.html')


@app.route('/register/')
def show_register():
    """Create and render register page"""
    return render_template('register.html')


@app.route('/update/')
def show_update():
    """Allows user to update their password"""
    return render_template('update.html')


@app.route('/handle_update)', methods=['GET', 'POST'])
def handle_update():
    """Processes update user password"""
    error = None
    if request.method == "POST":
        username = request.form.get('username')
        old_pass = request.form.get('old_password')
        new_pass = request.form.get('new_password')
        check_pass = request.form.get('new_password2')

        if not is_registered(username):
            error = 'User is not registered'

        hash_pass = ''
        hash_pass = get_hash(hash_pass, username)

        if not sha256_crypt.verify(old_pass, hash_pass):
            error = 'Current Password incorrect'

        if new_pass != check_pass:
            error = 'Passwords do not match'

        if is_bad_pass(new_pass):
            error = 'Password too common'

        if not is_complex(new_pass):
            error = 'Password not complex enough'

        if error is not None:
            return render_template('update.html', error=error)

        if sha256_crypt.verify(old_pass, hash_pass):
            fields = ['username', 'password_hash', 'real_name', 'email_address']
            temp_data = []
            with open(os.path.join(sys.path[0] + "/static/pass_file.csv"), "r+",
                      newline="") as pass_file:
                reader = csv.DictReader(pass_file, fieldnames=fields)
                next(reader)

                for line in reader:
                    if line['username'] == username:
                        line['password_hash'] = sha256_crypt.hash(new_pass)
                    temp_data.append(line)

            with open(os.path.join(sys.path[0] + "/static/pass_file.csv"), "w",
                      newline="") as pass_file:
                writer = csv.DictWriter(pass_file, fieldnames=fields)
                writer.writeheader()
                writer.writerows(temp_data)

            flash('Password Update Successful')
        else:
            error = 'Current Password not correct'
            return redirect(url_for('show_update', error=error))

    return redirect(url_for('show_home', error=error))


@app.route('/handle_login/', methods=['GET', 'POST'])
def handle_login():
    """Process login by finding username and comparing password hashes"""
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        user_pass = request.form.get('password')
        hash_pass = ''
        if is_registered(username):
            hash_pass = get_hash(hash_pass, username)
            if sha256_crypt.verify(user_pass, hash_pass):
                flash('Login Successful')
                return redirect(url_for('show_home'))
        hash_pass = sha256_crypt.hash(user_pass)
        error = 'Invalid Credentials'

        fields = ['date_time', 'IP_address', 'user_name', 'pass_hash']
        with open(os.path.join(sys.path[0] + "/static/failed_logins.csv"), 'a',
                  newline='') as pass_log:
            writer = csv.DictWriter(pass_log, fieldnames=fields)
            hostname = socket.gethostname()
            row = {'date_time': get_date_time(), 'IP_address': socket.gethostbyname(hostname),
                   'user_name': username, 'pass_hash': hash_pass}
            writer.writerow(row)

    return render_template('login.html', error=error)


def get_hash(hash_pass, username):
    """Get password hash"""
    with open(os.path.join(sys.path[0] + "/static/pass_file.csv"), "r") as pass_file:
        lines = csv.reader(pass_file)
        for line in lines:
            if username == line[0]:
                hash_pass = line[1]
                break
    return hash_pass


@app.route('/login/')
def show_login():
    """Create and render login page"""
    return render_template('login.html')


@app.route('/handle_data/', methods=['GET', 'POST'])
def handle_data():
    """Processes registration data"""
    email = request.form.get('email')
    real_name = request.form.get('real_name')
    username = request.form.get('username')
    password = request.form.get('password')

    error = None

    if not username:
        error = 'Please enter your Username.'
    elif not password:
        error = 'Please enter your Password.'
    elif is_registered(username):
        error = 'You are already registered'
    elif not is_complex(password):
        error = 'Make your password more complex. It must be at least 12 characters in length, ' \
                'and include at least 1 uppercase character, 1 lowercase character, 1 number and ' \
                '1 special character.'

    if is_bad_pass(password):
        print("Password is too common. Please pick a more secret password.")
        error = "Password is too common. Please pick a more secret password."

    if error is None:
        register(username, password, real_name, email)
        flash('You successfully registered')
        return redirect(url_for('show_home'))

    return render_template('register.html', error=error)


def is_registered(username):
    """Checks if user is already registered"""

    with open(os.path.join(sys.path[0] + "/static/pass_file.csv"), "r") as pass_file:
        reader = csv.reader(pass_file)
        for row in reader:
            if username in row:
                return True
        return False


def special_test(input_string, special_req):
    """Tests if given string has enough punctuation/special characters"""
    counter = 0

    # Counts how many punctuation characters in given string
    for char in input_string:
        if char in string.punctuation:
            counter += 1

    return counter >= special_req


def is_bad_pass(password):
    """Checks password against common known passwords"""
    with open(os.path.join(sys.path[0] + "/static/CommonPassword.txt"), "r") as \
            bad_pass_file:
        bad_pass_list = bad_pass_file.readlines()

    if password + '\n' in bad_pass_list:
        return True
    return False


def is_complex(password):
    """Checks password complexity"""
    lower_case_req = 1
    upper_case_req = 1
    digit_count = 1
    special_count = 1
    length = 12

    if (len(password) >= length) and (sum(char.islower() for char in password) >= lower_case_req
                                      and sum(char.isupper() for char in password) >= upper_case_req
                                      and sum(char.isdigit() for char in password) >= digit_count
                                      and special_test(password, special_count)):
        return True
    return False


def register(username, password, real_name, email_address):
    """Registers user"""

    fields = ['username', 'password_hash', 'real_name', 'email_address']

    with open(os.path.join(sys.path[0] + "/static/pass_file.csv"), 'a',
              newline='') as pass_file:
        writer = csv.DictWriter(pass_file, fieldnames=fields)
        row = {'username': username, 'password_hash': sha256_crypt.hash(
            password), 'real_name': real_name, 'email_address': email_address}
        writer.writerow(row)


if __name__ == '__main__':
    app.run()
