# basic_website_v3.py
"""
Creates and hosts a basic website to demonstrate capabilities of flask and Python.
Content is basic information about Video Game console generations.

Will Feighner
2021 05 08
"""
import datetime
import os
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


@app.route('/handle_login/', methods=['GET', 'POST'])
def handle_login():
    """Process login by finding username and comparing password hashes"""
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        user_pass = request.form.get('password')
        hash_pass = ''
        if is_registered(username):
            with open(os.path.join(sys.path[0] + "\\" + "static\\pass_file.txt"), "r") as pass_file:
                lines = pass_file.readlines()
                for line in lines:
                    if username in line:
                        hash_pass = line.split(', ')[1]
                        break

        if sha256_crypt.verify(user_pass, hash_pass):
            flash('Login Successful')
            return redirect(url_for('show_home'))
        error = 'Invalid Credentials'
    return render_template('login.html', error=error)


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
    elif not complexity(password):
        error = 'Make your password more complex.It must be at least 12 characters in length,   ' \
                'and include at least 1 uppercase character, 1 lowercase character, 1 number and ' \
                '1 special character.'

    if error is None:
        register(username, password, real_name, email)
        flash('You successfully registered')
        return redirect(url_for('show_home'))

    return render_template('register.html', error=error)


def is_registered(username):
    """Checks if user is already registered"""
    print(os.path.join(sys.path[0] + "\\" + "static\\pass_file.txt"))
    username += ', '
    with open(os.path.join(sys.path[0] + "\\" + "static\\pass_file.txt"), "r") as pass_file:
        if username in pass_file.read():
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


def complexity(password):
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

    with open(os.path.join(sys.path[0] + "\\" + "static\\pass_file.txt"), "a") as pass_file:
        pass_file.writelines("\n" + username + ", " + sha256_crypt.hash(password) + ", " +
                             real_name + ", " + email_address)


if __name__ == '__main__':
    app.run()
