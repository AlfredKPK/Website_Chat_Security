# -*- coding: utf-8 -*-
# ==============================================================================
# Copyright (c) 2024 Xavier de Carné de Carnavalet
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# ==============================================================================

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, flash
from flask_mysqldb import MySQL
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import yaml
import pyotp
import qrcode
import random
import string
import hashlib
import os
import binascii
import requests

app = Flask(__name__)
#limiter: default 200 per day, 50 per hour
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)


# Configure secret key and Flask-Session
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SESSION_TYPE'] = 'filesystem'  # Options: 'filesystem', 'redis', 'memcached', etc.
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True  # To sign session cookies for extra security
app.config['SESSION_FILE_DIR'] = './sessions'  # Needed if using filesystem type
#app.config['SESSION_COOKIE_HTTPONLY'] = True

# Load database configuration from db.yaml or configure directly here
db_config = yaml.load(open('db.yaml'), Loader=yaml.FullLoader)
app.config['MYSQL_HOST'] = db_config['mysql_host']
app.config['MYSQL_USER'] = db_config['mysql_user']
app.config['MYSQL_PASSWORD'] = db_config['mysql_password']
app.config['MYSQL_DB'] = db_config['mysql_db']

mysql = MySQL(app)

# Initialize the Flask-Session
Session(app)

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    sender_id = session['user_id']
    username = session['username']
    return render_template('chat.html', sender_id=sender_id, username=username)

@app.route('/users')
def users():
    if 'user_id' not in session:
        abort(403)

    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id, username, ECDH_publicKey FROM users")
    user_data = cur.fetchall()
    cur.close()

    filtered_users = [[user[0], user[1], user[2]] for user in user_data if user[0] != session['user_id']]
    return {'users': filtered_users}

@app.route('/fetch_messages')
@limiter.exempt
def fetch_messages():
    if 'user_id' not in session:
        abort(403)

    last_message_id = request.args.get('last_message_id', 0, type=int)
    peer_id = request.args.get('peer_id', type=int)
    
    cur = mysql.connection.cursor()
    query = """SELECT message_id,sender_id,receiver_id,message_text,key_refresh FROM messages 
               WHERE message_id > %s AND 
               ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s))
               ORDER BY message_id ASC"""
    cur.execute(query, (last_message_id, peer_id, session['user_id'], session['user_id'], peer_id))

    # Fetch the column names
    column_names = [desc[0] for desc in cur.description]
    # Fetch all rows, and create a list of dictionaries, each representing a message
    messages = [dict(zip(column_names, row)) for row in cur.fetchall()]

    cur.close()
    return jsonify({'messages': messages})

@app.route('/login', methods=['GET', 'POST'])
#limit to 30 accesses per hour
@limiter.limit("30 per hour")
def login():
    error = None
    #remove the qrcode stored in otpFirstTime.html (if exists)
    try:
        os.remove('static/images/qrcode.png')
    except:
        pass
    if request.method == 'POST':
        #check is recaptcha is done
        recaptchaResponse = request.form["g-recaptcha-response"]
        if verifyRecaptcha(recaptchaResponse):
            userDetails = request.form
            username = userDetails['username']
            password = str(userDetails['password'])
            cur = mysql.connection.cursor()
            cur.execute("SELECT user_id, password, salt FROM users WHERE username=%s", (username,))
            account = cur.fetchone()
            if(account):
                databasePassword = account[1]
                saltHex = account[2]
                #reformat to the original salt
                salt = binascii.unhexlify(saltHex)
                #hash and salt the entered password so can check with database
                hashedPassword = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
                if (str(hashedPassword) == str(databasePassword)):
                    return redirect(url_for('otp', username=username))
                else:
                    error = 'Invalid credentials'
            else:
                error = 'Invalid credentials'
        else:
            error = 'Please complete reCAPTCHA'
    return render_template('login.html', error=error)

#verify recaptcha code
def verifyRecaptcha(response):
    secretKey = "6Le95aIpAAAAAGWgYf61ccBM8bURNx9q_DPzz1h_"
    verification_url = "https://www.google.com/recaptcha/api/siteverify"

    data = {
        "secret": secretKey,
        "response": response
    }
    response = requests.post(verification_url, data=data)
    result = response.json() 
    if result["success"]:
        return True
    else:
        return False

#Ask for OTP, verifies OTP (otp.html)
@app.route('/otp', methods=['GET', 'POST'])
def otp():
        error = None
        username = request.args.get('username', None)
        if request.method == 'POST':
            enteredOtp = str(request.form.get('otp'))
            #get the user_id and secret key stored in database
            cur = mysql.connection.cursor()
            cur.execute("SELECT user_id, otp_key FROM users WHERE username=%s", (username,))
            account = cur.fetchone()
            if account:
                otp_key = account[1]
                databaseOtp = pyotp.TOTP(otp_key)
                #compare otp, if correct, establish session
                if (databaseOtp.now() == enteredOtp):
                    session['username'] = username
                    session['user_id'] = account[0]
                    return redirect(url_for('index'))
            error = 'Invalid One-time Password'
        return render_template('otp.html', username=username, error=error)

#recovery page
@app.route('/recovery', methods=['GET', 'POST'])
def recovery():
    username = request.args.get('username', None)
    return render_template('recovery.html', username=username)

#verify recovery key
@app.route('/recoverycheck', methods=['GET', 'POST'])
def recoveryCheck():
    error = None
    username = request.args.get('username', None)
    if request.method == 'POST':
        enteredRecovery = request.form.get('recoveryKey')
        #get recovery key from database
        cur = mysql.connection.cursor()
        cur.execute("SELECT recovery_key FROM users WHERE username=%s", (username,))
        recoveryKey = cur.fetchone()
        databaseRecovery = recoveryKey[0]
        #check database and entered recovery key
        if databaseRecovery == enteredRecovery:
            #regenerate a new set of secretKey, recoverykey
            secretKey = pyotp.random_base32()
            recoveryKey = generateRecoveryKey()
            cur = mysql.connection.cursor()
            cur.execute("UPDATE users Set otp_key = %s,  recovery_key = %s WHERE username=username", (secretKey, recoveryKey))
            mysql.connection.commit()
            return redirect(url_for('otpFirstTime', username=username, secretKey=secretKey, recoveryKey=recoveryKey))
        else:
            error = 'Incorrect recovery key'
    return render_template('recovery.html', username=username, error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        return render_template('register.html')
    
#Check if registration is correct
@app.route('/register/check', methods=['GET', 'POST']) 
def registerCheck():
    userDetails = request.form
    username = userDetails['username']
    password = userDetails['password']
    passwordRetype = userDetails['passwordRetype']

    #grab same username from database
    cur = mysql.connection.cursor()
    cur.execute("SELECT username FROM users WHERE username=%s", (username,))
    checkUserName = cur.fetchone()

    #check unique username
    if(checkUserName):
        error = 'Username is taken'
        return render_template('register.html', error=error)
    
    #password must be at least 8 char
    if len(password) < 8:
        error = 'Password must be at least 8 characters.'
        return render_template('register.html', error=error)
    
    #check with Have I Been Pwned database
    pwnedCount = passwordSecurityCheck(password)
    if pwnedCount > 0:
        error = 'Password is too common / Password has been breahed'
        return render_template('register.html', error=error)
    
    #compare password and retype
    if password == passwordRetype:
        saltHash = generateHashedPassword(password)
        saltHex = saltHash[0]
        hashedPassword = str(saltHash[1])
        #generate secretkey and recoverykey
        secretKey = pyotp.random_base32()
        recoveryKey = generateRecoveryKey()
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (username, password, salt, otp_key, recovery_key) VALUES (%s, %s, %s, %s, %s)", (username, hashedPassword, saltHex, secretKey, recoveryKey))
        mysql.connection.commit()
        return redirect(url_for('otpFirstTime', username=username, secretKey=secretKey, recoveryKey=recoveryKey))
    else:
        error = 'Passwords do not match'
    return render_template('register.html', error=error)

#Have I Been Pwned
def passwordSecurityCheck(password):
    #the website uses fiirst 5 characters to search the database
    #if exists, then it will check the count of suffix appearing in that line
    sha1Hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1Hash[:5]
    suffix = sha1Hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    if response.status_code == 200:
        for line in response.text.splitlines():
            linePrefix, count = line.split(":")
            if linePrefix == suffix:
                return int(count)
    return 0

#salt and hash password
def generateHashedPassword(password):
        salt = os.urandom(32)
        #reformat to be stored in database
        saltHex = binascii.hexlify(salt).decode()
        hashedPassword = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return (saltHex, hashedPassword)

#generate a 32 length long cryptographically secure recovery key
def generateRecoveryKey():
    length = 32
    letters = string.ascii_uppercase
    recoveryKey = ''.join(random.choice(letters) for i in range(length))
    return recoveryKey

def sendECDH():
    ecdhPublicKey = request.form.get('ecdhPublicKey')  # Retrieve the ecdhPublicKey value from the form
    username = request.form.get('name') 
    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET ECDH_publicKey = %s WHERE username = %s", (ecdhPublicKey, username))
    mysql.connection.commit()


#Shows QR Code, secret key, recovery key for first time users (otpFirstTIme.html), generate and sending the key
@app.route('/register/otpFirstTime', methods=['GET', 'POST'])
def otpFirstTime():
    username = request.args.get('username', None)
    secretKey = request.args.get('secretKey', None)
    recoveryKey = request.args.get('recoveryKey', None)
    uri = pyotp.TOTP(secretKey).provisioning_uri(name=username, issuer_name="COMP3334 Group Project")
    qrcode.make(uri).save("static/images/qrcode.png")
    if request.method == 'POST':
        sendECDH()
        flash('Public key updated successfully.', 'info')
        return redirect(url_for('login'))
    return render_template('otpFirstTime.html', username=username, secretKey=secretKey, recoveryKey=recoveryKey)

@app.route('/send_message', methods=['POST'])
def send_message():
    if not request.json or not 'message_text' in request.json:
        abort(400)  # Bad request if the request doesn't contain JSON or lacks 'message_text'
    if 'user_id' not in session:
        abort(403)

    # Extract data from the request
    sender_id = session['user_id']
    receiver_id = request.json['receiver_id']
    message_text = request.json['message_text']
    key_refresh = request.json['key_refresh']

    # Assuming you have a function to save messages
    save_message(sender_id, receiver_id, message_text, key_refresh)
    
    return jsonify({'status': 'success', 'message': 'Message sent'}), 200

def save_message(sender, receiver, message, key_refresh):
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO messages (sender_id, receiver_id, message_text, key_refresh) VALUES (%s, %s, %s, %s)", (sender, receiver, message, key_refresh))
    mysql.connection.commit()
    cur.close()

@app.route('/erase_chat', methods=['POST'])
def erase_chat():
    if 'user_id' not in session:
        abort(403)

    peer_id = request.json['peer_id']
    cur = mysql.connection.cursor()
    query = "DELETE FROM messages WHERE ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s)) AND key_refresh = 'false'"
    cur.execute(query, (peer_id, session['user_id'], session['user_id'], peer_id))
    mysql.connection.commit()

    # Check if the operation was successful by evaluating affected rows
    if cur.rowcount > 0:
        return jsonify({'status': 'success'}), 200
    else:
        return jsonify({'status': 'failure'}), 200

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been successfully logged out.', 'info')  # Flash a logout success message
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

