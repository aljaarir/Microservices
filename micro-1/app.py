import sqlite3
import os
from flask import Flask, request, jsonify
from hashlib import sha256
import hmac # JWT
import base64 # JWT
import json # json.loads() for verifying process in JWT

import requests # allowed

app = Flask(__name__)
db_name = "user.db"
sql_file = "user.sql"
db_flag = False



# ------------------------------------------------------------------------------------------

def create_db():
    conn = sqlite3.connect(db_name)
    
    with open(sql_file, 'r') as sql_startup:
    	init_db = sql_startup.read()
    cursor = conn.cursor()
    cursor.executescript(init_db)
    conn.commit()
    conn.close()
    global db_flag
    db_flag = True
    return conn

def get_db():
	if not db_flag:
		create_db()
	conn = sqlite3.connect(db_name)
	return conn


@app.route('/clear', methods=['GET'])
def clear_db():
    # Took from Proj2 as Mariani said this is a better option than dropping the tables
    global db_flag
    if db_flag:
        conn = sqlite3.connect(db_name)
        conn.close()
        db_flag = False
    
    # Remove the database file if it exists
    if os.remove(db_name):
        return jsonify({"status": "Database cleared successfully"})
    else:
        return jsonify({"status": "Database file not found"})



@app.route('/create_user', methods=['POST'])
def create_user():
    # Utilized data = request.get_json() tested on POSTMAN -> can feed it with request.form too
    # Just need to change the input form
    data = request.form 
    first_name = data['first_name']
    last_name = data['last_name']
    username = data['username']
    email_address = data['email_address']
    password = data['password']
    group = data.get('group')
    salt = data['salt']

    # Make sure PW is strong
    if not validate_password(password, first_name, last_name, username):
        return jsonify({"status": 4, "pass_hash": "NULL"})
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Hash 
    password_salted = password + salt
    password_hash = sha256(password_salted.encode('utf-8')).hexdigest()

    # Check if username or email already exists
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,)) # Needs comma after bc its a tuple
    if cursor.fetchone():
        return jsonify({"status": 2, "pass_hash": "NULL"})
    
    cursor.execute("SELECT * FROM users WHERE email = ?", (email_address,))
    if cursor.fetchone():
        return jsonify({"status": 3, "pass_hash": "NULL"})

    # Insert the user into the database
    cursor.execute(
        "INSERT INTO users (first_name, last_name, username, email, password_hash, group_list, salt) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (first_name, last_name, username, email_address, password_hash, group, salt)
    )
    
    conn.commit()
    conn.close()
    
    # Log user creation to microservice
    MICRO2URL = "http://log_functions_container:5000/log_event"
    r = requests.post(url=MICRO2URL, data={"event": "user_creation","user": username, 'filename': None})
    return jsonify({"status": 1,"pass_hash": password_hash})

def validate_password(password, first_name, last_name, username):
    # Check length
    if len(password) < 8:
        return False

    has_lowercase = False
    has_uppercase = False
    has_number = False
    
    for char in password:
        if char.islower():
            has_lowercase = True
        if char.isupper():
            has_uppercase = True
        if char.isdigit():
            has_number = True


    # If any of the requirements are not met, return False
    if not (has_lowercase and has_uppercase and has_number ):
        return False

    # Check if password contains the entire first_name, last_name, or username
    if first_name.lower() in password.lower() or last_name.lower() in password.lower() or username.lower() in password.lower():
        return False
    
    return True

@app.route('/login', methods=['POST'])
def login():
    data = request.form
    username = data['username']
    password = data['password']
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    # If user not found
    if not user:
        return jsonify({"status": 2, "jwt": "NULL"})
    
    # Else grab data from query
    stored_password_hash, stored_salt = user
    
    # Hash the provided password with the stored salt
    password_hash = sha256((password + stored_salt).encode()).hexdigest()
    
    # If hashes fail, exit
    if password_hash != stored_password_hash:
        return jsonify({"status": 2, "jwt": "NULL"})
    
    # Generate JWT if login successful
    jwt_token = generate_jwt(username)
    
    
    # Log user login to microservice
    MICRO2URL = "http://log_functions_container:5000/log_event"
    r = requests.post(url=MICRO2URL, data={"event": "login","user": username, 'filename': None})
    return jsonify({"status": 1, "jwt": jwt_token})

# JWT
def load_key():
    with open('key.txt', 'r') as key_file:
        return key_file.read()
    
def generate_jwt(username):
    header = '{"alg": "HS256", "typ": "JWT"}'
    payload = f'{{"username": "{username}"}}'

    # Encode the header and payload using Base64 URL-safe encoding
    header_encoded = base64.urlsafe_b64encode(header.encode('utf-8')).decode('utf-8')
    payload_encoded = base64.urlsafe_b64encode(payload.encode('utf-8')).decode('utf-8')

    # Create the signature
    key = load_key()
    signature_data = f'{header_encoded}.{payload_encoded}'
    signature = hmac.new(key.encode('utf-8'), signature_data.encode('utf-8'), sha256).hexdigest()
    return f'{header_encoded}.{payload_encoded}.{signature}'

@app.route('/verify', methods=['POST'])
def verify_jwt():
    data = request.form
    token = data.get('jwt')
    
    # Split the token up to header,payload, signature
    parts = token.split('.')
    if len(parts) != 3:
        return jsonify(None) 

    header_encoded, payload_encoded, signature = parts

    # Recreate the signature
    key = load_key()
    message = f"{header_encoded}.{payload_encoded}"
    recreated_signature = hmac.new(key.encode('utf-8'), message.encode('utf-8'), sha256).hexdigest()

    # If the signature doesn't match, it's invalid
    if recreated_signature != signature:
        return jsonify(None)

    # Decode the payload to get user & access
    payload_decoded = base64.urlsafe_b64decode(payload_encoded + '==').decode('utf-8')
    # '==' acts as padding

    # Json.loads() converts into py dictionary of all data inside
    payload = json.loads(payload_decoded)
    

    username = payload.get('username')
    return jsonify(username)


@app.route('/group_checker', methods=['POST'])
def group_checker():
    # post is request.form
    # get is request.get -- Look at project
    data = request.form
    username = data.get('username')
    # stored_jwt = request.headers['Authorization']  # Don't know if needed or not
    conn = get_db()
    cursor = conn.cursor()
    # Find all groups user is related to
    cursor.execute("SELECT group_list FROM users WHERE username = ?", (username,))
    groups = cursor.fetchone()
    conn.close()
    return jsonify(groups)
    
	
    

     