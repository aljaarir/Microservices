import sqlite3
import os
from flask import Flask, request, jsonify
import requests # allowed

# PORT 5003
app = Flask(__name__)
db_name = "logs.db"
sql_file = "logs.sql"
db_flag = False


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

    
@app.route('/log_event', methods=['POST'])
def log_event():
    data = request.form
    event = data.get('event')
    user = data.get('user')
    filename = data.get('filename')

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs';")
    db_check = cursor.fetchone()

    if not db_check:
        create_db()
        conn.close()
        conn = get_db() 
        cursor = conn.cursor() 

    cursor.execute("INSERT INTO logs (event_type, user, file_name) VALUES (?, ?, ?)", (event, user, filename))
    conn.commit()
    conn.close()
    return jsonify({"status": 1})

    
 
@app.route('/view_log', methods=['GET'])
def view_log():
    args = request.args
    username = args.get('username')
    file_name = args.get('filename')

    stored_jwt = request.headers['Authorization']
    MICRO2URL = "http://user_functions_container:5000/verify"
    r = requests.post(url = MICRO2URL, data={"jwt": stored_jwt})
    permitted_user = r.json()
    if not permitted_user:
        return jsonify({"status": 2})  # Bad JWT

    # Only allowed groups can view logs for the file

    MICRO2URL = "http://user_functions_container:5000/group_checker"
    r = requests.post(url=MICRO2URL, data={"username": permitted_user})
    user_groups = r.json()

    MICRO2URL = "http://document_functions_container:5000/document_groups"
    r = requests.get(url=MICRO2URL, params={"filename": file_name})
    document_groups = r.json()

    # Have to add a way to figure out a way to order of events when added to db
    # Collect event, user, filename with query
    # store that into a returning data
    conn = get_db()
    cursor = conn.cursor()
    if username:
        if permitted_user != username:
            return jsonify({"status": 3}) # users can only look at their own logs
        cursor.execute("SELECT * FROM logs WHERE user = ?", (username,))
    elif file_name:
        if not any(group in user_groups for group in document_groups):
            return jsonify({"status": 3})  # Not authorized to view the document
        cursor.execute("SELECT * FROM logs WHERE file_name = ?", (file_name,))
    else:
        return jsonify({"status": 2, "data": "NULL"})



    # Need to figure out how to send the response

    # If we were to then make a request to view the logs for the file ’a.txt’ the return in the data
    # would look like:
    # {
    # "status": 1
    # "data": {
    # 1: { "event": "document_creation", "user": "user1", "filename": "a.txt"},
    # 2: { "event": "document_edit", "user": "user2", "filename": "a.txt"},
    # 3: { "event": "document_edit", "user": "user1", "filename": "a.txt"},
    # 4: { "event": "document_search", "user": "user1", "filename": "a.txt"}
    # }
    # }
    
    logs = cursor.fetchall()
    conn.close()
    
    data = {}
    i = 1
    for log in logs:
        data[i] = {"event": log[1], "user": log[2], "filename": log[3] or "NULL"}
        i += 1

    return jsonify({"status": 1, "data": data})

@app.route('/last_mod', methods=['GET'])
def last_mod():
    args = request.args
    file_name = args.get('filename')

    conn = get_db()
    cursor = conn.cursor()
    # Find  latest modification log for the given file
    cursor.execute(
        "SELECT user FROM logs WHERE file_name = ? AND (event_type = 'document_edit' OR event_type = 'document_creation') ORDER BY log_id DESC LIMIT 1", 
        (file_name,))
    last_mod = cursor.fetchone()
    conn.close()
    return jsonify(last_mod[0])




@app.route('/total_mod', methods=['GET'])
def total_mod():
    args = request.args
    file_name = args.get('filename')

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) AS total_modifications FROM logs WHERE file_name = ?", (file_name,) )
    conn.commit()
    total_modifications = cursor.fetchone()
    conn.close()
    return jsonify(total_modifications[0])


