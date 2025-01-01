import sqlite3
import os
import json
import requests
from flask import Flask, request, jsonify
import hashlib # hash the document body

app = Flask(__name__)
db_name = "documents.db"
sql_file = "documents.sql"
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



@app.route('/create_document', methods=['POST'])
def create_document():
      data = request.form
      file_name = data.get('filename')
      body = data.get('body')
      groups = data.get('groups')
      groups_dict = json.loads(groups)  # Parse the JSON string into a dictionary
      groups_list = list(groups_dict.values())  # Extract all group values

      stored_jwt = request.headers['Authorization']

      MICRO2URL = "http://user_functions_container:5000/verify"
      r = requests.post(url = MICRO2URL, data={"jwt": stored_jwt})
      permitted_user = r.json()

      if permitted_user:
            conn = sqlite3.connect(db_name)
            cursor = conn.cursor()
            # https://stackoverflow.com/questions/1601151/how-do-i-check-in-sqlite-whether-a-table-exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='documents';")
            db_check = cursor.fetchone()

            existed_file = None # deal with scope
            if db_check:
                cursor.execute("SELECT file_name FROM documents WHERE file_name = ?", (file_name,))
                existed_file = cursor.fetchone()
            else:
                create_db()

            # Check if file already exists, and delete if so
            if existed_file:
                cursor.execute("DELETE FROM documents WHERE file_name = ?", (file_name,))
                cursor.execute("DELETE FROM document_groups WHERE file_name = ?", (file_name,))


            cursor.execute("INSERT INTO documents (file_name, body, created_by) VALUES (?, ?, ?)", 
            (file_name, body, permitted_user,))

            for group in groups_list:
                 cursor.execute("INSERT INTO document_groups (file_name, group_name) VALUES (?, ?)",
                (file_name, group,))
        
            conn.commit()
            conn.close()

            file = open(file_name,'w',newline='\n')
            if file:
                file.write(body)
                file.close()
            else:
                 return jsonify({"status": 2}) # "Only failcase is if bad JWT" but never know if this is an
            # Add to log microservice
            MICRO2URL = "http://log_functions_container:5000/log_event"
            r = requests.post(url=MICRO2URL, data={"event": 'document_creation', "user": permitted_user, "filename": file_name})            
            return jsonify({"status": 1}) 
      else:
            return jsonify({"status": 2}) # Not Permitted User
      

@app.route('/edit_document', methods=['POST'])
def edit_document():
    data = request.form
    file_name = data.get('filename')
    body = data.get('body')

    # Verify JWT
    MICRO2URL = "http://user_functions_container:5000/verify"
    stored_jwt = request.headers['Authorization']
    r = requests.post(url=MICRO2URL, data={"jwt": stored_jwt})
    permitted_user = r.json()
    if not permitted_user:
        return jsonify({"status": 2})  # Bad JWT


    MICRO2URL = "http://user_functions_container:5000/group_checker"
    r = requests.post(url=MICRO2URL, data={"username": permitted_user})
    user_groups = r.json()

    # Fetch groups associated with the document
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT group_name FROM document_groups WHERE file_name = ?", (file_name,))
    document_groups = [row[0] for row in cursor.fetchall()]
    conn.close()
    # return jsonify({"status": 2, "doc_groups": document_groups, "user_groups": user_groups})
    # Check if the user is part of any group that has access to the document
 
    if not any(group in user_groups for group in document_groups):
        return jsonify({"status": 3, "doc_groups": document_groups, "user_groups": user_groups})  # Not authorized to edit the document

    # Append text to the document
    with open(file_name, mode="a", newline='\n') as file:
        file.write(body)
        file.close()

    # Log the edit event
    MICRO2URL = "http://log_functions_container:5000/log_event"
    requests.post(url=MICRO2URL, data={"event": 'document_edit', "user": permitted_user, "filename": file_name})
    return jsonify({"status": 1})



@app.route('/document_groups', methods=['GET'])
def document_groups():
    args = request.args
    file_name = args.get('filename')

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT group_name FROM document_groups WHERE file_name = ?", (file_name,))
    groups = [row[0] for row in cursor.fetchall()]  # Get group names as a list
    conn.close()

    return jsonify(groups)


@app.route('/document_owner', methods=['GET'])
def document_owner():
    args = request.args
    file_name = args.get('filename')

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT created_by FROM documents WHERE file_name = ?", (file_name,))
    file_owner = cursor.fetchone()
    conn.close()

    doc_owner = file_owner[0]
    if doc_owner:
        return jsonify(doc_owner)
    else:
        return jsonify(None)


@app.route('/document_hash', methods=['GET'])
def document_hash():
    args = request.args 
    file_name = args.get('filename')

    # https://stackoverflow.com/questions/22058048/hashing-a-file-in-python
    with open(file_name, mode="rb") as file:
        file_hash = (hashlib.file_digest(file, "SHA256")).hexdigest()
        file.close()

    return jsonify(file_hash)
    


