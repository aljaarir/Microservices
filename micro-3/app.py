import sqlite3
import os
import json
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# No dB needed

@app.route('/search', methods=['GET'])
def search():
      args = request.args
      file_name = args.get('filename')
      stored_jwt = request.headers['Authorization']

      MICRO2URL = "http://user_functions_container:5000/verify"
      r = requests.post(url = MICRO2URL, data={"jwt": stored_jwt})
      permitted_user = r.json()

      if not permitted_user:
            return jsonify({"status": 2}) # Bad JWT
      
      MICRO2URL = "http://user_functions_container:5000/group_checker"
      r = requests.post(url=MICRO2URL, data={"username": permitted_user})  
      user_group = r.json()
      
      MICRO2URL = "http://document_functions_container:5000/document_groups"
      r = requests.get(url=MICRO2URL, params={"filename": file_name})
      total_groups = r.json()
      app.logger.info(user_group)
      app.logger.info(total_groups)
      
      if not any(group in user_group for group in total_groups):
            return jsonify({"status": 3,"data": "NULL"}) # Not able to access documents
      
      # You will have the filename already sent in, and you will likely need to get the owner from the document
      # management microservice, the hash from the document management microservice, and
      # the last modified and total number of modifications from the logging microservice
      # 1. owner, hash from micro-2
      # 2. last-modified and total modifications from log
      MICRO2URL = "http://document_functions_container:5000/document_owner"
      r = requests.get(url=MICRO2URL, params={"filename": file_name})
      file_owner = r.json()

      MICRO2URL = "http://document_functions_container:5000/document_hash"
      r = requests.get(url=MICRO2URL, params={"filename": file_name})
      file_hash = r.json()

      MICRO2URL = "http://log_functions_container:5000/total_mod"
      r = requests.get(url=MICRO2URL, params={"filename": file_name})
      total_modifications = r.json()   

      MICRO2URL = "http://log_functions_container:5000/last_mod"
      r = requests.get(url=MICRO2URL, params={"filename": file_name})
      last_modified = r.json()
      
      # Log the edit event
      MICRO2URL = "http://log_functions_container:5000/log_event"
      requests.post(url=MICRO2URL, data={"event": 'document_search', "user": permitted_user, "filename": file_name})


      return jsonify({
        "status": 1,
        "data": {
            "filename": file_name,
            "owner": file_owner,
            "last_mod": last_modified,
            "total_mod": total_modifications,
            "hash": file_hash
        }
    })
      

    