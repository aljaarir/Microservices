import requests
import json
import os

try:
	
	URLCREATEUSERclear = "http://127.0.0.1:9000/clear"
	URLDOCCREATEclear = "http://127.0.0.1:9001/clear"
	# URLDOCSEARCHclear = "http://127.0.0.1:9002/clear"
	URLLOGclear = "http://127.0.0.1:9003/clear"
	r_clear = requests.get(url = URLLOGclear)
	r_clear = requests.get(url = URLCREATEUSERclear)
	# r_clear = requests.get(url = URLDOCSEARCHclear)
	r_clear = requests.get(url = URLDOCCREATEclear)

	URLCREATEUSER = "http://127.0.0.1:9000/create_user"
	URLLOGIN = "http://127.0.0.1:9000/login"
	URLDOCCREATE = "http://127.0.0.1:9001/create_document"
	URLDOCEDIT = "http://127.0.0.1:9001/edit_document"
	URLDOCSEARCH = "http://127.0.0.1:9002/search"
	URLLOG = "http://127.0.0.1:9003/view_log"


	PARAMS = {'first_name': 'james', 'last_name': 'mariani', 'username': 'james', 'email_address': 'j@a.com', 'password': 'Examplepassword1', 'group': 'instructors', 'salt': 'FE8x1gO+7z0B'}
	r = requests.post(url = URLCREATEUSER, data = PARAMS)
	data = r.json()
	if data['status'] != 1:
		quit()
	
	PARAMS = {'first_name': 'abigail', 'last_name': 'murray', 'username': 'abigail', 'email_address': 'a@a.com', 'password': 'Examplepassword1', 'group': 'instructors', 'salt': 'FE8x1gO+7z0B'}
	r = requests.post(url = URLCREATEUSER, data = PARAMS)
	data = r.json()
	if data['status'] != 1:
		quit()

	LOGINPARAMS = {'username': 'james', 'password': 'Examplepassword1'}
	r_login = requests.post(url = URLLOGIN, data = LOGINPARAMS)
	login_data = r_login.json()

	solution = {"status": 1, "jwt": 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJqYW1lcyJ9.d5425b8034f430475313408dc6494622c8f1a373a16275c46d44f47d8d35fd52'}
	for key in solution:
		if solution[key] != login_data[key]:
			quit()
	
	LOGINPARAMS = {'username': 'abigail', 'password': 'Examplepassword1'}
	r_login = requests.post(url = URLLOGIN, data = LOGINPARAMS)
	login_data = r_login.json()

	solution = {"status": 1, "jwt": 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJhYmlnYWlsIn0=.9f8f49704d3cc7e898730f0ee2a0d92813b4b196ba5b9c16219139ceb4d2aab7'}
	for key in solution:
		if solution[key] != login_data[key]:

			quit()

	print("Passed Create and Login user")

	CREATEDOCPARAMS = {'filename': 'a.txt', 'body': 'I will test project 3 better than I tested project 2', 'groups': json.dumps({'group1': 'instructors'})}
	r_create = requests.post(url = URLDOCCREATE, data = CREATEDOCPARAMS, headers={'Authorization': 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJqYW1lcyJ9.d5425b8034f430475313408dc6494622c8f1a373a16275c46d44f47d8d35fd52'})
	create_data = r_create.json()

	solution = {"status": 1}
	for key in solution:
		if solution[key] != create_data[key]:
			print("Failed Doc Creation")
			quit()
		else:
			print("Passed Doc Creation")
	
	

	EDITDOCPARAMS = {'filename': 'a.txt', 'body': '\nI promise I promise I promise to test better'}
	r_edit = requests.post(url = URLDOCEDIT, data = EDITDOCPARAMS, headers={'Authorization': 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJhYmlnYWlsIn0=.9f8f49704d3cc7e898730f0ee2a0d92813b4b196ba5b9c16219139ceb4d2aab7'})
	edit_data = r_edit.json()
	# print(edit_data)

	solution = {"status": 1}
	for key in solution:
		if solution[key] != edit_data[key]:
			print("Failed Doc Edit")
			quit()
		else:
			print("Passed Doc Edit")

	print("Passed Create and Edit Document")

	SEARCHDOCPARAMS = {'filename': 'a.txt'}
	r_search = requests.get(url = URLDOCSEARCH, params = SEARCHDOCPARAMS, headers={'Authorization': 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJqYW1lcyJ9.d5425b8034f430475313408dc6494622c8f1a373a16275c46d44f47d8d35fd52'})
	search_data = r_search.json()

	expected_dict = {'status': 1, 'data': {'filename': 'a.txt', 'owner': 'james', 'last_mod': 'abigail', 'total_mod': 2, 'hash': '58efaf17cbf28e6e01c47a3cad63a69f2a03f9ebc358ea859613378fd8ae5728'}}
	print(search_data)																	
	for x in expected_dict['data']:
		if expected_dict['data'][x] != search_data['data'][x]:
			quit()

	print("Passed Searching Test")

	LOGPARAMS = {'filename': 'a.txt'}
	r_log = requests.get(url = URLLOG, params = LOGPARAMS, headers={'Authorization': 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJqYW1lcyJ9.d5425b8034f430475313408dc6494622c8f1a373a16275c46d44f47d8d35fd52'})
	log_data = r_log.json()
	print(log_data)		

	log_dict = {1: {'event': 'document_creation', 'user': 'james', 'filename': 'a.txt'}, 2: {'event': 'document_edit', 'user': 'abigail', 'filename': 'a.txt'}, 3: {'event': 'document_search', 'user': 'james', 'filename': 'a.txt'}}
	expected = json.dumps({'status': 1, 'data': log_dict})
	expected_dict = json.loads(expected)

	for x in expected_dict['data']:
		for y in expected_dict['data'][x]:
			if expected_dict['data'][x][y] != log_data['data'][x][y]:
				quit()

	print('Passed Log Test')

	print('All Tests Passed')

except:
	print('Test Failed')
