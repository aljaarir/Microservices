import requests
import json
 
URLCREATEUSERclear = "http://127.0.0.1:9000/clear"
URLDOCCREATEclear = "http://127.0.0.1:9001/clear"
URLDOCSEARCHclear = "http://127.0.0.1:9002/clear"
URLLOGclear = "http://127.0.0.1:9003/clear"
r_clear = requests.get(url = URLLOGclear)
r_clear = requests.get(url = URLCREATEUSERclear)
r_clear = requests.get(url = URLDOCSEARCHclear)
r_clear = requests.get(url = URLDOCCREATEclear)

URL = "http://127.0.0.1:9000/create_user"
PARAMS = {'first_name': 'James', 'last_name': 'Mariani', 'username': 'james.mariani', 'email_address': 'james@mariani.com', 'password': 'Examplepassword1', 'group': 'instructors', 'salt': 'FE8x1gO+7z0B'}

r = requests.post(url = URL, data = PARAMS)
data = r.json()


solution = {"status": 1, "pass_hash": "9060e88fe7f9a95839a19926d517a442da58f47c48edc2f37e1c3aea5f8956fc"}

for key in solution:
	if solution[key] != data[key]:
		print('Test Failed')
		quit()
		
print('Test Passed')
