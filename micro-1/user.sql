DROP TABLE IF EXISTS users;

CREATE TABLE users (
    first_name TEXT NOT NULL,               
    last_name TEXT NOT NULL,                
    username TEXT UNIQUE NOT NULL,          
    email TEXT NOT NULL PRIMARY KEY,            
    password_hash TEXT NOT NULL,    
    group_list TEXT NOT NULL,        
    salt TEXT NOT NULL            
);

