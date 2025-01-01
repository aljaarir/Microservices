DROP TABLE IF EXISTS logs;

CREATE TABLE logs (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL, 
    user TEXT NOT NULL,        
    file_name TEXT    
);