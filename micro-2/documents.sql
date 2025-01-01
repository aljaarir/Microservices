DROP TABLE IF EXISTS documents;
DROP TABLE IF EXISTS document_groups;

CREATE TABLE documents (
   file_name TEXT PRIMARY KEY,  
   body TEXT,      
   created_by TEXT NOT NULL
);

CREATE TABLE document_groups (
   file_name TEXT NOT NULL,
   group_name TEXT NOT NULL,
   FOREIGN KEY (file_name) REFERENCES documents (file_name) ON DELETE CASCADE
);
