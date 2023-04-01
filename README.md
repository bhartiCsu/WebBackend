# WebBackend

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50),
    password VARCHAR(200),
    email VARCHAR(100),
    role VARCHAR(10) DEFAULT 'user',
    signup_date DATETIME DEFAULT CURRENT_TIMESTAMP
);
