CREATE DATABASE IF NOT EXISTS nizami_behram_electronics CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE nizami_behram_electronics;

-- İstifadəçilər cədvəli (Parollar bcrypt hash formatında saxlanılır)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ISO 27001 standartına uyğun Təhlükəsizlik Audit Jurnalı cədvəli
CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    username VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    status VARCHAR(100) NOT NULL,
    ip_address VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);