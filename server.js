const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();

app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname)));

// ================= MYSQL CONNECTION (CLOUD & LOCAL READY - NIZAMI) =================
const db = mysql.createPool({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME || "nizami_behram_electronics",
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10
});

db.getConnection((err, connection) => {
    if (err) {
        console.error("MySQL qoşulma xətası:", err.message);
    } else {
        console.log("MySQL uğurla qoşuldu (nizami_behram_electronics)");
        connection.release();
    }
});

// ================= ISO 27001 AUDIT LOG HELPER =================
function writeAuditLog(userId, username, action, status, req) {
    const ipAddress = req.headers["x-forwarded-for"] || req.socket.remoteAddress || req.ip || "UNKNOWN";
    const sql = "INSERT INTO audit_logs (user_id, username, action, status, ip_address) VALUES (?, ?, ?, ?, ?)";
    db.query(sql, [userId, username, action, status, ipAddress], (err) => {
        if (err) console.error("Audit log yazılarkən xəta:", err.message);
    });
}

// ================= BRUTE-FORCE COOLDOWN MEXANİZMİ =================
const loginAttempts = new Map();
const MAX_ATTEMPTS = 3;          // Maksimum səhv cəhd sayı
const COOLDOWN_MS = 30 * 1000;   // 30 saniyə bloklama müddəti

// ================= REGISTER ENDPOINT =================
app.post("/register", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: "İstifadəçi adı və şifrə tələb olunur!" });
    }

    db.query("SELECT * FROM users WHERE username = ?", [username], async (err, results) => {
        if (err) return res.status(500).json({ message: "Server xətası baş verdi." });

        if (results.length > 0) {
            writeAuditLog(null, username, "REGISTER", "FAILED_USER_EXISTS", req);
            return res.status(409).json({ message: "Bu istifadəçi adı artıq mövcuddur!" });
        }

        try {
            const hashedPassword = await bcrypt.hash(password, 10);

            db.query(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                [username, hashedPassword],
                (insertErr, insertResult) => {
                    if (insertErr) return res.status(500).json({ message: "Qeydiyyat zamanı xəta baş verdi." });

                    writeAuditLog(insertResult.insertId, username, "REGISTER", "SUCCESS", req);
                    res.status(201).json({ message: "Qeydiyyat uğurla tamamlandı!" });
                }
            );
        } catch (hashError) {
            res.status(500).json({ message: "Kriptoqrafiya xətası." });
        }
    });
});

// ================= LOGIN ENDPOINT (COOLDOWN İLƏ) =================
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: "İstifadəçi adı və şifrəni daxil edin!" });
    }

    const key = username.toLowerCase();
    const now = Date.now();
    const attemptData = loginAttempts.get(key) || { count: 0, lockUntil: 0 };

    // Əgər istifadəçi hazırda Cooldown (blok) rejimindədirsə:
    if (attemptData.lockUntil > now) {
        const remainingSeconds = Math.ceil((attemptData.lockUntil - now) / 1000);
        writeAuditLog(null, username, "LOGIN", "BLOCKED_COOLDOWN", req);
        return res.status(429).json({
            message: `Çox sayda uğursuz cəhd! ${remainingSeconds} saniyə gözləyin.`,
            remainingSeconds
        });
    }

    db.query("SELECT * FROM users WHERE username = ?", [username], async (err, results) => {
        if (err) return res.status(500).json({ message: "Server xətası baş verdi." });

        if (results.length === 0) {
            writeAuditLog(null, username, "LOGIN", "FAILED_USER_NOT_FOUND", req);
            return res.status(401).json({ message: "İstifadəçi tapılmadı!" });
        }

        const user = results[0];
        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            attemptData.count += 1;

            if (attemptData.count >= MAX_ATTEMPTS) {
                attemptData.lockUntil = now + COOLDOWN_MS;
                attemptData.count = 0; // Növbəti dövr üçün sıfırla
                loginAttempts.set(key, attemptData);

                writeAuditLog(user.id, username, "LOGIN", "BLOCKED_COOLDOWN", req);
                return res.status(429).json({
                    message: "3 dəfə səhv şifrə daxil edildi! 30 saniyəlik blok (Cooldown) aktivləşdi.",
                    remainingSeconds: 30
                });
            }

            loginAttempts.set(key, attemptData);
            const left = MAX_ATTEMPTS - attemptData.count;
            writeAuditLog(user.id, username, "LOGIN", "FAILED_WRONG_PASSWORD", req);
            return res.status(401).json({ message: `Şifrə yanlışdır! Qalan cəhd: ${left}` });
        }

        // Uğurlu girişdə səhv cəhdləri sıfırla
        loginAttempts.delete(key);
        writeAuditLog(user.id, username, "LOGIN", "SUCCESS", req);
        res.status(200).json({ message: "Giriş uğurludur!", username: user.username });
    });
});

// ================= CANLI AUDIT MONITORINQ ENDPOINT-I =================
app.get("/api/audit-logs", (req, res) => {
    db.query("SELECT * FROM audit_logs ORDER BY created_at DESC", (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`Behram Electronics Inc. Server running on port ${PORT} - Audit Logs & Cooldown Active!`);
});