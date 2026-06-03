// doc bien tu moi trg file env
require('dotenv').config();
const http = require("http");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const fs = require("fs");

const SECRET_KEY = process.env.JWT_SECRET || "36RAUMATHANHOA";
const Port = process.env.PORT || 3000;
const LOG_FILE = "server.log";

// ket noi MongoDB Atlas
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log(" DATABASE Hoat dong!"))
    .catch(err => console.error("Loi ket noi:", err));

// cau truc document user trong database
const userSchema = new mongoose.Schema({
    email:    { type: String, required: true, unique: true },
    password: { type: String, required: true },
    score:    { type: Number, default: 0 },
    otp:      { code: String, expire: Date }
});
const User = mongoose.model('User', userSchema);

function authMiddleware(req, res) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
            success: false,
            message: "No token provided"
        }));
        return null;
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        return decoded;
    } catch (err) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
            success: false,
            message: "Token expired or invalid"
        }));
        return null;
    }
}

const writeLog = (msg) => {
    const timestamp = new Date().toISOString();
    const entry = `[${timestamp}] ${msg}\n`;
    fs.appendFileSync(LOG_FILE, entry);
    console.log(`[LOG] ${msg}`);
};

const server = http.createServer((req, res) => {
    // Cau hinh CORS thong thoang cho phep ca Live Server lan GitHub Pages ket noi
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

    if (req.method === "OPTIONS") {
        res.writeHead(204);
        return res.end();
    }

    let body = "";
    req.on("data", chunk => { body += chunk.toString(); });
    req.on("end", async () => {
        // JSON.parse co the throw SyntaxError nen bat buoc dung try/catch o day
        let payload = {};
        try {
            payload = body ? JSON.parse(body) : {};
        } catch (e) {
            res.writeHead(400, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({ success: false, message: "Invalid request body" }));
        }
        
        const { email, password, otp, newPassword } = payload;

        // Thiet lap mac dinh tra ve dữ lieu dang JSON cho moi api dung duoi
        res.writeHead(200, { "Content-Type": "application/json" });

        // 1. dang ky
        if (req.url === "/api/signup" && req.method === "POST") {
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                writeLog(`SIGNUP_FAILED: Email already exists - ${email}`);
                return res.end(JSON.stringify({ success: false, message: "Email already exists" }));
            }

            const hash = await bcrypt.hash(password, 10);
            await new User({ email, password: hash }).save();

            writeLog(`SIGNUP_SUCCESS: ${email}`);
            return res.end(JSON.stringify({ success: true, message: "Signup successful" }));
        }

        // 2. dang nhap
        else if (req.url === "/api/login" && req.method === "POST") {
            const user = await User.findOne({ email });
            if (user) {
                const isMatch = await bcrypt.compare(password, user.password);
                if (isMatch) {
                    const token = jwt.sign({ id: user._id }, SECRET_KEY, { expiresIn: '24h' });
                    writeLog(`LOGIN_SUCCESS: ${email}`);
                    return res.end(JSON.stringify({ 
                        success: true,
                        message: "Login successful",
                        token
                    }));
                }
            }
            writeLog(`LOGIN_FAILED: ${email}`);
            return res.end(JSON.stringify({ success: false, message: "Invalid email or password" }));
        }

        // 3. quen mat khau
        else if (req.url === "/api/forgot-password" && req.method === "POST") {
            const user = await User.findOne({ email });
            if (!user) return res.end(JSON.stringify({ success: false, message: "Email not found" }));

            const code = Math.floor(1000 + Math.random() * 9000).toString();
            user.otp = { code, expire: new Date(Date.now() + 60 * 1000) };
            await user.save();

            writeLog(`OTP_SENT: ${email} - CODE: ${code}`);
            return res.end(JSON.stringify({ success: true, message: "Your OTP code is: " + code }));
        }

        // 3.5 gui lai otp
        else if (req.url === "/api/resend-otp" && req.method === "POST") {
            const user = await User.findOne({ email });
            if (!user) return res.end(JSON.stringify({ success: false, message: "User not found" }));

            const code = Math.floor(1000 + Math.random() * 9000).toString();
            user.otp = { code, expire: new Date(Date.now() + 60 * 1000) };
            await user.save();

            writeLog(`OTP_RESEND: ${email} - NEW_CODE: ${code}`);
            return res.end(JSON.stringify({ success: true, message: "New OTP sent: " + code }));
        }

        // 4. xac thuc otp
        else if (req.url === "/api/verify-otp" && req.method === "POST") {
            const user = await User.findOne({ email });
            if (!user || !user.otp || user.otp.code !== otp || Date.now() > user.otp.expire) {
                writeLog(`OTP_VERIFY_FAILED: ${email}`);
                return res.end(JSON.stringify({ success: false, message: "Invalid or expired OTP" }));
            }

            writeLog(`OTP_VERIFY_SUCCESS: ${email}`);
            return res.end(JSON.stringify({ success: true, message: "OTP verified!" }));
        }

        // 5. doi mat khau
        else if (req.url === "/api/reset-password" && req.method === "POST") {
            const user = await User.findOne({ email });
            if (user && user.otp && user.otp.code === String(otp) && Date.now() < user.otp.expire) {
                user.password = await bcrypt.hash(newPassword, 10);
                user.otp = undefined; 
                await user.save();

                writeLog(`PASSWORD_RESET_SUCCESS: ${email}`);
                return res.end(JSON.stringify({ success: true, message: "Password changed successfully" }));
            } else {
                return res.end(JSON.stringify({ success: false, message: "OTP invalid or expired" }));
            }
        }

        else {
            res.writeHead(404, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({ success: false, message: "Not Found" }));
        }
    });
});

server.listen(Port, () => {
    console.log(` The server is running at the server ${Port}`);
    writeLog("SERVER_STARTED");
});