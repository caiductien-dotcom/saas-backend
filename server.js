//đọc biến từ môi trg file env
require('dotenv').config();
const http = require("http");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const fs = require("fs");

const Port = process.env.PORT || 3000;
const LOG_FILE = "server.log";

// ket noi MongoDB Atlas
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log(" DATABASE Hoạt động!"))
    .catch(err => console.error("Lỗi kết nối:", err));

// cấu trúc document user trong database
const userSchema = new mongoose.Schema({
    email:    { type: String, required: true, unique: true },
    password: { type: String, required: true },
    score:    { type: Number, default: 0 },
    otp:      { code: String, expire: Date }
});
const User = mongoose.model('User', userSchema);

const writeLog = (msg) => {
    const timestamp = new Date().toISOString();
    const entry = `[${timestamp}] ${msg}\n`;
    fs.appendFileSync(LOG_FILE, entry);
    console.log(`[LOG] ${msg}`);
};

const server = http.createServer((req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

    if (req.method === "OPTIONS") 
        return res.end();

    let body = "";
    req.on("data", chunk => { body += chunk.toString(); });
    req.on("end", async () => {
        // JSON.parse có thể throw SyntaxError nên bắt buộc dùng try/catch ở đây
        let payload = {};
        try {
            payload = body ? JSON.parse(body) : {};
        } catch (e) {
            res.writeHead(400);
            return res.end(JSON.stringify({ success: false, message: "Invalid request body" }));
        }
        const { email, password, otp, newPassword } = payload;

        // 1.dang ki
        if (req.url === "/api/signup" && req.method === "POST") {
            // tim email trong db
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                writeLog(`SIGNUP_FAILED: Email already exists - ${email}`);
                return res.end(JSON.stringify({ success: false, message: "Email already exists" }));
            }

            const hash = await bcrypt.hash(password, 10);
            // luu user moi vao db
            await new User({ email, password: hash }).save();

            writeLog(`SIGNUP_SUCCESS: ${email}`);
            return res.end(JSON.stringify({ success: true, message: "Signup successful" }));
        }

        // 2.dang nhap
        else if (req.url === "/api/login" && req.method === "POST") {
            // tim user trong db
            const user = await User.findOne({ email });
            if (user) {
                const isMatch = await bcrypt.compare(password, user.password);
                //dung de tao jwt sau khi user dang nhap dung mk
                if (isMatch) {
                    // Dung id MongoDB lam payload JWT
                    //tao jwt token bang thu vien auth0
                    const token = jwt.sign({ id: user._id }, 
                        process.env.JWT_SECRET, 
                        { expiresIn: '24h' });
                    writeLog(`LOGIN_SUCCESS: ${email}`);
                    // them "return" de tranh gui response 2 lan, them "message" de frontend khong bi undefined
                    return res.end(JSON.stringify({ 
                        success: true,
                        message: "Login successful",
                        token, 
                        redirect: "https://caiductien-dotcom.github.io/WEB-BASED-BATTLESHIP-GAME/" 
                    }));
                }
            }
            writeLog(`LOGIN_FAILED: ${email}`);
            return res.end(JSON.stringify({ success: false, message: "Invalid email or password" }));
        }

        // 3.quen mk
        else if (req.url === "/api/forgot-password" && req.method === "POST") {
            const user = await User.findOne({ email });
            if (!user) return res.end(JSON.stringify({ success: false, message: "Email not found" }));

            const code = Math.floor(1000 + Math.random() * 9000).toString();
            // Luu OTP vào document user trong DB
            user.otp = { code, expire: new Date(Date.now() + 60 * 1000) };
            await user.save();

            writeLog(`OTP_SENT: ${email} - CODE: ${code}`);
            return res.end(JSON.stringify({ success: true, message: "Your OTP code is: " + code }));
        }

        // 3.5 gui lai otp
        else if (req.url === "/api/resend-otp" && req.method === "POST") {
            const user = await User.findOne({ email });
            if (!user) 
                return res.end(JSON.stringify({ success: false, message: "User not found" }));

            const code = Math.floor(1000 + Math.random() * 9000).toString();
            //ghi de otp moi vao db
            user.otp = { code, expire: new Date(Date.now() + 60 * 1000) };
            await user.save();

            writeLog(`OTP_RESEND: ${email} - NEW_CODE: ${code}`);
            return res.end(JSON.stringify({ success: true, message: "New OTP sent: " + code }));
        }

        // 4.xac thuc otp
        else if (req.url === "/api/verify-otp" && req.method === "POST") {
            // lay user tu db de doc otp da luu
            const user = await User.findOne({ email });
            if (!user || !user.otp || user.otp.code !== otp || Date.now() > user.otp.expire) {
                writeLog(`OTP_VERIFY_FAILED: ${email}`);
                return res.end(JSON.stringify({ success: false, message: "Invalid or expired OTP" }));
            }

            writeLog(`OTP_VERIFY_SUCCESS: ${email}`);
            return res.end(JSON.stringify({ success: true, message: "OTP verified!" }));
        }

        // 5.doi mk
        else if (req.url === "/api/reset-password" && req.method === "POST") {
            // doi pass(tim trong email)
            const user = await User.findOne({ email });
            if (user && user.otp && user.otp.code === String(otp) && Date.now() < user.otp.expire) {
                user.password = await bcrypt.hash(newPassword, 10);
                user.otp = undefined; // xoa otp khi dung xong
                await user.save();

                writeLog(`PASSWORD_RESET_SUCCESS: ${email}`);
                return res.end(JSON.stringify({ success: true, message: "Password changed successfully" }));
            } else {
                return res.end(JSON.stringify({ success: false, message: "Session invalid or expired" }));
            }
        }

        else {
            res.writeHead(404);
            return res.end(JSON.stringify({ success: false, message: "Not Found" }));
        }
    });
});
server.listen(Port, () => {
    console.log(` Server đang chạy tại cổng ${Port}`);
    writeLog("SERVER_STARTED");
});