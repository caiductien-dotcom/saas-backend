require('dotenv').config();
const http = require("http");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const fs = require("fs");

const SECRET_KEY = process.env.JWT_SECRET || "36RAUMATHANHOA";
const Port = process.env.PORT || 3000;
const LOG_FILE = "server.log";

mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log(" DATABASE Hoat dong!"))
    .catch(err => console.error("Loi ket noi:", err));

const userSchema = new mongoose.Schema({
    name:     { type: String, required: true },
    email:    { type: String, required: true, unique: true },
    password: { type: String, required: true },
    score:    { type: Number, default: 0 },
    otp:      { code: String, expire: Date }
});
const User = mongoose.model('User', userSchema);

const matchSchema = new mongoose.Schema({
    userId:   { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    opponent: { type: String, default: "AI" },
    mode:     { type: String, enum: ["easy", "hard"], required: true },
    result:   { type: String, enum: ["win", "lose"], required: true },
    points:   { type: Number, required: true },
    playedAt: { type: Date, default: Date.now }
});
const Match = mongoose.model('Match', matchSchema);
function sendJSON(res, statusCode, data) {
    res.writeHead(statusCode, { "Content-Type": "application/json" });
    res.end(JSON.stringify(data));
}

function authMiddleware(req, res) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        sendJSON(res, 401, { success: false, message: "No token provided" });
        return null;
    }

    const token = authHeader.split(" ")[1];

    try {
        return jwt.verify(token, SECRET_KEY);
    } catch (err) {
        sendJSON(res, 401, { success: false, message: "Token expired or invalid" });
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
        let payload = {};
        try {
            payload = body ? JSON.parse(body) : {};
        } catch (e) {
            return sendJSON(res, 400, { success: false, message: "Invalid request body" });
        }

        const { name, email, password, otp, newPassword } = payload;

        // 1. dang ky
        if (req.url === "/api/signup" && req.method === "POST") {
            if (!name || !email || !password) {
                return sendJSON(res, 400, { success: false, message: "Name, email and password are required" });
            }
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                writeLog(`SIGNUP_FAILED: Email already exists - ${email}`);
                return sendJSON(res, 200, { success: false, message: "Email already exists" });
            }
            const hash = await bcrypt.hash(password, 10);
            await new User({ name, email, password: hash }).save();
            writeLog(`SIGNUP_SUCCESS: ${email} (${name})`);
            return sendJSON(res, 200, { success: true, message: "Signup successful" });
        }

        // 2. dang nhap
        else if (req.url === "/api/login" && req.method === "POST") {
            const user = await User.findOne({ email });
            if (user) {
                const isMatch = await bcrypt.compare(password, user.password);
                if (isMatch) {
                    const token = jwt.sign({ id: user._id }, SECRET_KEY, { expiresIn: '24h' });
                    writeLog(`LOGIN_SUCCESS: ${email}`);
                    return sendJSON(res, 200, { success: true, message: "Login successful", token });
                }
            }
            writeLog(`LOGIN_FAILED: ${email}`);
            return sendJSON(res, 200, { success: false, message: "Invalid email or password" });
        }

        // 3. quen mat khau
        else if (req.url === "/api/forgot-password" && req.method === "POST") {
            const user = await User.findOne({ email });
            if (!user) return sendJSON(res, 200, { success: false, message: "Email not found" });
            const code = Math.floor(1000 + Math.random() * 9000).toString();
            user.otp = { code, expire: new Date(Date.now() + 60 * 1000) };
            await user.save();
            writeLog(`OTP_SENT: ${email} - CODE: ${code}`);
            return sendJSON(res, 200, { success: true, message: "Your OTP code is: " + code });
        }

        // 3.5 gui lai otp
        else if (req.url === "/api/resend-otp" && req.method === "POST") {
            const user = await User.findOne({ email });
            if (!user) return sendJSON(res, 200, { success: false, message: "User not found" });
            const code = Math.floor(1000 + Math.random() * 9000).toString();
            user.otp = { code, expire: new Date(Date.now() + 60 * 1000) };
            await user.save();
            writeLog(`OTP_RESEND: ${email} - NEW_CODE: ${code}`);
            return sendJSON(res, 200, { success: true, message: "New OTP sent: " + code });
        }

        // 4. xac thuc otp
        else if (req.url === "/api/verify-otp" && req.method === "POST") {
            const user = await User.findOne({ email });
            if (!user || !user.otp || user.otp.code !== otp || Date.now() > user.otp.expire) {
                writeLog(`OTP_VERIFY_FAILED: ${email}`);
                return sendJSON(res, 200, { success: false, message: "Invalid or expired OTP" });
            }
            writeLog(`OTP_VERIFY_SUCCESS: ${email}`);
            return sendJSON(res, 200, { success: true, message: "OTP verified!" });
        }

        // 5. doi mat khau
        else if (req.url === "/api/reset-password" && req.method === "POST") {
            const user = await User.findOne({ email });
            if (user && user.otp && user.otp.code === String(otp) && Date.now() < user.otp.expire) {
                user.password = await bcrypt.hash(newPassword, 10);
                user.otp = undefined;
                await user.save();
                writeLog(`PASSWORD_RESET_SUCCESS: ${email}`);
                return sendJSON(res, 200, { success: true, message: "Password changed successfully" });
            }
            return sendJSON(res, 200, { success: false, message: "OTP invalid or expired" });
        }

        // 6. luu ket qua tran dau
        else if (req.url === "/api/save-match" && req.method === "POST") {
            const decoded = authMiddleware(req, res);
            if (!decoded) return;

            const { mode, result } = payload;
            if (!["easy", "hard"].includes(mode)) {
                return sendJSON(res, 400, { success: false, message: "Invalid mode. Use 'easy' or 'hard'" });
            }
            if (!["win", "lose"].includes(result)) {
                return sendJSON(res, 400, { success: false, message: "Invalid result. Use 'win' or 'lose'" });
            }

            const points = result === "win" ? (mode === "hard" ? 3 : 1) : 0;
            const user = await User.findByIdAndUpdate(
                decoded.id,
                { $inc: { score: points } },
                { new: true }
            );
            if (!user) return sendJSON(res, 404, { success: false, message: "User not found" });

            await new Match({ userId: decoded.id, opponent: "AI", mode, result, points }).save();
            writeLog(`MATCH_SAVED: ${user.email} vs AI | mode=${mode} | result=${result} | +${points}pts => total: ${user.score}`);
            return sendJSON(res, 200, {
                success: true,
                message: result === "win" ? `+${points} point${points > 1 ? "s" : ""} added` : "Match saved, no points awarded",
                score: user.score
            });
        }

        // 7. lay lich su tran dau
        else if (req.url === "/api/match-history" && req.method === "GET") {
            const decoded = authMiddleware(req, res);
            if (!decoded) return;

            const matches = await Match.find({ userId: decoded.id })
                .sort({ playedAt: -1 })
                .limit(20);
            return sendJSON(res, 200, { success: true, matches });
        }

        // 8. lay thong tin user + check token
        else if (req.url === "/api/me" && req.method === "GET") {
            const decoded = authMiddleware(req, res);
            if (!decoded) return;

            const user = await User.findById(decoded.id).select("name score");
            if (!user) return sendJSON(res, 404, { success: false, message: "User not found" });

            return sendJSON(res, 200, { success: true, name: user.name, score: user.score });
        }

        else {
            return sendJSON(res, 404, { success: false, message: "Not Found" });
        }
    });
});

server.listen(Port, () => {
    console.log(` The server is running at the server ${Port}`);
    writeLog("SERVER_STARTED");
});