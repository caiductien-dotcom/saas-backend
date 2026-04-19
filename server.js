const http = require("http");
const fs = require("fs");
const fsPromises = require("fs").promises;
const path = require("path");
const bcrypt = require("bcrypt"); // thu vien ma hoa mat khau

const Port = 3000;
const USER_FILE = path.join(__dirname, "user.txt");
const LOG_FILE = path.join(__dirname, "server.log");

// Quan ly otp tren ram
const otpStorage = new Map(); 

//ham ghi log vao file
const writeLog = (msg) => {
    const entry = `[${new Date().toLocaleString()}] ${msg}\n`;
    fs.appendFileSync(LOG_FILE, entry);
};

const server = http.createServer((req, res) => {
    // Setup CORS 
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (req.method === "OPTIONS") return res.end();

    let body = "";
    req.on("data", chunk => { body += chunk.toString(); });
    req.on("end", async () => {
        const payload = body ? JSON.parse(body) : {};
        const { email, password, otp, newPassword } = payload;

        // 1. api dang ky 
        if (req.url === "/api/signup" && req.method === "POST") {
            const data = await fsPromises.readFile(USER_FILE, "utf-8").catch(() => "");
            
            // kiem tra trung email
            if (data.includes(`|${email}|`)) {
                return res.end(JSON.stringify({ success: false, message: "Email đã tồn tại" }));
            }

            const id = Date.now(); //tao id don gian 
            const hash = await bcrypt.hash(password, 10); // ma hoa mat khau
            
            await fsPromises.appendFile(USER_FILE, `${id}|${email}|${hash}\n`);
            writeLog(`SIGNUP_SUCCESS: ${email}`);
            res.end(JSON.stringify({ success: true, message: "Đăng ký thành công" }));
        }

        // 2. API dang nhap
        else if (req.url === "/api/login" && req.method === "POST") {
            const data = await fsPromises.readFile(USER_FILE, "utf-8").catch(() => "");
            const userLine = data.split("\n").find(line => line.includes(`|${email}|`));

            if (userLine) {
                const savedHash = userLine.split("|")[2].trim();
                // so sanh mat khau tho voi hash
                const isMatch = await bcrypt.compare(password, savedHash);
                if (isMatch) {
                    writeLog(`LOGIN_SUCCESS: ${email}`);
                    return res.end(JSON.stringify({ success: true, message: "Đăng nhập thành công" }));
                }
            }
            res.end(JSON.stringify({ success: false, message: "Sai tài khoản hoặc mật khẩu" }));
        }

        // 3. API quen mk
        else if (req.url === "/api/forgot-password" && req.method === "POST") {
            const code = Math.floor(1000 + Math.random() * 9000).toString();
            // Luu ma kem thoi han
            otpStorage.set(email, { code, expire: Date.now() + 5 * 60 * 1000 });

            writeLog(`OTP_SEND: ${email} - CODE: ${code}`);
            res.end(JSON.stringify({ success: true, message: "Mã OTP của bạn là: " + code }));
        }

        // 4. API xac thuc otp
        else if (req.url === "/api/verify-otp" && req.method === "POST") {
            const record = otpStorage.get(email);
            
            if (record && record.code === otp && Date.now() < record.expire) {
                res.end(JSON.stringify({ success: true, message: "OTP hợp lệ" }));
            } else {
                res.end(JSON.stringify({ success: false, message: "OTP sai hoặc đã hết hạn" }));
            }
        }

        // 5. API doi mk
        else if (req.url === "/api/reset-password" && req.method === "POST") {
            const record = otpStorage.get(email);
            if (record && record.code === otp) {
                const data = await fsPromises.readFile(USER_FILE, "utf-8");
                const newHash = await bcrypt.hash(newPassword, 10); // ma hoa mk moi

                const updatedData = data.split("\n").map(line => {
                    if (line.includes(`|${email}|`)) {
                        const parts = line.split("|");
                        return `${parts[0]}|${email}|${newHash}`;
                    }
                    return line;
                }).join("\n");

                await fsPromises.writeFile(USER_FILE, updatedData);
                otpStorage.delete(email); //xoa otp sau khi doi mk
                writeLog(`RESET_PASS: ${email}`);
                res.end(JSON.stringify({ success: true, message: "Đã đổi mật khẩu" }));
            } else {
                res.end(JSON.stringify({ success: false, message: "Yêu cầu không hợp lệ" }));
            }
        }
        
        else {
            res.writeHead(404);
            res.end(JSON.stringify({ success: false, message: "API Not Found" }));
        }
    });
});

server.listen(Port, () => {
    console.log(`Server BE đang chạy tại http://localhost:${Port}`);
    writeLog("SERVER_START");
});