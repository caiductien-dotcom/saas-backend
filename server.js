const http = require("http");
const fs = require("fs");
const fsPromises = require("fs").promises;
const path = require("path");

const Port = 3000;
const USER_FILE = path.join(__dirname, "user.txt");
const OTP_FILE = path.join(__dirname, "otp.txt");

const server = http.createServer((req, res) => {
    // Setup CORS
    res.setHeader("Access-Control-Allow-Origin", "*"); 
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (req.method === "OPTIONS") {
        res.writeHead(200);
        res.end();
        return;
    }
    
    // Redirect về Frontend
    if (req.url === "/" && req.method === "GET") {
        console.log("Đang chuyển hướng sang trang Login...");
        res.writeHead(302, {
            'Location': 'http://localhost:5500/sass-frontend/pages/login2.html'
        });
        res.end();
        return; 
    }

    let body = "";
    req.on("data", chunk => { body += chunk.toString(); });

    req.on("end", async () => { 
        console.log("Đang gọi URL:", req.url, "| Phương thức:", req.method);
        console.log("Dữ liệu nhận được:", body);
        const payload = body ? JSON.parse(body) : {};

        // 1. API Đăng ký
        if (req.url === "/api/signup" && req.method === "POST") {
            const { email, password } = payload;
            const data = await fsPromises.readFile(USER_FILE, "utf-8").catch(() => "");
            const users = data.split("\n").filter(Boolean);
            
            if (users.some(u => u.split(",")[0] === email)) {
                res.writeHead(200, { "Content-Type": "application/json" });
                res.end(JSON.stringify({ success: false, message: "Email đã tồn tại" }));
            } else {
                await fsPromises.appendFile(USER_FILE, `${email},${password}\n`);
                res.writeHead(200, { "Content-Type": "application/json" });
                res.end(JSON.stringify({ success: true, message: "Đăng ký thành công" }));
            }
        } 

        // 2. API Đăng nhập
        else if (req.url === "/api/login" && req.method === "POST") {
            const { email, password } = payload;
            const data = await fsPromises.readFile(USER_FILE, "utf-8").catch(() => "");
            const users = data.split("\n").filter(Boolean);
            const found = users.find(u => u === `${email},${password}`);
            
            res.writeHead(200, { "Content-Type": "application/json" });
            if (found) {
                res.end(JSON.stringify({ success: true, message: "Đăng nhập thành công" }));
            } else {
                res.end(JSON.stringify({ success: false, message: "Sai tài khoản hoặc mật khẩu" }));
            }
        }

        // 3. API Quên mật khẩu - Tạo mã
        else if (req.url === "/api/forgot-password" && req.method === "POST") {
            const { email } = payload;
            const otp = Math.floor(1000 + Math.random() * 9000).toString();
            
            console.log(`\n[DEV] EMAIL: ${email} | MÃ OTP CỦA ÔNG ĐÂY: ${otp}\n`);

            await fsPromises.writeFile(OTP_FILE, `${email},${otp}`);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ 
                success: true, 
                message: "Mã OTP của bạn là: " + otp
            }));
        }

        // 4. API Xác thực OTP
        else if (req.url === "/api/verify-otp" && req.method === "POST") {
            const { email, otp } = payload;
            try {
                const otpRaw = await fsPromises.readFile(OTP_FILE, "utf-8");
                const [savedEmail, savedOtp] = otpRaw.split(",");

                res.writeHead(200, { "Content-Type": "application/json" });
                if (email === savedEmail && otp === savedOtp) {
                    res.end(JSON.stringify({ success: true, message: "OTP chính xác!" }));
                } else {
                    res.end(JSON.stringify({ success: false, message: "Mã OTP không đúng" }));
                }
            } catch (err) {
                res.writeHead(200, { "Content-Type": "application/json" });
                res.end(JSON.stringify({ success: false, message: "OTP đã hết hạn hoặc chưa tạo" }));
            }
        }

        // 5. API Đổi mật khẩu mới
        else if (req.url === "/api/reset-password" && req.method === "POST") {
            const { email, otp, newPassword } = payload;
            try {
                const otpRaw = await fsPromises.readFile(OTP_FILE, "utf-8");
                const [savedEmail, savedOtp] = otpRaw.split(",");

                res.writeHead(200, { "Content-Type": "application/json" });
                if (email === savedEmail && otp === savedOtp) {
                    const userData = await fsPromises.readFile(USER_FILE, "utf-8");
                    let users = userData.split("\n").filter(Boolean);
                    users = users.map(line => {
                        const [e, p] = line.split(",");
                        return e === email ? `${e},${newPassword}` : line;
                    });

                    await fsPromises.writeFile(USER_FILE, users.join("\n") + "\n");
                    await fsPromises.unlink(OTP_FILE).catch(() => {}); 
                    res.end(JSON.stringify({ success: true, message: "Đổi mật khẩu thành công!" }));
                } else {
                    res.end(JSON.stringify({ success: false, message: "OTP không hợp lệ" }));
                }
            } catch (err) {
                res.writeHead(200, { "Content-Type": "application/json" });
                res.end(JSON.stringify({ success: false, message: "Lỗi hệ thống" }));
            }
        }
        
        // 6. 404
        else {
            res.writeHead(404, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ success: false, message: "API không tồn tại!" }));
        }
    });
});

server.listen(Port, () => {
    console.log(`Server đang chạy tại http://localhost:${Port}`);
});