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
    const timestamp = new Date().toISOString();
    const entry = `[${timestamp}] ${msg}\n`;
    fs.appendFileSync(LOG_FILE, entry);
    console.log(`[LOG] ${msg}`); // In ra terminal de theo doi
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
                writeLog(`SIGNUP_FAILED: Email already exists - ${email}`);
                return res.end(JSON.stringify({ success: false, message: "Email already exists" }));
            }

            const id = Date.now(); //tao id don gian 
            const hash = await bcrypt.hash(password, 10); // ma hoa mat khau
            
            await fsPromises.appendFile(USER_FILE, `${id}|${email}|${hash}\n`);
            writeLog(`SIGNUP_SUCCESS: ${email}`);
            res.end(JSON.stringify({ success: true, message: "Signup successful" }));
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
                    return res.end(JSON.stringify({ success: true, message: "Login successful" }));
                }
            }
            writeLog(`LOGIN_FAILED: Invalid credentials - ${email}`);
            res.end(JSON.stringify({ success: false, message: "Invalid email or password" }));
        }

        // 3. API quen mk
        else if (req.url === "/api/forgot-password" && req.method === "POST") {
            const data = await fsPromises.readFile(USER_FILE, "utf-8").catch(() => "");
            
            // neu email chua dky thi khong the gui otp
            if (!data.includes(`|${email}|`)) {
                writeLog(`FORGOT_PASSWORD_FAILED: Email not found - ${email}`);
                return res.end(JSON.stringify({ success: false, message: "This email is not registered" }));
            }

            const code = Math.floor(1000 + Math.random() * 9000).toString();
            otpStorage.set(email, { code, expire: Date.now() + 5 * 60 * 1000 });

            writeLog(`OTP_SENT: ${email} - CODE: ${code}`);
            res.end(JSON.stringify({ success: true, message: "Your OTP code is: " + code }));
        }

        // 3.5 API gui lai otp
        else if (req.url === "/api/resend-otp" && req.method === "POST") {
            if (!email) return res.end(JSON.stringify({ success: false, message: "Email required" }));

            const code = Math.floor(1000 + Math.random() * 9000).toString();
            // gia han them 5 phut
            otpStorage.set(email, { code, expire: Date.now() + 5 * 60 * 1000 });

            writeLog(`OTP_RESEND: ${email} - NEW_CODE: ${code}`);
            res.end(JSON.stringify({ success: true, message: "New OTP sent: " + code }));
        }

        // 4. api xac thuc otp
        else if (req.url === "/api/verify-otp" && req.method === "POST") {
            const record = otpStorage.get(email);
            
            if (record && record.code === otp && Date.now() < record.expire) {
                writeLog(`OTP_VERIFY_SUCCESS: ${email}`);
                res.end(JSON.stringify({ success: true, message: "OTP is valid" }));
            } else {
                writeLog(`OTP_VERIFY_FAILED: Invalid or expired - ${email}`);
                res.end(JSON.stringify({ success: false, message: "Invalid or expired OTP" }));
            }
        }

        // 5. api doi mk moi
        else if (req.url === "/api/reset-password" && req.method === "POST") {
            const record = otpStorage.get(email);
            
            // Chi cho phep doi mk neu OTP hop le va chua het han
            if (record && record.code === otp && Date.now() < record.expire) {
                const data = await fsPromises.readFile(USER_FILE, "utf-8");
                const newHash = await bcrypt.hash(newPassword, 10);

                const updatedData = data.split("\n").map(line => {
                    if (line.includes(`|${email}|`)) {
                        const parts = line.split("|");
                        return `${parts[0]}|${email}|${newHash}`; // giu nguyen id va email, chi thay hash 
                    }
                    return line;
                }).filter(line => line.trim() !== "").join("\n") + "\n";

                await fsPromises.writeFile(USER_FILE, updatedData);
                otpStorage.delete(email); // doi xong thi xoa otp
                
                writeLog(`PASSWORD_RESET_SUCCESS: ${email}`);
                res.end(JSON.stringify({ success: true, message: "Password changed successfully" }));
            } else {
                writeLog(`PASSWORD_RESET_FAILED: Session invalid or expired - ${email}`);
                res.end(JSON.stringify({ success: false, message: "Invalid session or OTP expired" }));
            }
        }
        
        else {
            writeLog(`NOT_FOUND: ${req.url}`);
            res.writeHead(404);
            res.end(JSON.stringify({ success: false, message: "API Not Found" }));
        }
    });
});

server.listen(Port, () => {
    console.log(`Backend server is running at http://localhost:${Port}`);
    writeLog("SERVER_STARTED");
});