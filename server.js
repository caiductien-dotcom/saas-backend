const http = require("http");
const https = require("https");
const fs = require("fs");
const bcrypt = require("bcrypt");

const Port = 3000;

//github 
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const GITHUB_OWNER = "caiductien-dotcom";
const GITHUB_REPO = "saas-backend";
const GITHUB_FILE = "user.txt";
const GITHUB_BRANCH = "main";

const LOG_FILE = "server.log";
const otpStorage = new Map();

const writeLog = (msg) => {
    const timestamp = new Date().toISOString();
    const entry = `[${timestamp}] ${msg}\n`;
    fs.appendFileSync(LOG_FILE, entry);
    console.log(`[LOG] ${msg}`);
};

// doc user.txt tu github
const readUsersFromGitHub = () => {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: "api.github.com",
            path: `/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${GITHUB_FILE}?ref=${GITHUB_BRANCH}`,
            method: "GET",
            headers: {
                "Authorization": `token ${GITHUB_TOKEN}`,
                "User-Agent": "saas-backend",
                "Accept": "application/vnd.github.v3+json"
            }
        };

        const req = https.request(options, (res) => {
            let data = "";
            res.on("data", chunk => data += chunk);
            res.on("end", () => {
                const json = JSON.parse(data);
                if (json.content) {
                    const content = Buffer.from(json.content, "base64").toString("utf-8");
                    resolve({ content, sha: json.sha });
                } else {
                    // File chua ton tai
                    resolve({ content: "", sha: null });
                }
            });
        });

        req.on("error", reject);
        req.end();
    });
};

// ghi user.txt len github
const writeUsersToGitHub = (content, sha) => {
    return new Promise((resolve, reject) => {
        const body = JSON.stringify({
            message: "update user data",
            content: Buffer.from(content).toString("base64"),
            branch: GITHUB_BRANCH,
            ...(sha && { sha })
        });

        const options = {
            hostname: "api.github.com",
            path: `/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${GITHUB_FILE}`,
            method: "PUT",
            headers: {
                "Authorization": `token ${GITHUB_TOKEN}`,
                "User-Agent": "saas-backend",
                "Accept": "application/vnd.github.v3+json",
                "Content-Type": "application/json",
                "Content-Length": Buffer.byteLength(body)
            }
        };

        const req = https.request(options, (res) => {
            let data = "";
            res.on("data", chunk => data += chunk);
            res.on("end", () => resolve(JSON.parse(data)));
        });

        req.on("error", reject);
        req.write(body);
        req.end();
    });
};

const server = http.createServer((req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (req.method === "OPTIONS") return res.end();

    let body = "";
    req.on("data", chunk => { body += chunk.toString(); });
    req.on("end", async () => {
        const payload = body ? JSON.parse(body) : {};
        const { email, password, otp, newPassword } = payload;

        // 1. API dang ky
        if (req.url === "/api/signup" && req.method === "POST") {
            const { content, sha } = await readUsersFromGitHub();

            if (content.includes(`|${email}|`)) {
                writeLog(`SIGNUP_FAILED: Email already exists - ${email}`);
                return res.end(JSON.stringify({ success: false, message: "Email already exists" }));
            }

            const id = Date.now();
            const hash = await bcrypt.hash(password, 10);
            const newContent = content + `${id}|${email}|${hash}\n`;

            await writeUsersToGitHub(newContent, sha);
            writeLog(`SIGNUP_SUCCESS: ${email}`);
            res.end(JSON.stringify({ success: true, message: "Signup successful" }));
        }

        // 2. API dang nhap
        else if (req.url === "/api/login" && req.method === "POST") {
            const { content } = await readUsersFromGitHub();
            const userLine = content.split("\n").find(line => line.includes(`|${email}|`));

            if (userLine) {
                const savedHash = userLine.split("|")[2].trim();
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
            const { content } = await readUsersFromGitHub();

            if (!content.includes(`|${email}|`)) {
                writeLog(`FORGOT_PASSWORD_FAILED: Email not found - ${email}`);
                return res.end(JSON.stringify({ success: false, message: "This email is not registered" }));
            }

            const code = Math.floor(1000 + Math.random() * 9000).toString();
            otpStorage.set(email, { code, expire: Date.now() + 10 * 1000 });

            writeLog(`OTP_SENT: ${email} - CODE: ${code}`);
            res.end(JSON.stringify({ success: true, message: "Your OTP code is: " + code }));
        }

        // 3.5 api resend otp
        else if (req.url === "/api/resend-otp" && req.method === "POST") {
            if (!email) return res.end(JSON.stringify({ success: false, message: "Email required" }));

            const code = Math.floor(1000 + Math.random() * 9000).toString();
            otpStorage.set(email, { code, expire: Date.now() + 10 * 1000 });

            writeLog(`OTP_RESEND: ${email} - NEW_CODE: ${code}`);
            res.end(JSON.stringify({ success: true, message: "New OTP sent: " + code }));
        }

        // 4. API xac thuc otp
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

        // 5. API doi mk
        else if (req.url === "/api/reset-password" && req.method === "POST") {
            const record = otpStorage.get(email);

            if (record && record.code === otp && Date.now() < record.expire) {
                const { content, sha } = await readUsersFromGitHub();
                const newHash = await bcrypt.hash(newPassword, 10);

                const updatedContent = content.split("\n").map(line => {
                    if (line.includes(`|${email}|`)) {
                        const parts = line.split("|");
                        return `${parts[0]}|${email}|${newHash}`;
                    }
                    return line;
                }).filter(line => line.trim() !== "").join("\n") + "\n";

                await writeUsersToGitHub(updatedContent, sha);
                otpStorage.delete(email);

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