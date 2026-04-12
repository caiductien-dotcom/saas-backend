const http = require("http"); // tao server web
const fs = require("fs"); // doc ghi file
const fsPromises = require("fs").promises; // dung cho Promise va Async/Await
const path = require("path"); // xu ly duong dan
//const auth = require("./js/auth")

const Port = 3000; // cong
const USER_FILE = path.join(__dirname, "user.txt"); // duong dan file user.txt
const OTP_FILE = path.join(__dirname, "otp.txt"); // duong dan file luu mã OTP

// Tao server
const server = http.createServer((req, res) => {

    // setup cors cho frontend goi vao
    res.setHeader("Access-Control-Allow-Origin", "*"); 
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    // trinh duyet gui OPTIONS de kiem tra CORS
    if (req.method === "OPTIONS") {
        res.writeHead(200);
        res.end();
        return;
    }
    //http redirect
    if (req.url === "/" && req.method === "GET") {
        console.log("Đang chuyển hướng sang trang Login...");
        res.writeHead(302, {
            'Location': 'http://127.0.0.1:5500/login2.html' 
        });
        res.end();
        return; 
    }

    let body = "";
    req.on("data", chunk => {
        body += chunk.toString(); // nhan du lieu tu client
    });

    // Cho req.on('end') thanh async de dung duoc await o duoi
    req.on("end", async () => { 
        console.log("Dữ liệu nhận được:", body);
        const payload = body ? JSON.parse(body) : {}; // json -> object

        //1. API dang ky
        if (req.url === "/api/signup" && req.method === "POST") {
            const { email, password } = payload;
            fs.readFile(USER_FILE, "utf-8", (err, data) => {
                const users = (err || !data) ? [] : data.split("\n").filter(Boolean);
                if (users.some(u => u.split(",")[0] === email)) {
                    res.end(JSON.stringify({ success: false, message: "Email da ton tai" }));
                } else {
                    fs.appendFile(USER_FILE, `${email},${password}\n`, err => {
                        res.end(JSON.stringify({ success: true, message: "Dang ky thanh cong" }));
                    });
                }
            });
        } 

        //2. API dang nhap
        else if (req.url === "/api/login" && req.method === "POST") {
            const { email, password } = payload;
            fs.readFile(USER_FILE, "utf-8", (err, data) => {
                const users = (err || !data) ? [] : data.split("\n").filter(Boolean);
                // Tim user khop ca email va password
                const found = users.find(u => u === `${email},${password}`);
                if (found) {
                    res.end(JSON.stringify({ success: true, message: "Dang nhap thanh cong" }));
                } else {
                    res.end(JSON.stringify({ success: false, message: "Sai tai khoan hoac mat khau" }));
                }
            });
        }

        //3. API quen mk 
        else if (req.url === "/api/forgot-password" && req.method === "POST") {
            const { email } = payload;
            const otp = Math.floor(1000 + Math.random() * 9000).toString(); // tao ma 4 so
            // Dung fsPromises.writeFile tra ve promise
            fsPromises.writeFile(OTP_FILE, `${email},${otp}`)
                .then(() => {
                    res.end(JSON.stringify({ success: true, message: "OTP da tao: " + otp }));
                })
                .catch(err => {
                    res.end(JSON.stringify({ success: false, message: "Loi tao OTP" }));
                });
        }
        //4.API Quen mk
        else if (req.url === "/api/reset-password" && req.method === "POST") {
            const { email, otp, newPassword } = payload;

            // Doc file OTP bang await
            const otpRaw = await fsPromises.readFile(OTP_FILE, "utf-8");
            const [savedEmail, savedOtp] = otpRaw.split(",");

            if (email === savedEmail && otp === savedOtp) {
                // Neu OTP dung, tien hanh doc file user va cap nhat mat khau
                const userData = await fsPromises.readFile(USER_FILE, "utf-8");
                let users = userData.split("\n").filter(Boolean);

                //  thay mat khau moi cho dung email
                users = users.map(line => {
                    const [e, p] = line.split(",");
                    return e === email ? `${e},${newPassword}` : line;
                });

                // Ghi lai file user moi bang await
                await fsPromises.writeFile(USER_FILE, users.join("\n") + "\n");
                res.end(JSON.stringify({ success: true, message: "Doi mat khau moi thanh cong" }));
            } else {
                res.end(JSON.stringify({ success: false, message: "Ma OTP khong chinh xac" }));
            }
        }
        // Tra ve 404 neu sai link
        else {
            res.writeHead(404);
            res.end(JSON.stringify({ success: false, message: "Sai URL" }));
        }
    });
});

server.listen(Port, () => {
    console.log(`Server dang chay tren cong http://localhost:${Port}\n`);
});