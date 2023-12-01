const express = require("express");
const app = express();
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require('bcrypt');
const jwt = require("jsonwebtoken");

const cookieParser = require("cookie-parser");

const saltRounds = 10;
const secret = "secret-key"

const db = mysql.createConnection({
	host: "bekvctid9hnn8ojg3dub-mysql.services.clever-cloud.com",
	user: "ubtmexty1xdhaf9h",
	password: "9UacvAocI96ynbYne7Ls",
	database: "bekvctid9hnn8ojg3dub",
})

app.use(cookieParser())
app.use(express.json())
app.use(cors({
    // https://user-auth-client-carlosna7.vercel.app
    // http://localhost:3000
    origin:"http://localhost:3000",
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
    credentials: true,
    secure: true,
}))

function errorHandler(res, msg, status = 500) {
    console.error(msg)
    res.status(status).json({ msg: "Erro no servidor" })
}

app.post("/login", async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;

    try {
        const [result] = await db.promise().query("SELECT * FROM usuarios WHERE email = ?", [email]);

        if (result.length > 0) {

            const hashPassword = result[0].password;
            const response = await bcrypt.compare(password, hashPassword);

            if (response) {
                const token = jwt.sign({email}, secret, { expiresIn: "1h" });

                // res.cookie("token", token)              
                res.cookie("tokenToken", token, {
                    secure: true, // Configura o cookie para HTTPS apenas
                    httpOnly: true,
                    sameSite: "None",
                });

                res.send({ success: true, msg: "Login bem-sucedido" })
            } else {
				res.send({ success: false, msg: "Email ou senha incorreto!"})
                // res.status(401).json({ msg: "Email ou Senha incorretos!" })
            }
        } else {
			res.send({ success: false, msg: "Usuário não registrado!"})
            // res.status(401).json({ msg: "Usuário não registrado!" })
        }
    } catch (err) {
        errorHandler(res, "Erro ao fazer login", err)
    }
})

app.post("/register", async (req, res) => {
    const {email, password} = req.body;

    try {
        const [existUser] = await db.promise().query("SELECT * FROM usuarios WHERE email=?", [email]);

        if (existUser.length === 0) {
            const hash = await bcrypt.hash(password, saltRounds);

            await db.promise().query("INSERT INTO usuarios (email, password) VALUES (?, ?)", [email, hash])
            res.send({ msg: "Usuário cadastrado com sucesso!" })
        } else {
            res.send({msg: "Email já cadastrado!"})
        }
    } catch (err) {
        errorHandler(res, "Erro ao cadastrar usuário!", err)
    }
})

app.post("/homelogged", (req, res) => {
    const token = req.cookies.token;
    const email = req.body.email;

    if (!token) {
        return res.status(401).json({ msg: "Token não informado." })
    }
  
    try {
        const verificar = jwt.verify(token, secret);
        if(email !== verificar.email) {
            res.clearCookie("token")

            return res.redirect("/")
        } else {
            console.log("certo!")
            res.send({ msg: "Você está Logado!" })
        }

    } catch (err) {
        res.status(401).json({ msg: "Invalid token" })
    }
})

app.listen(3001, () => {
	console.log("Rodando na porta 3001")
})