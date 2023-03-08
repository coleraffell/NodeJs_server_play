const express = require("express");
const session = require("express-session");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const { MemoryStore } = require("express-session");
const app = express();
const mongoUri = "mongodb+srv://coleraffell:LiverpoolFc13@cluster0.xe1mxga.mongodb.net/?retryWrites=true&w=majority";
const mongoDBSession = require("connect-mongodb-session")(session);
const userModel = require("./models/user");
var rsa = require("node-rsa");


console.log("\n--------------------------");

mongoose.set('strictQuery', true);

async function connect() {
    try {
        await mongoose.connect(mongoUri);
        console.log("\nConnected to MongoDB");
    } catch (error) {
        console.log(error);
    }
}

const store = new mongoDBSession({
    uri: mongoUri,
    collection: 'mySessions',
})

connect();

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.json()) // for parsing application/json

app.use(session({
    secret: 'Key that signs cookie',
    resave: false, 
    saveUninitialized: true, // if true: gives cookie upon visiting site and then authenticates it after whereas false waits
    store: store,
}));

const isAuthenticated = (req, res, next) => {
    if (req.session.isAuth) {
        next();
    } else {
        res.redirect('/login');
    }
};

function generateKeys() {

    const key = new rsa({ b: 1024 });

    var publicKey = key.exportKey('public');
    var privateKey = key.exportKey('private');

    //let key_public = new rsa(publicKey);
    //let key_private = new rsa(privateKey);

    //return { key_public, key_private };
    return { publicKey, privateKey };
};

app.get("/", (req, res) => {
    res.render("landing");
    console.log("\nSession ID: " + req.session.id);
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    const user = await userModel.findOne({ email });

    if (!user) {
        console.log("\nUser not found");
        return res.redirect('/login');
    } 
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
        console.log("\nWrong password")
        return res.redirect('/login');
    }

    let key_public = new rsa(user.publicKey);
    let key_private = new rsa(user.privateKey);

    let secret = "Secret Message";

    var publicEncrypt = key_public.encrypt(secret);
    var privateDecrypt = key_private.decrypt(publicEncrypt);
    console.log("\nPublic Encrypted: " + publicEncrypt);
    console.log("\nPrivate Decrypted: " + privateDecrypt);

    
    // Authenticate user session
    req.session.isAuth = true; 

    console.log("\nUsername: " + user.username + " logged in");
    req.session.email = email;
    req.session.username = user.username;
    res.redirect('/dashboard');
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.post("/register", async (req, res) => { 
    const { username, email, password } = req.body;
    let user = await userModel.findOne({ email });

    if (user) {
        return res.redirect('/register');
    } else { 
        const hashedPassword = await bcrypt.hash(password, 12);

        let keys = generateKeys();
        let pubKey = (await keys).publicKey,
            privKey = (await keys).privateKey;
        
        user = new userModel({
            username,
            email,
            password: hashedPassword,
            publicKey: pubKey,
            privateKey: privKey,
        });

        await user.save();
        console.log("\nNew user created: " + username);
        res.redirect("/login");
    }
 });

app.get("/dashboard", isAuthenticated, (req, res) => {
    //console.log("Username: " + req.session.username);
    res.render("dashboard", { username: req.session.username });
});

app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) throw err;
        res.redirect("/");
    })
});

app.listen(8080, console.log("\nServer running on localhost:8080"));