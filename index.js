require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { MongoClient } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 12;

// MongoDB setup
const mongoUrl = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/?retryWrites=true&w=majority`;

const client = new MongoClient(mongoUrl, {
    tls: true,
    tlsAllowInvalidCertificates: false
});

const userCollection = client.db(process.env.MONGODB_DATABASE).collection('users');

// Session store
const mongoStore = MongoStore.create({
    mongoUrl: mongoUrl,
    collectionName: 'sessions',
    ttl: 60 * 60 // 1 hour
});

// Middleware
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
    cookie: { maxAge: 60 * 60 * 1000 } // 1 hour
}));

// ── Authentication middleware ────────────────────────────────────────────────
function sessionValidation(req, res, next) {
    if (!req.session.authenticated) {
        res.redirect('/login');
        return;
    }
    next();
}

// ── Authorization middleware ─────────────────────────────────────────────────
function adminAuthorization(req, res, next) {
    if (req.session.user_type != 'admin') {
        res.status(403);
        res.render('403');
        return;
    }
    next();
}

// ── Routes ───────────────────────────────────────────────────────────────────

// Home page
app.get('/', (req, res) => {
    res.render('index', {
        loggedIn: req.session.authenticated ? true : false,
        name: req.session.name || ''
    });
});

// Sign up - GET
app.get('/signup', (req, res) => {
    res.render('signup');
});

// Sign up - POST
app.post('/signupSubmit', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    if (!name) {
        res.send('Name is required. <a href="/signup">Try again</a>');
        return;
    }
    if (!email) {
        res.send('Email is required. <a href="/signup">Try again</a>');
        return;
    }
    if (!password) {
        res.send('Password is required. <a href="/signup">Try again</a>');
        return;
    }

    // Joi validation (NoSQL injection protection)
    const schema = Joi.object({
        name: Joi.string().alphanum().max(20).required(),
        email: Joi.string().email({ tlds: { allow: false } }).required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send(`Invalid input. <a href="/signup">Try again</a>`);
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
        name: name,
        email: email,
        password: hashedPassword,
        user_type: 'user'
    });

    req.session.authenticated = true;
    req.session.name = name;
    req.session.email = email;
    req.session.user_type = 'user';

    res.redirect('/members');
});

// Login - GET
app.get('/login', (req, res) => {
    res.render('login');
});

// Login - POST
app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    // Joi validation (NoSQL injection protection)
    const schema = Joi.object({
        email: Joi.string().email({ tlds: { allow: false } }).required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send(`Invalid input. <a href="/login">Try again</a>`);
        return;
    }

    const result = await userCollection
        .find({ email: email })
        .project({ name: 1, email: 1, password: 1, user_type: 1, _id: 1 })
        .toArray();

    if (result.length != 1) {
        res.send('User not found. <a href="/login">Try again</a>');
        return;
    }

    if (await bcrypt.compare(password, result[0].password)) {
        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.email = result[0].email;
        req.session.user_type = result[0].user_type;
        res.redirect('/members');
        return;
    } else {
        res.send('Invalid email/password combination. <a href="/login">Try again</a>');
        return;
    }
});

// Members - GET (authentication required)
app.get('/members', sessionValidation, (req, res) => {
    const images = ['img1.jpg', 'img2.jpg', 'img3.jpg'];
    res.render('members', {
        name: req.session.name,
        images: images
    });
});

// Admin - GET (authentication + authorization required)
app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
    const users = await userCollection.find().project({ name: 1, email: 1, user_type: 1 }).toArray();
    res.render('admin', { users: users });
});

// Promote user to admin
app.get('/promoteUser', sessionValidation, adminAuthorization, async (req, res) => {
    // Joi validation on URL parameter
    const schema = Joi.string().email({ tlds: { allow: false } }).required();
    const validationResult = schema.validate(req.query.email);
    if (validationResult.error != null) {
        res.send('Invalid input.');
        return;
    }

    await userCollection.updateOne(
        { email: req.query.email },
        { $set: { user_type: 'admin' } }
    );
    res.redirect('/admin');
});

// Demote user to regular user
app.get('/demoteUser', sessionValidation, adminAuthorization, async (req, res) => {
    // Joi validation on URL parameter
    const schema = Joi.string().email({ tlds: { allow: false } }).required();
    const validationResult = schema.validate(req.query.email);
    if (validationResult.error != null) {
        res.send('Invalid input.');
        return;
    }

    await userCollection.updateOne(
        { email: req.query.email },
        { $set: { user_type: 'user' } }
    );
    res.redirect('/admin');
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// 404 - catch-all
app.get('*', (req, res) => {
    res.status(404);
    res.render('404');
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});