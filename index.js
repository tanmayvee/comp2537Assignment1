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
const mongoUrl = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true&w=majority`;

let userCollection;
let mongoClient;

async function startServer() {
  // 1. Connect to MongoDB first
  mongoClient = new MongoClient(mongoUrl, { tls: true, tlsAllowInvalidCertificates: false });
  await mongoClient.connect();
  const db = mongoClient.db(process.env.MONGODB_DATABASE);
  userCollection = db.collection('users');
  console.log('Connected to MongoDB');

  // 2. Set up middleware AFTER connection is ready
  app.use(express.urlencoded({ extended: false }));
  app.use(express.static('public'));

  app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    resave: true,
    saveUninitialized: false,
    store: MongoStore.create({
      client: mongoClient,
      dbName: process.env.MONGODB_DATABASE,
      collectionName: 'sessions',
      ttl: 60 * 60, // 1 hour
    }),
    cookie: { maxAge: 60 * 60 * 1000 }, // 1 hour
  }));

  // 3. Define routes AFTER middleware
  
  // Home page
  app.get('/', (req, res) => {
    if (req.session && req.session.authenticated) {
      res.send(`
        <!DOCTYPE html>
        <html>
        <head><title>Home</title></head>
        <body>
          <h1>Hello, ${req.session.name}!</h1>
          <a href="/members"><button>Go to Members Area</button></a><br><br>
          <a href="/logout"><button>Logout</button></a>
        </body>
        </html>
      `);
    } else {
      res.send(`
        <!DOCTYPE html>
        <html>
        <head><title>Home</title></head>
        <body>
          <h1>Welcome</h1>
          <a href="/signup"><button>Sign up</button></a><br><br>
          <a href="/login"><button>Log in</button></a>
        </body>
        </html>
      `);
    }
  });

  // Sign up – GET
  app.get('/signup', (req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>Sign Up</title></head>
      <body>
        <h2>create user</h2>
        <form action="/signupSubmit" method="POST">
          <input name="name" type="text" placeholder="name" /><br><br>
          <input name="email" type="text" placeholder="email" /><br><br>
          <input name="password" type="password" placeholder="password" /><br><br>
          <button type="submit">Submit</button>
        </form>
      </body>
      </html>
    `);
  });

  // Sign up – POST
  app.post('/signupSubmit', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name) return res.send(`Name is required. <a href="/signup">Try again</a>`);
    if (!email) return res.send(`Email is required. <a href="/signup">Try again</a>`);
    if (!password) return res.send(`Password is required. <a href="/signup">Try again</a>`);

    // Joi validation (NoSQL injection protection)
    const schema = Joi.object({
      name: Joi.string().max(50).required(),
      email: Joi.string().email({ tlds: { allow: false } }).max(100).required(),
      password: Joi.string().max(50).required(),
    });

    const { error } = schema.validate({ name, email, password });
    if (error) {
      return res.send(`Invalid input: ${error.details[0].message}. <a href="/signup">Try again</a>`);
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await userCollection.insertOne({ name, email, password: hashedPassword });

    req.session.authenticated = true;
    req.session.name = name;
    req.session.email = email;

    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
        return res.send('Session error. Please try again.');
      }
      res.redirect('/members');
    });
  });

  // Login – GET
  app.get('/login', (req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>Log In</title></head>
      <body>
        <h2>log in</h2>
        <form action="/loginSubmit" method="POST">
          <input name="email" type="text" placeholder="email" /><br><br>
          <input name="password" type="password" placeholder="password" /><br><br>
          <button type="submit">Submit</button>
        </form>
      </body>
      </html>
    `);
  });

  // Login – POST
  app.post('/loginSubmit', async (req, res) => {
    const { email, password } = req.body;

    // Joi validation (NoSQL injection protection)
    const schema = Joi.object({
      email: Joi.string().email({ tlds: { allow: false } }).max(100).required(),
      password: Joi.string().max(50).required(),
    });

    const { error } = schema.validate({ email, password });
    if (error) {
      return res.send(`Invalid input. <a href="/login">Try again</a>`);
    }

    const user = await userCollection.findOne({ email });
    if (!user) {
      return res.send(`Invalid email/password combination. <a href="/login">Try again</a>`);
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.send(`Invalid email/password combination. <a href="/login">Try again</a>`);
    }

    req.session.authenticated = true;
    req.session.name = user.name;
    req.session.email = user.email;

    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
        return res.send('Session error. Please try again.');
      }
      res.redirect('/members');
    });
  });

  // Members – GET
  app.get('/members', (req, res) => {
    if (!req.session || !req.session.authenticated) {
      return res.redirect('/');
    }

    const images = ['img1.jpg', 'img2.jpg', 'img3.jpg'];
    const randomImage = images[Math.floor(Math.random() * images.length)];

    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>Members</title></head>
      <body>
        <h1>Hello, ${req.session.name}.</h1>
        <img src="/${randomImage}" alt="random image" style="max-width:400px;" /><br><br>
        <a href="/logout"><button>Sign out</button></a>
      </body>
      </html>
    `);
  });

  // Logout
  app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
  });

  // 404 – catch-all
  app.get('*', (req, res) => {
    res.status(404).send(`
      <!DOCTYPE html>
      <html>
      <head><title>404</title></head>
      <body>
        <h1>Page not found - 404</h1>
      </body>
      </html>
    `);
  });

  // 4. Start listening
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});