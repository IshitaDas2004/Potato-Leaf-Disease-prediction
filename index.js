const express        = require('express');
const path           = require('path');
const bcrypt         = require('bcrypt');
const session        = require('express-session');
const { Client }     = require('pg');
const multer         = require('multer');
const axios          = require('axios');
const FormData = require('form-data'); // Required for sending images to Python
const nodemailer = require('nodemailer'); // Required for emails
const cron = require('node-cron'); // Required for daily reminders


const fs             = require('fs');
const passport       = require('passport');
const LocalStrategy  = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
require('dotenv').config();

const app        = express();
const port       = 3000;
const SALT_ROUNDS = 10;


// ── Database ──────────────────────────────────────────────────────────────────
const client = new Client({
    user:     'postgres',
    host:     'localhost',
    database: 'Potato-Disease',
    password: '1221',
    port:     5432,
});

client.connect()
    .then(() => console.log('✅ Connected to PostgreSQL'))
    .catch(err => { console.error('❌ DB connection failed:', err.message); process.exit(1); });


// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret:            process.env.SESSION_SECRET || 'your_secret_key',
    resave:            false,
    saveUninitialized: false,
    rolling:           true,
    cookie: {
        maxAge:   30 * 60 * 1000,
        httpOnly: true,
        secure:   false, // set true if using HTTPS
    },
}));

app.use(passport.initialize());
app.use(passport.session());


// ── View Engine ───────────────────────────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));



// ── Auth Middleware ───────────────────────────────────────────────────────────
const isAuth = (req, res, next) => {
    if (req.session.user) return next();
    res.redirect('/');
};


// ── Passport: Local Strategy ──────────────────────────────────────────────────
passport.use(new LocalStrategy(
    { usernameField: 'email', passwordField: 'password' },
    async (email, password, done) => {
        try {
            const result = await client.query(
                'SELECT * FROM users WHERE email = $1', [email]
            );
            if (result.rows.length === 0)
                return done(null, false, { message: 'Invalid email or password.' });

            const user = result.rows[0];

            if (user.password === 'GOOGLE_OAUTH')
                return done(null, false, { message: 'Please sign in with Google for this account.' });

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch)
                return done(null, false, { message: 'Invalid email or password.' });

            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }
));


// ── Passport: Google OAuth Strategy ──────────────────────────────────────────
passport.use(new GoogleStrategy(
    {
        clientID:     process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL:  '/auth/google/callback',
    },
    async (accessToken, refreshToken, profile, done) => {
        try {
            const email     = profile.emails[0].value;
            const firstname = profile.name.givenName;
            const lastname  = profile.name.familyName;

            const existing = await client.query(
                'SELECT * FROM users WHERE email = $1', [email]
            );

            if (existing.rows.length > 0)
                return done(null, existing.rows[0]);

            // New Google user — insert with placeholder password
            const newUser = await client.query(
                `INSERT INTO users (firstname, lastname, email, password, phone, location, terms_accepted)
                 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
                [firstname, lastname, email, 'GOOGLE_OAUTH', '', '', true]
            );

            return done(null, newUser.rows[0]);
        } catch (err) {
            return done(err);
        }
    }
));

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser(async (id, done) => {
    try {
        const result = await client.query('SELECT * FROM users WHERE id = $1', [id]);
        done(null, result.rows[0]);
    } catch (err) {
        done(err);
    }
});


// ── ROUTES ────────────────────────────────────────────────────────────────────

// GET / — Login page
app.get('/', (req, res) => {
    if (req.session.user) return res.redirect('/home');
    res.render('Login.ejs');
});
app.get('/home', isAuth, (req, res) => {
    res.render('index.ejs');
});


// GET /signup
app.get('/signup', (req, res) => {
    if (req.session.user) return res.redirect('/home');
    res.render('signup.ejs');
});

// POST /signup

app.post('/signup', async (req, res) => {
    // 1. Extract variables from req.body
    const { firstname, lastname, email, password, phone, location, terms_accepted } = req.body;

    // 2. Validation
    if (!firstname || !lastname || !email || !password || !phone || !location) {
        return res.status(400).send('All fields are required.');
    }

    if (password.length < 8) {
        return res.status(400).send('Password must be at least 8 characters.');
    }

    try {
        // 3. Check if user already exists
        const existing = await client.query(
            'SELECT id FROM users WHERE email = $1', [email]
        );
        if (existing.rows.length > 0) {
            return res.status(409).send('An account with this email already exists.');
        }

        // 4. Hash the password
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        // 5. Insert into Database
        await client.query(
            `INSERT INTO users (firstname, lastname, email, password, phone, location, terms_accepted)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [firstname, lastname, email, hashedPassword, phone, location, terms_accepted ? true : false]
        );

        // 6. Save session and Redirect to Login (/)
        req.session.save((err) => {
            if (err) {
                console.error('Session save error:', err);
                return res.status(500).send('Error saving session.');
            }
            res.redirect('/'); 
        });

    } catch (err) {
        console.error('Signup error:', err.message);
        res.status(500).send('Server error.');
    }
});


// POST / — Login
app.post('/', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password)
        return res.status(400).send('Email and password are required.');

    try {
        const result = await client.query(
            'SELECT * FROM users WHERE email = $1', [email]
        );

        if (result.rows.length === 0)
            return res.status(401).send('Invalid email or password.');

        const user = result.rows[0];

        if (user.password === 'GOOGLE_OAUTH')
            return res.status(401).send('Please sign in with Google for this account.');

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch)
            return res.status(401).send('Invalid email or password.');

        req.session.regenerate(err => {
            if (err) return res.status(500).send('Session error.');
            req.session.user = { id: user.id, name: user.firstname };
            res.redirect('/home');
        });

    } catch (err) {
        console.error('Login error:', err.message);
        res.status(500).send('Server error.');
    }
});


// GET /auth/google — Redirect to Google
app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

// GET /auth/google/callback — Google calls back here
app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        req.session.user = { id: req.user.id, name: req.user.firstname };
        res.redirect('/home');
    }
);


// GET /logout
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) console.error('Logout error:', err);
        res.redirect('/');
    });
});


// ── Start Server ──────────────────────────────────────────────────────────────
app.listen(port, () => {
    console.log(`🚀 Server is running on http://localhost:${port}`);
});