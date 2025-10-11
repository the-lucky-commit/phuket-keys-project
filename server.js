import express from 'express';
import 'dotenv/config';
import cors from 'cors';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const { Pool } = pg;
const app = express();
const port = process.env.PORT || 10000; // Render uses port 10000 by default

// Middlewares
app.use(cors());
app.use(express.json());

// Database Pool for PostgreSQL on Render
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// =================================================================
// --- Authentication & Authorization ---
// =================================================================

// Login Endpoint (Public)
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

        if (rows.length === 0) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const accessToken = jwt.sign({ username: user.username, id: user.id }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ accessToken });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Format: Bearer TOKEN

    if (!token) {
        return res.status(401).json({ error: 'Access token is missing or invalid' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token is not valid' });
        }
        req.user = user;
        next();
    });
};

// =================================================================
// --- Protected Admin API Endpoints ---
// =================================================================
const adminRouter = express.Router();
adminRouter.use(verifyToken); // Apply token verification to all admin routes

// GET all properties (Admin)
adminRouter.get('/properties', async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT * FROM properties ORDER BY created_at DESC');
        res.json(rows);
    } catch (error) {
        console.error('Error fetching admin properties:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

// GET a single property by ID (Admin)
adminRouter.get('/properties/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { rows } = await pool.query('SELECT * FROM properties WHERE id = $1', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Property not found' });
        res.json(rows[0]);
    } catch (error) {
        console.error('Error fetching single property:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

// CREATE a new property
adminRouter.post('/properties', async (req, res) => {
    try {
        const { title, status, price, main_image_url, price_period } = req.body;
        const sql = `INSERT INTO properties (title, status, price, main_image_url, price_period) VALUES ($1, $2, $3, $4, $5) RETURNING id`;
        const { rows } = await pool.query(sql, [title, status, price, main_image_url, price_period]);
        res.status(201).json({ message: 'Property created successfully', id: rows[0].id });
    } catch (error) {
        console.error('Error creating property:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

// UPDATE a property
adminRouter.put('/properties/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { title, status, price, main_image_url, price_period } = req.body;
        const sql = `UPDATE properties SET title = $1, status = $2, price = $3, main_image_url = $4, price_period = $5 WHERE id = $6`;
        const { rowCount } = await pool.query(sql, [title, status, price, main_image_url, price_period, id]);
        if (rowCount === 0) return res.status(404).json({ message: 'Property not found' });
        res.json({ message: 'Property updated successfully' });
    } catch (error) {
        console.error('Error updating property:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

// DELETE a property
adminRouter.delete('/properties/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { rowCount } = await pool.query('DELETE FROM properties WHERE id = $1', [id]);
        if (rowCount === 0) return res.status(404).json({ message: 'Property not found' });
        res.json({ message: 'Property deleted successfully' });
    } catch (error) {
        console.error('Error deleting property:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

// Use the admin router for all routes starting with /api/admin
app.use('/api/admin', adminRouter);

// =================================================================
// --- Public API Endpoints (No login required) ---
// =================================================================

// GET all properties (with search functionality)
app.get('/api/properties', async (req, res) => {
    try {
        const { status, type, keyword } = req.query;

        let baseQuery = 'SELECT * FROM properties';
        const conditions = [];
        const values = [];
        let counter = 1;

        if (status) {
            conditions.push(`status = $${counter++}`);
            values.push(status);
        }
        if (type) {
            conditions.push(`LOWER(title) LIKE $${counter++}`);
            values.push(`%${type.toLowerCase()}%`);
        }
        if (keyword) {
            conditions.push(`LOWER(title) LIKE $${counter++}`);
            values.push(`%${keyword.toLowerCase()}%`);
        }

        if (conditions.length > 0) {
            baseQuery += ' WHERE ' + conditions.join(' AND ');
        }

        baseQuery += ' ORDER BY created_at DESC';

        const { rows } = await pool.query(baseQuery, values);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching public properties:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

// GET a single property by ID (Public)
app.get('/api/properties/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { rows } = await pool.query('SELECT * FROM properties WHERE id = $1', [id]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Property not found' });
        }
        res.json(rows[0]);
    } catch(error){
        console.error('Error fetching public single property:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

// Contact Form Endpoint
app.post('/api/contact', (req, res) => {
    try {
        const { name, email, phone, message } = req.body;
        if (!name || !email || !message) {
            return res.status(400).json({ error: 'Name, email, and message are required.' });
        }
        console.log('--- New Contact Form Submission ---');
        console.log(`Name: ${name}`);
        console.log(`Email: ${email}`);
        console.log(`Phone: ${phone || 'Not provided'}`);
        console.log(`Message: ${message}`);
        console.log('---------------------------------');
        res.status(200).json({ success: true, message: 'Message received successfully!' });
    } catch (error) {
        console.error('Error handling contact form:', error);
        res.status(500).json({ error: 'Server error' });
    }
});


// Start Server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});