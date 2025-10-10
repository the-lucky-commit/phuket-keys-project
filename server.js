import express from 'express';
import mysql from 'mysql2/promise';
import 'dotenv/config';
import path from 'path';
import { fileURLToPath } from 'url';
import cors from 'cors';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 3000;

// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database Pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// =================================================================
// API Endpoints
// =================================================================

// --- Property API Endpoints ---

// GET all properties
app.get('/api/admin/properties', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM properties ORDER BY created_at DESC');
        res.json(rows);
    } catch (error) {
        console.error('Error fetching properties for admin:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

// GET a single property by ID
app.get('/api/admin/properties/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT * FROM properties WHERE id = ?', [id]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Property not found' });
        }
        res.json(rows[0]);
    } catch (error) {
        console.error('Error fetching single property:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

// CREATE a new property
app.post('/api/admin/properties', async (req, res) => {
    try {
        const { title, status, price, main_image_url, price_period } = req.body;
        if (!title || !status || !price) {
            return res.status(400).json({ error: 'Title, status, and price are required' });
        }
        const sql = `INSERT INTO properties (title, status, price, main_image_url, price_period) VALUES (?, ?, ?, ?, ?)`;
        const [result] = await pool.query(sql, [title, status, price, main_image_url, price_period]);
        res.status(201).json({ message: 'Property created successfully', id: result.insertId });
    } catch (error) {
        console.error('Error creating property:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

// UPDATE a property
app.put('/api/admin/properties/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { title, status, price, main_image_url, price_period } = req.body;
        if (!title || !status || !price) {
            return res.status(400).json({ error: 'Title, status, and price are required' });
        }
        const sql = `UPDATE properties SET title = ?, status = ?, price = ?, main_image_url = ?, price_period = ? WHERE id = ?`;
        const [result] = await pool.query(sql, [title, status, price, main_image_url, price_period, id]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Property not found' });
        }
        res.json({ message: 'Property updated successfully' });
    } catch (error) {
        console.error('Error updating property:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

// DELETE a property
app.delete('/api/admin/properties/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const [result] = await pool.query('DELETE FROM properties WHERE id = ?', [id]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Property not found' });
        }
        res.json({ message: 'Property deleted successfully' });
    } catch (error) {
        console.error('Error deleting property:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

// --- Contact Form API Endpoint ---
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

// =================================================================
// Page Routing (for legacy static files, not used by Next.js)
// =================================================================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Start Server
app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`);
});