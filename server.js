import express from 'express';
import 'dotenv/config';
import path from 'path';
import { fileURLToPath } from 'url';
import cors from 'cors';
import pg from 'pg'; // ใช้ pg แทน mysql2
const { Pool } = pg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// การตั้งค่า Database Pool สำหรับ PostgreSQL บน Render
const pool = new Pool({
    connectionString: process.env.DATABASE_URL, // Render จะตั้งค่าตัวแปรนี้ให้เอง
    ssl: {
        rejectUnauthorized: false
    }
});

// --- API Endpoints (ปรับให้เข้ากับ pg) ---

app.get('/api/admin/properties', async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT * FROM properties ORDER BY created_at DESC');
        res.json(rows);
    } catch (error) {
        console.error('Error fetching properties:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

app.get('/api/admin/properties/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { rows } = await pool.query('SELECT * FROM properties WHERE id = $1', [id]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Property not found' });
        }
        res.json(rows[0]);
    } catch (error) {
        console.error('Error fetching single property:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

app.post('/api/admin/properties', async (req, res) => {
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

app.put('/api/admin/properties/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { title, status, price, main_image_url, price_period } = req.body;
        const sql = `UPDATE properties SET title = $1, status = $2, price = $3, main_image_url = $4, price_period = $5 WHERE id = $6`;
        const { rowCount } = await pool.query(sql, [title, status, price, main_image_url, price_period, id]);
        if (rowCount === 0) {
            return res.status(404).json({ message: 'Property not found' });
        }
        res.json({ message: 'Property updated successfully' });
    } catch (error) {
        console.error('Error updating property:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

app.delete('/api/admin/properties/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { rowCount } = await pool.query('DELETE FROM properties WHERE id = $1', [id]);
        if (rowCount === 0) {
            return res.status(404).json({ message: 'Property not found' });
        }
        res.json({ message: 'Property deleted successfully' });
    } catch (error) {
        console.error('Error deleting property:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

app.post('/api/contact', (req, res) => {
    const { name, email, phone, message } = req.body;
    console.log('--- New Contact Form Submission ---');
    console.log(`Name: ${name}`);
    console.log(`Email: ${email}`);
    res.status(200).json({ success: true, message: 'Message received successfully!' });
});

app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`);
});