import express from 'express';
import 'dotenv/config';
import cors from 'cors';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const { Pool } = pg;
const app = express();
const port = process.env.PORT || 10000;

app.use(cors());
app.use(express.json());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// ... (ส่วนของ Authentication และ Admin API เหมือนเดิม) ...

// =================================================================
// --- Public API Endpoints (No login required) ---
// =================================================================

// GET all properties (with search and pagination)
app.get('/api/properties', async (req, res) => {
    try {
        // --- แก้ไขจุดที่ 1: ลบ 'as string' ออก ---
        const page = parseInt(req.query.page || '1');
        const limit = parseInt(req.query.limit || '9');
        const offset = (page - 1) * limit;

        const { status, type, keyword } = req.query;

        // --- ส่วนสร้าง Query ---
        let baseQuery = 'FROM properties';
        const conditions = [];
        const values = [];
        let counter = 1;

        // --- แก้ไขจุดที่ 2: ลบ 'as string' และเพิ่มการตรวจสอบค่าว่าง ---
        if (status && status !== '') {
            conditions.push(`status = $${counter++}`);
            values.push(status);
        }
        if (type && type !== '') {
            conditions.push(`LOWER(title) LIKE $${counter++}`);
            values.push(`%${type.toLowerCase()}%`);
        }
        if (keyword && keyword.trim() !== '') {
            conditions.push(`LOWER(title) LIKE $${counter++}`);
            values.push(`%${keyword.toLowerCase()}%`);
        }
        
        if (conditions.length > 0) {
            baseQuery += ' WHERE ' + conditions.join(' AND ');
        }

        // --- Query สำหรับนับจำนวนทั้งหมด ---
        const totalResult = await pool.query(`SELECT COUNT(*) ${baseQuery}`, values);
        const totalProperties = parseInt(totalResult.rows[0].count);
        const totalPages = Math.ceil(totalProperties / limit);
        
        // --- Query สำหรับดึงข้อมูลตามหน้า ---
        const dataQuery = `SELECT * ${baseQuery} ORDER BY created_at DESC LIMIT $${counter++} OFFSET $${counter++}`;
        const dataValues = [...values, limit, offset];

        const { rows } = await pool.query(dataQuery, dataValues);

        res.json({
            properties: rows,
            currentPage: page,
            totalPages: totalPages
        });

    } catch (error) {
        console.error('Error fetching public properties:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});


// ... (โค้ดส่วนที่เหลือของ Public API และ app.listen() เหมือนเดิม) ...

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