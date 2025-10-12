import express from 'express';
import 'dotenv/config';
import cors from 'cors';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';

const { Pool } = pg;
const app = express();
const port = process.env.PORT || 10000;

// Middlewares
app.use(cors());
app.use(express.json());

// --- Cloudinary Config ---
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET,
});

// --- Multer Config ---
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// --- Database Pool ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// =================================================================
// --- AUTHENTICATION & AUTHORIZATION ---
// =================================================================

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

const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
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
// --- PROTECTED ADMIN API ENDPOINTS ---
// =================================================================
const adminRouter = express.Router();
adminRouter.use(verifyToken);

adminRouter.get('/properties', async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT * FROM properties ORDER BY created_at DESC');
        res.json(rows);
    } catch (error) {
        console.error('Error fetching admin properties:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

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

adminRouter.post('/properties', async (req, res) => {
    try {
        const { title, status, price, main_image_url, price_period, bedrooms, bathrooms, area_sqm, description } = req.body;
        const sql = `INSERT INTO properties (title, status, price, main_image_url, price_period, bedrooms, bathrooms, area_sqm, description) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`;
        const { rows } = await pool.query(sql, [title, status, price, main_image_url, price_period, bedrooms, bathrooms, area_sqm, description]);
        res.status(201).json({ message: 'Property created successfully', id: rows[0].id });
    } catch (error) {
        console.error('Error creating property:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

adminRouter.put('/properties/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { title, status, price, main_image_url, price_period, bedrooms, bathrooms, area_sqm, description } = req.body;
        const sql = `UPDATE properties SET title = $1, status = $2, price = $3, main_image_url = $4, price_period = $5, bedrooms = $6, bathrooms = $7, area_sqm = $8, description = $9 WHERE id = $10`;
        const { rowCount } = await pool.query(sql, [title, status, price, main_image_url, price_period, bedrooms, bathrooms, area_sqm, description, id]);
        if (rowCount === 0) return res.status(404).json({ message: 'Property not found' });
        res.json({ message: 'Property updated successfully' });
    } catch (error) {
        console.error('Error updating property:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

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

app.use('/api/admin', adminRouter);

// --- Image Upload Endpoint (also protected) ---
app.post('/api/upload', verifyToken, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded.' });
    }
    const b64 = Buffer.from(req.file.buffer).toString('base64');
    let dataURI = "data:" + req.file.mimetype + ";base64," + b64;
    const result = await cloudinary.uploader.upload(dataURI, {
      folder: "phuket-keys"
    });
    res.status(200).json({ imageUrl: result.secure_url });
  } catch (error) {
    console.error('Image upload error:', error);
    res.status(500).json({ error: 'Image upload failed.' });
  }
});

// =================================================================
// --- PUBLIC API ENDPOINTS (No login required) ---
// =================================================================

app.get('/api/properties', async (req, res) => {
    try {
        const page = parseInt(req.query.page || '1');
        const limit = parseInt(req.query.limit || '9');
        const offset = (page - 1) * limit;

        const { status, type, keyword } = req.query;

        let baseQuery = 'FROM properties';
        const conditions = [];
        const values = [];
        let counter = 1;

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

        const totalResult = await pool.query(`SELECT COUNT(*) ${baseQuery}`, values);
        const totalProperties = parseInt(totalResult.rows[0].count);
        const totalPages = Math.ceil(totalProperties / limit);
        
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

app.post('/api/contact', (req, res) => {
    // This part will be updated later with Nodemailer
    const { name, email, phone, message } = req.body;
    console.log({ name, email, phone, message });
    res.status(200).json({ success: true, message: 'Message received successfully!' });
});

// =================================================================
// --- SERVER START ---
// =================================================================
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});