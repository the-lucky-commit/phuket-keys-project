import express from 'express';
import 'dotenv/config';
import cors from 'cors';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const { Pool } = pg;
const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// --- Middleware สำหรับตรวจสอบ Token ---
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) return res.sendStatus(401); // Unauthorized

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // Forbidden
        req.user = user;
        next();
    });
};

// =================================================================
// API Endpoints
// =================================================================

// --- Authentication Endpoint (ไม่ต้องใช้ Token) ---
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

        if (rows.length === 0) {
            return res.status(400).json({ error: 'Invalid username or password' });
        }

        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid username or password' });
        }

        const accessToken = jwt.sign({ username: user.username, id: user.id }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ accessToken });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// --- Protected Admin API Endpoints (ต้องใช้ Token) ---
const adminRouter = express.Router();
adminRouter.use(verifyToken); // ใช้ middleware กับทุก route ใน adminRouter

adminRouter.get('/properties', async (req, res) => { /* ...โค้ดเดิม... */ });
adminRouter.get('/properties/:id', async (req, res) => { /* ...โค้ดเดิม... */ });
adminRouter.post('/properties', async (req, res) => { /* ...โค้ดเดิม... */ });
adminRouter.put('/properties/:id', async (req, res) => { /* ...โค้ดเดิม... */ });
adminRouter.delete('/properties/:id', async (req, res) => { /* ...โค้ดเดิม... */ });

// Copy-paste โค้ด handler ของ properties มาใส่ใน adminRouter
// GET all
adminRouter.get('/properties', async (req, res) => {
    const { rows } = await pool.query('SELECT * FROM properties ORDER BY created_at DESC');
    res.json(rows);
});
// ... ทำแบบเดียวกันกับ GET by ID, POST, PUT, DELETE ...

// ใช้ adminRouter ที่มี middleware ป้องกัน
app.use('/api/admin', adminRouter);


// --- Public API Endpoints ---
app.post('/api/contact', (req, res) => { /* ...โค้ดเดิม... */ });
app.get('/api/properties', async (req, res) => { /* API สำหรับหน้าบ้าน (ไม่ต้อง login) */
    const { rows } = await pool.query('SELECT * FROM properties ORDER BY created_at DESC');
    res.json(rows);
});
 app.get('/api/properties/:id', async (req, res) => { /* API สำหรับหน้าบ้าน (ไม่ต้อง login) */
    const { id } = req.params;
    const { rows } = await pool.query('SELECT * FROM properties WHERE id = $1', [id]);
    res.json(rows[0]);
});


app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`);
});