import express from 'express';
import 'dotenv/config';
import cors from 'cors';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';
import sgMail from '@sendgrid/mail';

const REQUIRED_ENV_VARS = [
  'DATABASE_URL',
  'FRONTEND_URL',
  'JWT_SECRET',
  'CLOUD_NAME',
  'API_KEY',
  'API_SECRET',
  'SENDGRID_API_KEY',
  'SENDGRID_SENDER_EMAIL'
];

const missingVars = REQUIRED_ENV_VARS.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
  console.error('====================================================');
  console.error('FATAL ERROR: Missing required environment variables:');
  console.error(missingVars.join('\n'));
  console.error('====================================================');
  process.exit(1); // สั่งให้เซิร์ฟเวอร์หยุดทำงานทันที
}

const { Pool } = pg;
const app = express();
const port = process.env.PORT || 10000;

if (!process.env.FRONTEND_URL) {
  console.error("FATAL ERROR: FRONTEND_URL is not defined in environment variables.");
  process.exit(1); // สั่งให้เซิร์ฟเวอร์หยุดทำงานทันที
}

// Middlewares & Configs
app.use(express.json());

console.log("===================================");
console.log("Reading FRONTEND_URL as:", process.env.FRONTEND_URL);

const corsOptions = {
  origin: [
    'http://localhost:3000',
    process.env.FRONTEND_URL
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET,
});

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// =================================================================
// --- AUTHENTICATION & AUTHORIZATION ---
// =================================================================

// [ 🔄 แทนที่ฟังก์ชันนี้ 🔄 ]
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Admin login - check admins table
        const { rows } = await pool.query('SELECT * FROM admins WHERE username = $1', [username]);

        if (rows.length === 0) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }
        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }
        const accessToken = jwt.sign({ username: user.username, id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ accessToken });
    } catch (error) {
        console.error('Admin Login error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- ⬇️ [เพิ่ม API ใหม่นี้] ⬇️ ---
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, email } = req.body; // สมมติว่ารับ email ด้วย

        // 1. ตรวจสอบ Input
        if (!username || !password || !email) {
            return res.status(400).json({ error: 'Username, password, and email are required' });
        }

        // 2. เช็คว่า Username หรือ Email ซ้ำหรือไม่
        const { rows: existingUsers } = await pool.query(
            'SELECT * FROM users WHERE username = $1 OR email = $2',
            [username, email]
        );
        if (existingUsers.length > 0) {
            return res.status(409).json({ error: 'Username or email already exists' });
        }

        // 3. Hash รหัสผ่าน
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // 4. บันทึกลง DB (role จะเป็น 'customer' โดยอัตโนมัติจาก DEFAULT)
        const { rows: newUsers } = await pool.query(
            'INSERT INTO users (username, password, email) VALUES ($1, $2, $3) RETURNING id, username, role',
            [username, hashedPassword, email]
        );

        const newUser = newUsers[0];

        // 5. สร้าง Token ให้ลูกค้า Login ทันที
        const accessToken = jwt.sign(
            { username: newUser.username, id: newUser.id, role: newUser.role }, 
            process.env.JWT_SECRET, 
            { expiresIn: '1d' }
        );

        res.status(201).json({ accessToken }); // ⭐️ ส่ง Token กลับไป

    } catch (error) {
        console.error('Customer Register error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- ⬇️ [เพิ่ม API ใหม่นี้] ⬇️ ---
app.post('/api/customer-login', async (req, res) => {
    try {
        const { username, password } = req.body; // หรือจะใช้ email login ก็ได้

        // ⭐️ เช็ค Role 'customer'
        const { rows } = await pool.query('SELECT * FROM users WHERE username = $1 AND role = $2', [username, 'customer']);

        if (rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials or not a customer account' });
        }
        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // ⭐️ สร้าง Token (มี role: 'customer')
        const accessToken = jwt.sign({ username: user.username, id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ accessToken });
    } catch (error) {
        console.error('Customer Login error:', error);
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

const customerRouter = express.Router();
customerRouter.use(verifyToken);

// [ ⬇️ เพิ่มโค้ดนี้ ⬇️ ]
// ดึงรายการ Amenities ทั้งหมดสำหรับหน้า Admin
adminRouter.get('/amenities', async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT * FROM amenities ORDER BY name ASC');
        res.json(rows);
    } catch (error) {
        console.error('Error fetching amenities:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

// --- ⬇️ [เพิ่ม API ใหม่นี้] ⬇️ ---
// GET: ดึงสถิติการค้นหา (Search Stats)
adminRouter.get('/search-stats', async (req, res) => {
    try {
        // --- Query 1: Top 10 Keywords ---
        const topKeywordsQuery = `
            SELECT keyword, COUNT(*) as search_count
            FROM search_logs
            WHERE keyword IS NOT NULL AND keyword != ''
            GROUP BY keyword
            ORDER BY search_count DESC
            LIMIT 10; 
        `;

        // --- Query 2: Top Property Types ---
        const topTypesQuery = `
            SELECT type, COUNT(*) as search_count
            FROM search_logs
            WHERE type IS NOT NULL AND type != 'All' 
            GROUP BY type
            ORDER BY search_count DESC
            LIMIT 10;
        `;

        // --- Query 3: Status Counts ---
        const statusCountsQuery = `
            SELECT status, COUNT(*) as search_count
            FROM search_logs
            WHERE status IS NOT NULL
            GROUP BY status
            ORDER BY search_count DESC;
        `;

        // --- รัน Query ทั้งหมดพร้อมกัน ---
        const [keywordsResult, typesResult, statusResult] = await Promise.all([
            pool.query(topKeywordsQuery),
            pool.query(topTypesQuery),
            pool.query(statusCountsQuery)
        ]);

        // --- จัดรูปแบบข้อมูลส่งกลับ ---
        res.json({
            topKeywords: keywordsResult.rows,
            topTypes: typesResult.rows,
            statusCounts: statusResult.rows
        });

    } catch (error) {
        console.error('Error fetching search stats:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

// --- ⬇️ [เพิ่ม API ใหม่นี้] ⬇️ ---
// GET: ดึงสถิติรายได้ (Revenue Stats)
adminRouter.get('/revenue-stats', async (req, res) => {
    try {
        // Query เพื่อคำนวณรายได้ แยกตามประเภท
        const revenueQuery = `
            SELECT
                -- 1. รายได้รวมทั้งหมด
                SUM(final_price) AS total_revenue,
                
                -- 2. รายได้จากการขาย ('Sold')
                SUM(CASE WHEN transaction_type = 'Sold' THEN final_price ELSE 0 END) AS sales_revenue,
                
                -- 3. รายได้จากการเช่า ('Rented')
                SUM(CASE WHEN transaction_type = 'Rented' THEN final_price ELSE 0 END) AS rental_revenue,
                
                -- 4. (Bonus) จำนวน Transaction ทั้งหมด
                COUNT(*) AS total_transactions,
                
                -- 5. (Bonus) จำนวนที่ขายได้
                SUM(CASE WHEN transaction_type = 'Sold' THEN 1 ELSE 0 END) AS units_sold,
                
                -- 6. (Bonus) จำนวนที่เช่าได้
                SUM(CASE WHEN transaction_type = 'Rented' THEN 1 ELSE 0 END) AS units_rented

            FROM transactions; 
        `; // ⭐️ ดึงจากตาราง transactions

        const { rows } = await pool.query(revenueQuery);

        // API จะ trả về แถวเดียวเสมอ (ถ้าไม่มีข้อมูลเลย จะเป็น null หรือ 0)
        res.json(rows[0] || { // ⭐️ ใส่ค่า default ป้องกัน null
            total_revenue: 0,
            sales_revenue: 0,
            rental_revenue: 0,
            total_transactions: 0,
            units_sold: 0,
            units_rented: 0
        });

    } catch (error) {
        console.error('Error fetching revenue stats:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

// API endpoint สำหรับ monthly revenue
adminRouter.get('/monthly-revenue', async (req, res) => {
    try {
        const monthlyRevenueQuery = `
            SELECT
                TO_CHAR(transaction_date, 'Mon') AS month,
                EXTRACT(MONTH FROM transaction_date) AS month_num,
                SUM(CASE WHEN transaction_type = 'Sold' THEN final_price ELSE 0 END) AS sales,
                SUM(CASE WHEN transaction_type = 'Rented' THEN final_price ELSE 0 END) AS rental
            FROM transactions
            WHERE EXTRACT(YEAR FROM transaction_date) = EXTRACT(YEAR FROM CURRENT_DATE)
            GROUP BY month, month_num
            ORDER BY month_num;
        `;

        const { rows } = await pool.query(monthlyRevenueQuery);

        // สร้างข้อมูล 12 เดือนเต็ม (ถ้าเดือนไหนไม่มีข้อมูลจะเป็น 0)
        const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        const monthlyData = months.map((month, index) => {
            const existingData = rows.find(row => row.month_num === index + 1);
            return {
                month,
                sales: existingData ? parseFloat(existingData.sales) : 0,
                rental: existingData ? parseFloat(existingData.rental) : 0,
            };
        });

        res.json(monthlyData);

    } catch (error) {
        console.error('Error fetching monthly revenue:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

// API endpoint สำหรับ export ข้อมูลสรุปแยกตามเดือนและปี
adminRouter.get('/export-summary', async (req, res) => {
    try {
        const { year, month } = req.query;
        
        // ดึงข้อมูล properties
        const propertiesQuery = `
            SELECT 
                id,
                title,
                price,
                status,
                type,
                bedrooms,
                bathrooms,
                area_sqm,
                description,
                created_at
            FROM properties
            ${year ? `WHERE EXTRACT(YEAR FROM created_at) = $1` : ''}
            ${year && month ? `AND EXTRACT(MONTH FROM created_at) = $2` : ''}
            ORDER BY created_at DESC;
        `;
        
        const propertiesParams = [];
        if (year) propertiesParams.push(year);
        if (year && month) propertiesParams.push(month);
        
        const { rows: properties } = await pool.query(propertiesQuery, propertiesParams);

        // ดึงข้อมูล transactions
        const transactionsQuery = `
            SELECT 
                t.id,
                t.property_id,
                p.title as property_title,
                t.transaction_type,
                t.final_price,
                t.transaction_date,
                t.user_id,
                u.username as customer_username,
                u.email as customer_email
            FROM transactions t
            LEFT JOIN properties p ON t.property_id = p.id
            LEFT JOIN users u ON t.user_id = u.id
            ${year ? `WHERE EXTRACT(YEAR FROM t.transaction_date) = $1` : ''}
            ${year && month ? `AND EXTRACT(MONTH FROM t.transaction_date) = $2` : ''}
            ORDER BY t.transaction_date DESC;
        `;
        
        const transactionsParams = [];
        if (year) transactionsParams.push(year);
        if (year && month) transactionsParams.push(month);
        
        const { rows: transactions } = await pool.query(transactionsQuery, transactionsParams);

        // ดึงข้อมูลสถิติรวม
        const statsQuery = `
            SELECT
                COUNT(*) FILTER (WHERE status = 'available') as available_count,
                COUNT(*) FILTER (WHERE status = 'reserved') as reserved_count,
                COUNT(*) FILTER (WHERE status = 'sold') as sold_count,
                COUNT(*) FILTER (WHERE status = 'rented') as rented_count,
                COUNT(*) as total_properties
            FROM properties
            ${year ? `WHERE EXTRACT(YEAR FROM created_at) = $1` : ''}
            ${year && month ? `AND EXTRACT(MONTH FROM created_at) = $2` : ''};
        `;
        
        const statsParams = [];
        if (year) statsParams.push(year);
        if (year && month) statsParams.push(month);
        
        const { rows: stats } = await pool.query(statsQuery, statsParams);

        // ดึงข้อมูล revenue แยกตามเดือน (สำหรับปีที่เลือก)
        const monthlyRevenueQuery = `
            SELECT
                TO_CHAR(transaction_date, 'Month YYYY') AS period,
                EXTRACT(MONTH FROM transaction_date) AS month_num,
                EXTRACT(YEAR FROM transaction_date) AS year_num,
                SUM(CASE WHEN transaction_type = 'Sold' THEN final_price ELSE 0 END) AS sales_revenue,
                SUM(CASE WHEN transaction_type = 'Rented' THEN final_price ELSE 0 END) AS rental_revenue,
                SUM(final_price) AS total_revenue,
                COUNT(*) FILTER (WHERE transaction_type = 'Sold') AS units_sold,
                COUNT(*) FILTER (WHERE transaction_type = 'Rented') AS units_rented
            FROM transactions
            ${year ? `WHERE EXTRACT(YEAR FROM transaction_date) = $1` : ''}
            GROUP BY period, month_num, year_num
            ORDER BY year_num DESC, month_num DESC;
        `;
        
        const monthlyRevenueParams = year ? [year] : [];
        const { rows: monthlyRevenue } = await pool.query(monthlyRevenueQuery, monthlyRevenueParams);

        res.json({
            properties,
            transactions,
            stats: stats[0],
            monthlyRevenue,
            filters: {
                year: year || 'all',
                month: month || 'all'
            }
        });

    } catch (error) {
        console.error('Error fetching export summary:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});
// --- ⬆️ [สิ้นสุดการเพิ่ม] ⬆️ ---

// --- ⬇️ [เพิ่ม API 3 เส้นนี้] ⬇️ ---

// 1. GET: ดึง "ID" ของ Property ทั้งหมดที่ User คนนี้ถูกใจ
// (Frontend จะใช้ข้อมูลนี้เพื่อแสดงว่าหัวใจดวงไหน 'เต็ม')
customerRouter.get('/favorites', async (req, res) => {
    try {
        const userId = req.user.id; // ⭐️ ได้ ID User จาก Token
        const { rows } = await pool.query(
            'SELECT property_id FROM user_favorites WHERE user_id = $1',
            [userId]
        );
        // ⭐️ ส่งกลับเป็น Array ของ ID (เช่น [15, 22, 30])
        const favoriteIds = rows.map(row => row.property_id);
        res.json(favoriteIds);
    } catch (error) {
        console.error('Error fetching favorites:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// 2. POST: กด "ถูกใจ" (เพิ่ม Property ลงใน Favorites)
customerRouter.post('/favorites', async (req, res) => {
    try {
        const userId = req.user.id;
        const { propertyId } = req.body; // ⭐️ รับ ID Property ที่จะถูกใจ

        if (!propertyId) {
            return res.status(400).json({ error: 'Property ID is required' });
        }

        // ⭐️ บันทึกลงตารางเชื่อม (ถ้าซ้ำ DB จะ error แต่เราจะดักไว้)
        await pool.query(
            'INSERT INTO user_favorites (user_id, property_id) VALUES ($1, $2)',
            [userId, propertyId]
        );
        res.status(201).json({ message: 'Favorite added' });

    } catch (error) {
        if (error.code === '23505') { // 23505 = Unique constraint violation
            return res.status(409).json({ error: 'Already favorited' });
        }
        console.error('Error adding favorite:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// 3. DELETE: กด "เลิกถูกใจ" (ลบ Property ออกจาก Favorites)
customerRouter.delete('/favorites/:propertyId', async (req, res) => {
    try {
        const userId = req.user.id;
        const { propertyId } = req.params; // ⭐️ รับ ID Property จาก URL

        const { rowCount } = await pool.query(
            'DELETE FROM user_favorites WHERE user_id = $1 AND property_id = $2',
            [userId, propertyId]
        );

        if (rowCount === 0) {
            return res.status(404).json({ error: 'Favorite not found' });
        }
        res.json({ message: 'Favorite removed' });

    } catch (error) {
        console.error('Error removing favorite:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- ⬆️ [สิ้นสุดการเพิ่ม] ⬆️ ---

// [ 🔄 แทนที่ฟังก์ชันนี้ 🔄 ]
adminRouter.get('/stats', async (req, res) => {
    try {
        const statsQuery = `
            SELECT
                COUNT(*) AS total_properties,
                SUM(CASE WHEN status = 'Available' THEN 1 ELSE 0 END) AS available,
                SUM(CASE WHEN status = 'Sold' THEN 1 ELSE 0 END) AS sold,
                SUM(CASE WHEN status = 'Rented' THEN 1 ELSE 0 END) AS rented,
                SUM(CASE WHEN status = 'Reserved' THEN 1 ELSE 0 END) AS reserved
            FROM properties;
        `;
        const { rows } = await pool.query(statsQuery);
        
        // Get user count
        const userCount = await pool.query('SELECT COUNT(*) as count FROM users');
        
        // Get transaction stats
        const transactionStats = await pool.query(`
            SELECT 
                COUNT(*) FILTER (WHERE transaction_type = 'Sold') as total_sold,
                COUNT(*) FILTER (WHERE transaction_type = 'Rented') as total_rented,
                COALESCE(SUM(final_price) FILTER (WHERE transaction_type = 'Sold'), 0) as revenue_sold,
                COALESCE(SUM(final_price) FILTER (WHERE transaction_type = 'Rented'), 0) as revenue_rented
            FROM transactions
        `);
        
        res.json({
            ...rows[0],
            total_users: parseInt(userCount.rows[0].count),
            ...transactionStats.rows[0]
        });
    } catch (error) {
        console.error('Error fetching dashboard stats:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

adminRouter.get('/properties', async (req, res) => {
    try {
        const { keyword, status } = req.query;

        let baseQuery = 'SELECT id, main_image, title, status, price, created_at, view_count, type, location, bedrooms, bathrooms FROM properties';
        const conditions = [];
        const values = [];
        let counter = 1;

        if (keyword) {
            conditions.push(`(LOWER(title) LIKE $${counter} OR LOWER(location) LIKE $${counter})`);
            values.push(`%${keyword.toLowerCase()}%`);
            counter++;
        }

        if (status) {
            conditions.push(`status = $${counter++}`);
            values.push(status);
        }

        if (conditions.length > 0) {
            baseQuery += ' WHERE ' + conditions.join(' AND ');
        }
        
        baseQuery += ' ORDER BY created_at DESC';

        const { rows } = await pool.query(baseQuery, values);
        res.json(rows);

    } catch (error) {
        console.error('Error fetching admin properties list:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

// เพิ่มโค้ดส่วนนี้เข้าไปใน server.js
adminRouter.get('/properties-by-type', async (req, res) => {
    try {
        const query = `
            SELECT
                type,
                COUNT(*) AS count
            FROM properties
            GROUP BY type
            ORDER BY count DESC;
        `;
        const { rows } = await pool.query(query);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching properties by type:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

// [ 🔄 แทนที่ฟังก์ชันนี้ 🔄 ]
adminRouter.get('/properties/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const propertyRes = await pool.query('SELECT * FROM properties WHERE id = $1', [id]);
        if (propertyRes.rows.length === 0) return res.status(404).json({ message: 'Property not found' });
        
        const imagesRes = await pool.query('SELECT id, image_url FROM property_images WHERE property_id = $1 ORDER BY created_at ASC', [id]);
        
        // --- [ ⬇️ เพิ่มส่วนนี้ ⬇️ ] ---
        // ดึง Amenities ที่ผูกกับ Property นี้
        const amenitiesQuery = `
            SELECT a.id, a.name, a.icon 
            FROM amenities a
            JOIN property_amenities pa ON a.id = pa.amenity_id
            WHERE pa.property_id = $1
            ORDER BY a.name;
        `;
        const amenitiesRes = await pool.query(amenitiesQuery, [id]);
        // --- [ ⬆️ สิ้นสุดส่วนที่เพิ่ม ⬆️ ] ---

        const property = propertyRes.rows[0];
        property.images = imagesRes.rows;
        property.amenities = amenitiesRes.rows; // ⭐️ ผูกข้อมูล Amenities เข้าไปด้วย

        res.json(property);
    } catch (error) {
        console.error('Error fetching single property:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

// [ 🔄 แทนที่ฟังก์ชันนี้ 🔄 ]
// POST (Create new property)
adminRouter.post('/properties', async (req, res) => {
    // ⭐️ 1. ใช้ client สำหรับ Transaction
    const client = await pool.connect();
    try {
        await client.query('BEGIN'); // ⭐️ 2. เริ่ม Transaction
        await client.query('BEGIN'); 

    // 1. ⬇️ [เพิ่ม 'availability'] ⬇️
    const { title, status, price, main_image_url, main_image_public_id, price_period, bedrooms, bathrooms, area_sqm, description, amenities, availability } = req.body;

    // 2. ⬇️ [เพิ่ม 'availability' (ตัวที่ 11) และ $11] ⬇️
    const sql = `INSERT INTO properties (title, status, price, main_image_url, main_image_public_id, price_period, bedrooms, bathrooms, area_sqm, description, availability) 
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id`;

    // 3. ⬇️ [เพิ่ม 'availability' (ตัวที่ 11)] ⬇️
    const values = [title, status, price, main_image_url, main_image_public_id, price_period, bedrooms, bathrooms, area_sqm, description, availability || 'Available']; // ⭐️ (ถ้าไม่ส่งมา ให้เป็น 'Available')

    const { rows } = await client.query(sql, values);
        const newPropertyId = rows[0].id; // ⭐️ 5. เอา ID ของ Property ที่เพิ่งสร้าง

        // 6. บันทึกลงตาราง 'property_amenities' (ถ้ามี)
        if (amenities && Array.isArray(amenities) && amenities.length > 0) {
            const amenitiesPromises = amenities.map(amenityId => {
                return client.query(
                    'INSERT INTO property_amenities (property_id, amenity_id) VALUES ($1, $2)',
                    [newPropertyId, amenityId]
                );
            });
            await Promise.all(amenitiesPromises); // ⭐️ 7. รันพร้อมกันทั้งหมด
        }

        await client.query('COMMIT'); // ⭐️ 8. ยืนยัน Transaction (สำเร็จทั้งหมด)
        res.status(201).json({ message: 'Property created successfully', id: newPropertyId });

    } catch (error) {
        await client.query('ROLLBACK'); // ⭐️ 9. ถ้าพลาด ให้ยกเลิกทั้งหมด
        console.error('Error creating property:', error);
        res.status(500).json({ error: 'Database query failed' });
    } finally {
        client.release(); // ⭐️ 10. คืน Connection
    }
});

// [ 🔄 แทนที่ฟังก์ชันนี้ 🔄 ]
// PUT (Update property by id)
adminRouter.put('/properties/:id', async (req, res) => {
    // ⭐️ 1. ใช้ client สำหรับ Transaction
    const client = await pool.connect();
    try {
    await client.query('BEGIN'); 
    const { id } = req.params;

    // 1. ⬇️ [เพิ่ม 'availability'] ⬇️
    const { 
        title, status, price, main_image_url, main_image_public_id, 
        price_period, bedrooms, bathrooms, area_sqm, description,
        old_main_image_public_id,
        amenities,
        availability // ⭐️ รับค่าใหม่นี้
    } = req.body;

    // 2. ⬇️ [เพิ่ม 'availability = $11'] ⬇️
    const sql = `UPDATE properties SET 
                    title = $1, status = $2, price = $3, main_image_url = $4, main_image_public_id = $5, 
                    price_period = $6, bedrooms = $7, bathrooms = $8, area_sqm = $9, description = $10,
                    availability = $11 
                 WHERE id = $12`; // ⭐️ (แก้ WHERE เป็น $12)

    // 3. ⬇️ [เพิ่ม 'availability' (ตัวที่ 11) และแก้ id เป็น $12] ⬇️
    const values = [
        title, status, price, main_image_url, main_image_public_id, 
        price_period, bedrooms, bathrooms, area_sqm, description, 
        availability || 'Available', // ⭐️ (ถ้าไม่ส่งมา ให้เป็น 'Available')
        id
    ];

    const { rowCount } = await client.query(sql, values);
        if (rowCount === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ message: 'Property not found' });
        }

        // 5. ⭐️ (สำคัญ) ลบ Amenities "เก่า" ทั้งหมดของ Property นี้
        await client.query('DELETE FROM property_amenities WHERE property_id = $1', [id]);

        // 6. ⭐️ เพิ่ม Amenities "ใหม่" เข้าไป (ถ้ามี)
        if (amenities && Array.isArray(amenities) && amenities.length > 0) {
            const amenitiesPromises = amenities.map(amenityId => {
                return client.query(
                    'INSERT INTO property_amenities (property_id, amenity_id) VALUES ($1, $2)',
                    [id, amenityId]
                );
            });
            await Promise.all(amenitiesPromises);
        }

        // 7. (เหมือนเดิม) ลบรูปเก่าออกจาก Cloudinary (ถ้ามี)
        if (old_main_image_public_id) {
            try {
                await cloudinary.uploader.destroy(old_main_image_public_id);
            } catch (cldError) {
                console.warn('Cloudinary destroy error:', cldError.message);
            }
        }

        await client.query('COMMIT'); // ⭐️ 8. ยืนยัน Transaction
        res.json({ message: 'Property updated successfully' });

    } catch (error) {
        await client.query('ROLLBACK'); // ⭐️ 9. ถ้าพลาด ให้ยกเลิก
        console.error('Error updating property:', error);
        res.status(500).json({ error: 'Database query failed' });
    } finally {
        client.release(); // ⭐️ 10. คืน Connection
    }
});

adminRouter.delete('/properties/:id', async (req, res) => {
    // --- ⬇️ [แก้ไข] ใช้ Transaction ---
    const client = await pool.connect(); // ยืม connection มาจัดการ Transaction
    try {
        const { id } = req.params;

        await client.query('BEGIN'); // เริ่ม Transaction

        // 1. ดึง Public ID ของ Gallery ทั้งหมด ที่เกี่ยวข้องกับ property นี้
        const galleryImagesRes = await client.query('SELECT public_id FROM property_images WHERE property_id = $1', [id]);
        const galleryPublicIds = galleryImagesRes.rows
            .map(img => img.public_id)
            .filter(Boolean); // .filter(Boolean) คือการกรองค่า null หรือ "" ออกไป

        // 2. ดึง Public ID ของรูปหลัก
        const propertyRes = await client.query('SELECT main_image_public_id FROM properties WHERE id = $1', [id]);

        if (propertyRes.rows.length === 0) {
            await client.query('ROLLBACK'); // ย้อนกลับ Transaction
            return res.status(404).json({ message: 'Property not found' });
        }

        const mainPublicId = propertyRes.rows[0].main_image_public_id;

        // 3. ลบ Gallery Images ออกจาก Cloudinary
        if (galleryPublicIds.length > 0) {
            // .api.delete_resources() ใช้ลบทีเดียวหลายไฟล์ (เร็วกว่า)
            await cloudinary.api.delete_resources(galleryPublicIds);
        }

        // 4. ลบ Main Image ออกจาก Cloudinary
        if (mainPublicId) {
            await cloudinary.uploader.destroy(mainPublicId);
        }

        // 5. ลบข้อมูลออกจาก Database
        // **คำเตือน:** โค้ดนี้จะทำงานได้ถูกต้อง
        // หากคุณตั้งค่า Foreign Key ของตาราง `property_images` (คอลัมน์ `property_id`)
        // ให้เป็น "ON DELETE CASCADE"
        // (ถ้าไม่ได้ตั้ง คุณต้องรัน DELETE FROM property_images... ก่อนบรรทัดนี้)

        // สมมติว่าตั้ง Cascade ไว้:
        await client.query('DELETE FROM properties WHERE id = $1', [id]);

        await client.query('COMMIT'); // ยืนยัน Transaction (ทุกอย่างสำเร็จ)
        // --- ⬆️ [แก้ไข] ---

        res.json({ message: 'Property and all associated images deleted successfully' });

    } catch (error) {
        await client.query('ROLLBACK'); // ย้อนกลับหากมีปัญหา
        console.error('Error deleting property:', error);
        res.status(500).json({ error: 'Database query failed' });
    } finally {
        client.release(); // คืน connection กลับเข้า pool
    }
});

// --- ⬇️ [เพิ่ม API ใหม่นี้] ⬇️ ---
// POST: บันทึก Transaction (ปิดการขาย/เช่า)
adminRouter.post('/properties/:id/close-deal', async (req, res) => {
    // ⭐️ 1. ใช้ Transaction
    const client = await pool.connect();
    try {
        await client.query('BEGIN'); // ⭐️ 2. เริ่ม Transaction
        const { id } = req.params; // ID ของ Property

        // 3. รับข้อมูลจาก Admin
        const { transaction_type, final_price, user_id } = req.body; 

        // 4. ตรวจสอบ Input
        if (!transaction_type || !final_price || (transaction_type !== 'Sold' && transaction_type !== 'Rented')) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Invalid transaction type or final price' });
        }

        // 5. บันทึกลงตาราง 'transactions'
        const transactionSql = `
            INSERT INTO transactions (property_id, user_id, transaction_type, final_price)
            VALUES ($1, $2, $3, $4)
        `;
        // (ถ้าไม่มี user_id ส่งมา ให้เป็น null)
        await client.query(transactionSql, [id, user_id || null, transaction_type, final_price]);

        // 6. ⭐️ อัปเดตสถานะ 'availability' ในตาราง 'properties'
        //    (ถ้าขายแล้ว -> Sold, ถ้าเช่าแล้ว -> Rented)
        const newAvailability = (transaction_type === 'Sold') ? 'Sold' : 'Rented';
        const updatePropertySql = `
            UPDATE properties SET availability = $1 WHERE id = $2
        `;
        await client.query(updatePropertySql, [newAvailability, id]);

        await client.query('COMMIT'); // ⭐️ 7. ยืนยัน Transaction
        res.status(201).json({ message: 'Transaction recorded and property status updated' });

    } catch (error) {
        await client.query('ROLLBACK'); // ⭐️ 8. ยกเลิกถ้าพลาด
        console.error('Error closing deal:', error);
        res.status(500).json({ error: 'Database query failed' });
    } finally {
        client.release(); // ⭐️ 9. คืน Connection
    }
});
// --- ⬆️ [สิ้นสุดการเพิ่ม] ⬆️ ---

adminRouter.post('/properties/:id/images', upload.array('images', 5), async (req, res) => {
    try {
        const { id } = req.params;
        const files = req.files;
        if (!files || files.length === 0) {
            return res.status(400).json({ error: 'No files uploaded.' });
        }

        const uploadPromises = files.map(file => {
            const b64 = Buffer.from(file.buffer).toString('base64');
            let dataURI = "data:" + file.mimetype + ";base64," + b64;
            return cloudinary.uploader.upload(dataURI, { folder: "phuket-keys-gallery" });
        });

        const results = await Promise.all(uploadPromises);

        // --- ⬇️ [แก้ไข] เราจะ map 'results' โดยตรง ---
        // ไม่ต้องใช้ imageUrls.map แล้ว
        const insertPromises = results.map(result => {
            // เพิ่ม public_id เข้าไปในคำสั่ง INSERT
            return pool.query(
                'INSERT INTO property_images (property_id, image_url, public_id) VALUES ($1, $2, $3)', 
                [id, result.secure_url, result.public_id] // <-- เพิ่ม result.public_id
            );
        });
        // --- ⬆️ [แก้ไข] ---

        await Promise.all(insertPromises);

        res.status(201).json({ message: 'Images uploaded successfully' });
    } catch (error) {
        console.error('Gallery image upload error:', error);
        res.status(500).json({ error: 'Image upload failed.' });
    }
}); 

adminRouter.delete('/images/:imageId', async (req, res) => {
    try {
        const { imageId } = req.params;

        // --- ⬇️ [แก้ไข] เพิ่มส่วนลบจาก Cloudinary ---

        // 1. ดึง public_id ออกมาจาก DB ก่อน
        const { rows } = await pool.query('SELECT public_id FROM property_images WHERE id = $1', [imageId]);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'Image not found in database' });
        }

        const publicId = rows[0].public_id;

        // 2. สั่งลบจาก Cloudinary (ถ้ามี publicId)
        if (publicId) {
            try {
                // ใช้ .destroy() สำหรับลบไฟล์เดียว
                await cloudinary.uploader.destroy(publicId);
            } catch (cldError) {
                // ถ้าลบใน Cloudinary ไม่ได้ ก็ไม่เป็นไร (อาจจะเคยลบไปแล้ว)
                // เราจะ log error ไว้ แต่ปล่อยให้โค้ดทำงานต่อ (ลบใน DB)
                console.warn('Cloudinary destroy error (image may already be deleted):', cldError.message);
            }
        }

        // 3. ลบจาก DB (เหมือนเดิม)
        await pool.query('DELETE FROM property_images WHERE id = $1', [imageId]);
        // --- ⬆️ [แก้ไข] ---

        res.json({ message: 'Image deleted successfully' });
    } catch (error) {
        console.error('Error deleting image:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

app.use('/api/admin', adminRouter);

app.use('/api/customer', customerRouter);

// =================================================================
// --- USER PROFILE API ENDPOINTS ---
// =================================================================
const userRouter = express.Router();
userRouter.use(verifyToken);

// Get user profile
userRouter.get('/profile', async (req, res) => {
    try {
        const userId = req.user.id;
        const { rows } = await pool.query(
            'SELECT id, username, email, full_name, phone, role, created_at FROM users WHERE id = $1',
            [userId]
        );
        
        if (rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json(rows[0]);
    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Update user profile
userRouter.put('/profile', async (req, res) => {
    try {
        const userId = req.user.id;
        const { username, email, full_name, phone } = req.body;
        
        // Check if username already exists (if changing)
        if (username) {
            const { rows: existingUser } = await pool.query(
                'SELECT id FROM users WHERE username = $1 AND id != $2',
                [username, userId]
            );
            if (existingUser.length > 0) {
                return res.status(400).json({ error: 'Username already taken' });
            }
        }
        
        // Check if email already exists (if changing)
        if (email) {
            const { rows: existingEmail } = await pool.query(
                'SELECT id FROM users WHERE email = $1 AND id != $2',
                [email, userId]
            );
            if (existingEmail.length > 0) {
                return res.status(400).json({ error: 'Email already taken' });
            }
        }
        
        const { rows } = await pool.query(
            'UPDATE users SET username = $1, email = $2, full_name = $3, phone = $4 WHERE id = $5 RETURNING id, username, email, full_name, phone, role, created_at',
            [username, email, full_name, phone, userId]
        );
        
        if (rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json(rows[0]);
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Change password
userRouter.put('/change-password', async (req, res) => {
    try {
        const userId = req.user.id;
        const { current_password, new_password } = req.body;
        
        // Get current password hash
        const { rows } = await pool.query('SELECT password FROM users WHERE id = $1', [userId]);
        
        if (rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Verify current password
        const isMatch = await bcrypt.compare(current_password, rows[0].password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }
        
        // Hash new password
        const hashedPassword = await bcrypt.hash(new_password, 10);
        
        // Update password
        await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, userId]);
        
        res.json({ message: 'Password changed successfully' });
    } catch (error) {
        console.error('Error changing password:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get user favorites
userRouter.get('/favorites', async (req, res) => {
    try {
        const userId = req.user.id;
        
        const { rows } = await pool.query(`
            SELECT 
                f.id,
                f.property_id,
                f.created_at as added_at,
                p.title as property_title,
                p.price as property_price,
                p.main_image_url as property_image
            FROM favorites f
            JOIN properties p ON f.property_id = p.id
            WHERE f.user_id = $1
            ORDER BY f.created_at DESC
        `, [userId]);
        
        res.json(rows);
    } catch (error) {
        console.error('Error fetching favorites:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Add favorite
userRouter.post('/favorites/:propertyId', async (req, res) => {
    try {
        const userId = req.user.id;
        const propertyId = parseInt(req.params.propertyId);
        
        // Check if already favorited
        const { rows: existing } = await pool.query(
            'SELECT id FROM favorites WHERE user_id = $1 AND property_id = $2',
            [userId, propertyId]
        );
        
        if (existing.length > 0) {
            return res.status(409).json({ message: 'Already in favorites' });
        }
        
        // Add to favorites
        await pool.query(
            'INSERT INTO favorites (user_id, property_id) VALUES ($1, $2)',
            [userId, propertyId]
        );
        
        res.json({ message: 'Added to favorites' });
    } catch (error) {
        console.error('Error adding favorite:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Remove favorite
userRouter.delete('/favorites/:propertyId', async (req, res) => {
    try {
        const userId = req.user.id;
        const propertyId = parseInt(req.params.propertyId);
        
        const result = await pool.query(
            'DELETE FROM favorites WHERE user_id = $1 AND property_id = $2',
            [userId, propertyId]
        );
        
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Favorite not found' });
        }
        
        res.json({ message: 'Removed from favorites' });
    } catch (error) {
        console.error('Error removing favorite:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.use('/api/users', userRouter);

// --- Image Upload Endpoint (for main image) ---
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

    // --- ⬇️ [แก้ไข] ส่งกลับ 2 ค่า ---
    res.status(200).json({ 
      imageUrl: result.secure_url, 
      publicId: result.public_id   // <-- เพิ่มค่านี้เข้าไป
    });
    // --- ⬆️ [แก้ไข] ---

  } catch (error) {
    console.error('Image upload error:', error);
    res.status(500).json({ error: 'Image upload failed.' });
  }
});

// =================================================================
// --- PUBLIC API ENDPOINTS ---
// =================================================================

// ในไฟล์ server.js, แทนที่ app.get('/api/properties', ...) เดิมด้วยโค้ดนี้

app.get('/api/properties', async (req, res) => {
    try {
        const page = parseInt(req.query.page || '1');
        const limit = parseInt(req.query.limit || '9');
        const offset = (page - 1) * limit;

        // --- 1. อ่านค่า Filter ใหม่ ---
        const { status, keyword, type, minPrice, maxPrice, type_of_sale } = req.query;

        let baseQuery = 'FROM properties';
        const conditions = [];
        const values = [];
        let counter = 1;

        // --- 2. สร้าง WHERE clause (เพิ่มเงื่อนไข type, minPrice, maxPrice, type_of_sale) ---
        if (status && status !== '') {
            conditions.push(`status = $${counter++}`);
            values.push(status);
        }
        if (keyword && typeof keyword === 'string' && keyword.trim() !== '') {
            const searchTerm = `%${keyword.toLowerCase()}%`;
            // ค้นหาทั้ง title และ description (ถ้าต้องการ)
            conditions.push(`(LOWER(title) LIKE $${counter} OR LOWER(description) LIKE $${counter})`);
            values.push(searchTerm);
            counter++; // เพิ่ม counter แค่ครั้งเดียวพอ เพราะ parameter index เหมือนกัน
        }
        if (type && typeof type === 'string' && type.trim() !== '' && type !== 'All') { // เพิ่มเงื่อนไข type
            conditions.push(`type = $${counter++}`);
            values.push(type);
        }
        if (type_of_sale && typeof type_of_sale === 'string' && type_of_sale.trim() !== '') {
            conditions.push(`type_of_sale = $${counter++}`);
            values.push(type_of_sale);
        }
        if (minPrice && !isNaN(parseFloat(minPrice))) { // ลบ as string ตรงนี้
        conditions.push(`price >= $${counter++}`);
        values.push(parseFloat(minPrice)); // ลบ as string ตรงนี้
}
        if (maxPrice && !isNaN(parseFloat(maxPrice))) { // ลบ as string ตรงนี้
        conditions.push(`price <= $${counter++}`);
        values.push(parseFloat(maxPrice)); // ลบ as string ตรงนี้
}

        if (conditions.length > 0) {
            baseQuery += ' WHERE ' + conditions.join(' AND ');
        }

        // --- ส่วนที่เหลือเหมือนเดิม (นับ Total, ดึงข้อมูล, ส่ง Response) ---
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

app.get('/api/properties/featured', async (req, res) => {
    try {
        const limit = 4; // กำหนดจำนวนรายการที่จะดึง (เช่น 4)
        const query = `
            SELECT * FROM properties 
            ORDER BY created_at DESC 
            LIMIT $1
        `;
        const { rows } = await pool.query(query, [limit]);
        res.json(rows); // ส่งกลับเป็น Array ของ properties เลย
    } catch (error) {
        console.error('Error fetching featured properties:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

// [ 🔄 แทนที่ฟังก์ชันนี้ 🔄 ]
app.get('/api/properties/:id', async (req, res) => {
    try {
        const { id } = req.params;
        pool.query('UPDATE properties SET view_count = view_count + 1 WHERE id = $1', [id]);
        const propertyRes = await pool.query('SELECT * FROM properties WHERE id = $1', [id]);
        if (propertyRes.rows.length === 0) return res.status(404).json({ message: 'Property not found' });

        const imagesRes = await pool.query('SELECT id, image_url FROM property_images WHERE property_id = $1 ORDER BY created_at ASC', [id]);
        
        // --- [ ⬇️ เพิ่มส่วนนี้ ⬇️ ] ---
        // ดึง Amenities ที่ผูกกับ Property นี้
        const amenitiesQuery = `
            SELECT a.id, a.name, a.icon 
            FROM amenities a
            JOIN property_amenities pa ON a.id = pa.amenity_id
            WHERE pa.property_id = $1
            ORDER BY a.name;
        `;
        const amenitiesRes = await pool.query(amenitiesQuery, [id]);
        // --- [ ⬆️ สิ้นสุดส่วนที่เพิ่ม ⬆️ ] ---
        
        const property = propertyRes.rows[0];
        property.images = imagesRes.rows;
        property.amenities = amenitiesRes.rows; // ⭐️ ผูกข้อมูล Amenities เข้าไปด้วย

        res.json(property);
    } catch(error){
        console.error('Error fetching public single property:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

app.post('/api/contact', async (req, res) => {
    sgMail.setApiKey(process.env.SENDGRID_API_KEY);
    try {
        const { name, email, phone, message } = req.body;
        if (!name || !email || !message) {
            return res.status(400).json({ error: 'Name, email, and message are required.' });
        }
        const msg = {
            to: process.env.SENDGRID_SENDER_EMAIL,
            from: process.env.SENDGRID_SENDER_EMAIL,
            subject: `New Message from ${name} via Website`,
            html: `<p>Name: ${name}</p><p>Email: ${email}</p><p>Phone: ${phone || 'N/A'}</p><p>Message: ${message}</p>`,
        };
        await sgMail.send(msg);
        res.status(200).json({ success: true, message: 'Message sent successfully!' });
    } catch (error) {
        console.error('SendGrid Error:', error.response?.body);
        res.status(500).json({ error: 'Failed to send message.' });
    }
});

// --- ⬇️ [เพิ่มโค้ดนี้] ⬇️ ---
// API สำหรับบันทึก Log การค้นหา (Public)
app.post('/api/log-search', async (req, res) => {
  try {
    const { status, type, minPrice, maxPrice, keyword } = req.body;

    // แปลงค่าว่าง (empty string) หรือ undefined เป็น null
    const statusToLog = status || null;
    const typeToLog = type || null;
    const minPriceToLog = minPrice || null;
    const maxPriceToLog = maxPrice || null;
    const keywordToLog = keyword || null;

    const sql = `INSERT INTO search_logs (status, type, min_price, max_price, keyword)
                 VALUES ($1, $2, $3, $4, $5)`;

    await pool.query(sql, [statusToLog, typeToLog, minPriceToLog, maxPriceToLog, keywordToLog]);

    // ตอบกลับทันที (fire-and-forget)
    res.status(200).json({ success: true });

  } catch (error) {
    console.error('Error logging search:', error);
    // ถ้าการ log พัง ก็ไม่เป็นไร ไม่ต้องแจ้ง User
    res.status(500).json({ success: false }); 
  }
});
// --- ⬆️ [สิ้นสุดการเพิ่ม] ⬆️ ---

// =================================================================
// --- USER MANAGEMENT ROUTES ---
// =================================================================

// Get all users
adminRouter.get('/users', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC'
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Delete user
adminRouter.delete('/users/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    // ตรวจสอบว่าไม่ใช่ admin
    const userCheck = await pool.query('SELECT role FROM users WHERE id = $1', [id]);
    
    if (userCheck.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    if (userCheck.rows[0].role === 'admin') {
      return res.status(403).json({ error: 'Cannot delete admin user' });
    }
    
    await pool.query('DELETE FROM users WHERE id = $1', [id]);
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// =================================================================
// --- SERVER START ---
// =================================================================
// ==================== ADMIN DASHBOARD APIs ====================

// Get dashboard statistics
adminRouter.get('/stats', async (req, res) => {
    try {
        const totalProperties = await pool.query('SELECT COUNT(*) as count FROM properties');
        const totalUsers = await pool.query('SELECT COUNT(*) as count FROM users');
        const totalSold = await pool.query('SELECT COUNT(*) as count FROM transactions WHERE transaction_type = $1', ['Sold']);
        const totalRented = await pool.query('SELECT COUNT(*) as count FROM transactions WHERE transaction_type = $1', ['Rented']);
        const totalRevenue = await pool.query('SELECT COALESCE(SUM(final_price), 0) as total FROM transactions WHERE transaction_type = $1', ['Sold']);
        const totalRentRevenue = await pool.query('SELECT COALESCE(SUM(final_price), 0) as total FROM transactions WHERE transaction_type = $1', ['Rented']);

        res.json({
            totalProperties: parseInt(totalProperties.rows[0].count),
            totalUsers: parseInt(totalUsers.rows[0].count),
            totalSold: parseInt(totalSold.rows[0].count),
            totalRented: parseInt(totalRented.rows[0].count),
            totalRevenue: parseFloat(totalRevenue.rows[0].total),
            totalRentRevenue: parseFloat(totalRentRevenue.rows[0].total)
        });
    } catch (error) {
        console.error('Error fetching stats:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get properties by type
app.get('/api/admin/properties-by-type', async (req, res) => {
    try {
        const { rows } = await pool.query(`
            SELECT type, COUNT(*) as count 
            FROM properties 
            GROUP BY type
            ORDER BY count DESC
        `);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching properties by type:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get search statistics
app.get('/api/admin/search-stats', async (req, res) => {
    try {
        const { rows } = await pool.query(`
            SELECT 
                keyword,
                COUNT(*) as count
            FROM search_logs
            WHERE keyword IS NOT NULL AND keyword != ''
            GROUP BY keyword
            ORDER BY count DESC
            LIMIT 10
        `);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching search stats:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get revenue statistics
app.get('/api/admin/revenue-stats', async (req, res) => {
    try {
        const { rows } = await pool.query(`
            SELECT 
                TO_CHAR(transaction_date, 'YYYY-MM') as month,
                transaction_type,
                SUM(final_price) as revenue
            FROM transactions
            GROUP BY TO_CHAR(transaction_date, 'YYYY-MM'), transaction_type
            ORDER BY month DESC
            LIMIT 12
        `);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching revenue stats:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get all properties (admin)
app.get('/api/admin/properties', async (req, res) => {
    try {
        const { keyword, status } = req.query;
        let query = 'SELECT * FROM properties WHERE 1=1';
        const params = [];

        if (keyword) {
            params.push(`%${keyword}%`);
            query += ` AND (title ILIKE $${params.length} OR location ILIKE $${params.length})`;
        }

        if (status) {
            params.push(status);
            query += ` AND status = $${params.length}`;
        }

        query += ' ORDER BY created_at DESC';

        const { rows } = await pool.query(query, params);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching admin properties:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get single property (admin)
app.get('/api/admin/properties/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { rows } = await pool.query('SELECT * FROM properties WHERE id = $1', [id]);
        
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Property not found' });
        }

        // Get amenities
        const amenitiesResult = await pool.query(`
            SELECT a.* FROM amenities a
            JOIN property_amenities pa ON a.id = pa.amenity_id
            WHERE pa.property_id = $1
        `, [id]);

        // Get images
        const imagesResult = await pool.query(
            'SELECT * FROM property_images WHERE property_id = $1 ORDER BY display_order',
            [id]
        );

        res.json({
            ...rows[0],
            amenities: amenitiesResult.rows,
            images: imagesResult.rows
        });
    } catch (error) {
        console.error('Error fetching property:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get all amenities
app.get('/api/admin/amenities', async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT * FROM amenities ORDER BY name');
        res.json(rows);
    } catch (error) {
        console.error('Error fetching amenities:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Create new property
app.post('/api/admin/properties', async (req, res) => {
    try {
        const {
            title, description, type, status, price, location,
            bedrooms, bathrooms, area, main_image, is_featured, amenities
        } = req.body;

        const { rows } = await pool.query(`
            INSERT INTO properties (
                title, description, type, status, price, location,
                bedrooms, bathrooms, area, main_image, is_featured
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *
        `, [title, description, type, status, price, location, bedrooms, bathrooms, area, main_image, is_featured]);

        const property = rows[0];

        // Add amenities if provided
        if (amenities && amenities.length > 0) {
            for (const amenityId of amenities) {
                await pool.query(
                    'INSERT INTO property_amenities (property_id, amenity_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                    [property.id, amenityId]
                );
            }
        }

        res.status(201).json(property);
    } catch (error) {
        console.error('Error creating property:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Update property
app.put('/api/admin/properties/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const {
            title, description, type, status, price, location,
            bedrooms, bathrooms, area, main_image, is_featured, amenities
        } = req.body;

        const { rows } = await pool.query(`
            UPDATE properties SET
                title = $1, description = $2, type = $3, status = $4,
                price = $5, location = $6, bedrooms = $7, bathrooms = $8,
                area = $9, main_image = $10, is_featured = $11, updated_at = NOW()
            WHERE id = $12
            RETURNING *
        `, [title, description, type, status, price, location, bedrooms, bathrooms, area, main_image, is_featured, id]);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Property not found' });
        }

        // Update amenities
        if (amenities) {
            await pool.query('DELETE FROM property_amenities WHERE property_id = $1', [id]);
            for (const amenityId of amenities) {
                await pool.query(
                    'INSERT INTO property_amenities (property_id, amenity_id) VALUES ($1, $2)',
                    [id, amenityId]
                );
            }
        }

        res.json(rows[0]);
    } catch (error) {
        console.error('Error updating property:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete property
app.delete('/api/admin/properties/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { rows } = await pool.query('DELETE FROM properties WHERE id = $1 RETURNING *', [id]);
        
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Property not found' });
        }

        res.json({ message: 'Property deleted successfully' });
    } catch (error) {
        console.error('Error deleting property:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Close deal (sell/rent property)
app.post('/api/admin/properties/:id/close-deal', async (req, res) => {
    try {
        const { id } = req.params;
        const { transaction_type, final_price, user_id } = req.body;

        // Update property status
        const statusMap = {
            'Sold': 'Sold',
            'Rented': 'Rented'
        };
        
        await pool.query(
            'UPDATE properties SET status = $1, updated_at = NOW() WHERE id = $2',
            [statusMap[transaction_type], id]
        );

        // Create transaction record
        const { rows } = await pool.query(`
            INSERT INTO transactions (property_id, transaction_type, final_price, user_id)
            VALUES ($1, $2, $3, $4)
            RETURNING *
        `, [id, transaction_type, final_price, user_id]);

        res.json(rows[0]);
    } catch (error) {
        console.error('Error closing deal:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ⭐️ RESET PROPERTIES ENDPOINT (Development only - protect in production!)
app.post('/api/admin/reset-properties', async (req, res) => {
  try {
    console.log('⭐️ Adding type_of_sale column if not exists...');
    await pool.query(`
      ALTER TABLE properties 
      ADD COLUMN IF NOT EXISTS type_of_sale VARCHAR(20) DEFAULT 'For Sale'
    `);
    
    console.log('🗑️  Deleting all existing properties...');
    await pool.query('DELETE FROM properties');
    
    console.log('📝 Creating new sample properties...');
    
    const properties = [
      // FOR SALE Properties (10 properties)
      { title: 'Luxury Pool Villa Surin', description: 'Stunning 3-bedroom pool villa in Surin Beach area. Modern design with sea view.', price: 15000000, price_period: null, type: 'Villa', bedrooms: 3, bathrooms: 3, area: 250, location: 'Surin, Phuket', status: 'Available', type_of_sale: 'For Sale', main_image_url: 'https://images.unsplash.com/photo-1613490493576-7fde63acd811?w=800' },
      { title: 'Modern Condo Laguna Complex', description: 'Brand new 2-bedroom condo in prestigious Laguna area with golf course view.', price: 6000000, price_period: null, type: 'Condo', bedrooms: 2, bathrooms: 2, area: 85, location: 'Laguna, Phuket', status: 'Available', type_of_sale: 'For Sale', main_image_url: 'https://images.unsplash.com/photo-1545324418-cc1a3fa10c00?w=800' },
      { title: 'Beachfront Villa Bang Tao', description: 'Exclusive beachfront villa with private beach access. 5 bedrooms with infinity pool.', price: 25000000, price_period: null, type: 'Villa', bedrooms: 5, bathrooms: 4, area: 400, location: 'Bang Tao, Phuket', status: 'Available', type_of_sale: 'For Sale', main_image_url: 'https://images.unsplash.com/photo-1512917774080-9991f1c4c750?w=800' },
      { title: 'Family Villa Rawai', description: 'Perfect family home with 4 bedrooms, large garden and pool in peaceful Rawai.', price: 12000000, price_period: null, type: 'Villa', bedrooms: 4, bathrooms: 3, area: 300, location: 'Rawai, Phuket', status: 'Available', type_of_sale: 'For Sale', main_image_url: 'https://images.unsplash.com/photo-1600596542815-ffad4c1539a9?w=800' },
      { title: 'Penthouse Panorama Patong', description: 'Luxury penthouse with 360° panoramic views of Patong Bay. 3 bedrooms, rooftop terrace.', price: 18000000, price_period: null, type: 'Condo', bedrooms: 3, bathrooms: 3, area: 180, location: 'Patong, Phuket', status: 'Reserved', type_of_sale: 'For Sale', main_image_url: 'https://images.unsplash.com/photo-1600607687939-ce8a6c25118c?w=800' },
      { title: 'Tropical House Kamala', description: 'Charming tropical house near Kamala Beach. 3 bedrooms with lush garden.', price: 9500000, price_period: null, type: 'House', bedrooms: 3, bathrooms: 2, area: 200, location: 'Kamala, Phuket', status: 'Available', type_of_sale: 'For Sale', main_image_url: 'https://images.unsplash.com/photo-1600585154340-be6161a56a0c?w=800' },
      { title: 'Investment Land Chalong', description: 'Prime development land in Chalong area. 2 rai with road access and utilities.', price: 8000000, price_period: null, type: 'Land', bedrooms: null, bathrooms: null, area: 3200, location: 'Chalong, Phuket', status: 'Available', type_of_sale: 'For Sale', main_image_url: 'https://images.unsplash.com/photo-1500382017468-9049fed747ef?w=800' },
      { title: 'Townhouse Complex Kathu', description: 'Modern 3-bedroom townhouse in secure complex with communal pool and gym.', price: 4500000, price_period: null, type: 'Townhouse', bedrooms: 3, bathrooms: 2, area: 120, location: 'Kathu, Phuket', status: 'Available', type_of_sale: 'For Sale', main_image_url: 'https://images.unsplash.com/photo-1600047509807-ba8f99d2cdde?w=800' },
      { title: 'Studio Apartment Karon Beach', description: 'Cozy studio apartment just 200m from Karon Beach. Perfect for investment.', price: 1800000, price_period: null, type: 'Apartment', bedrooms: 1, bathrooms: 1, area: 35, location: 'Karon, Phuket', status: 'Available', type_of_sale: 'For Sale', main_image_url: 'https://images.unsplash.com/photo-1522708323590-d24dbb6b0267?w=800' },
      { title: 'Shophouse Phuket Town', description: '3-story shophouse in old town. Ground floor commercial, 2 floors residential.', price: 10000000, price_period: null, type: 'Shophouse', bedrooms: 4, bathrooms: 3, area: 220, location: 'Phuket Town', status: 'Sold', type_of_sale: 'For Sale', main_image_url: 'https://images.unsplash.com/photo-1582268611958-ebfd161ef9cf?w=800' },
      
      // FOR RENT Properties (10 properties)
      { title: 'Seaside Condo Monthly Patong', description: 'Fully furnished 2-bedroom condo for long-term rent. Sea view, pool, gym.', price: 35000, price_period: 'month', type: 'Condo', bedrooms: 2, bathrooms: 2, area: 75, location: 'Patong, Phuket', status: 'Available', type_of_sale: 'For Rent', main_image_url: 'https://images.unsplash.com/photo-1502672260266-1c1ef2d93688?w=800' },
      { title: 'Garden Villa Long-term Cherngtalay', description: 'Beautiful 3-bedroom villa with garden. Available for 1-year lease.', price: 60000, price_period: 'month', type: 'Villa', bedrooms: 3, bathrooms: 3, area: 220, location: 'Cherngtalay, Phuket', status: 'Available', type_of_sale: 'For Rent', main_image_url: 'https://images.unsplash.com/photo-1600585154526-990dced4db0d?w=800' },
      { title: 'Budget Room Phuket Town', description: 'Affordable 1-bedroom apartment in town center. Perfect for workers.', price: 800, price_period: 'month', type: 'Apartment', bedrooms: 1, bathrooms: 1, area: 28, location: 'Phuket Town', status: 'Available', type_of_sale: 'For Rent', main_image_url: 'https://images.unsplash.com/photo-1560448204-e02f11c3d0e2?w=800' },
      { title: 'Romantic Hideaway Kamala', description: 'Cozy 2-bedroom house with mountain view. Peaceful location, pets allowed.', price: 28000, price_period: 'month', type: 'House', bedrooms: 2, bathrooms: 2, area: 90, location: 'Kamala, Phuket', status: 'Available', type_of_sale: 'For Rent', main_image_url: 'https://images.unsplash.com/photo-1600566753190-17f0baa2a6c3?w=800' },
      { title: 'Luxury Pool Villa Nai Harn', description: 'Premium 4-bedroom pool villa near Nai Harn Beach. Fully serviced.', price: 120000, price_period: 'month', type: 'Villa', bedrooms: 4, bathrooms: 4, area: 320, location: 'Nai Harn, Phuket', status: 'Reserved', type_of_sale: 'For Rent', main_image_url: 'https://images.unsplash.com/photo-1600607687920-4e2a09cf159d?w=800' },
      { title: 'Office Space Central Festival', description: 'Modern office space in Central Festival area. 80 sqm with parking.', price: 45000, price_period: 'month', type: 'Commercial', bedrooms: null, bathrooms: 2, area: 80, location: 'Phuket Town', status: 'Available', type_of_sale: 'For Rent', main_image_url: 'https://images.unsplash.com/photo-1497366216548-37526070297c?w=800' },
      { title: 'Student Studio Near University', description: 'Perfect for students. Furnished studio with WiFi, near PSU campus.', price: 6500, price_period: 'month', type: 'Apartment', bedrooms: 1, bathrooms: 1, area: 22, location: 'Kathu, Phuket', status: 'Available', type_of_sale: 'For Rent', main_image_url: 'https://images.unsplash.com/photo-1554995207-c18c203602cb?w=800' },
      { title: 'Family House Rawai', description: '3-bedroom house with yard. Great for families. Near international school.', price: 42000, price_period: 'month', type: 'House', bedrooms: 3, bathrooms: 2, area: 160, location: 'Rawai, Phuket', status: 'Available', type_of_sale: 'For Rent', main_image_url: 'https://images.unsplash.com/photo-1600585154084-4e5fe7c39198?w=800' },
      { title: 'Penthouse Laguna Area', description: 'Exclusive penthouse with private pool. 3 bedrooms, stunning views.', price: 95000, price_period: 'month', type: 'Condo', bedrooms: 3, bathrooms: 3, area: 200, location: 'Laguna, Phuket', status: 'Available', type_of_sale: 'For Rent', main_image_url: 'https://images.unsplash.com/photo-1600607687644-c7171b42498b?w=800' },
      { title: 'Townhouse Chalong', description: 'Modern 2-bedroom townhouse in gated community. Pool and security.', price: 25000, price_period: 'month', type: 'Townhouse', bedrooms: 2, bathrooms: 2, area: 100, location: 'Chalong, Phuket', status: 'Available', type_of_sale: 'For Rent', main_image_url: 'https://images.unsplash.com/photo-1600047509358-9dc75507daeb?w=800' },
      
      // DAILY RENT Properties (10 properties)
      { title: 'Beach Condo Patong Daily', description: 'Beachfront condo perfect for vacation. 2 beds, fully equipped kitchen.', price: 4500, price_period: 'day', type: 'Condo', bedrooms: 2, bathrooms: 2, area: 65, location: 'Patong, Phuket', status: 'Available', type_of_sale: 'Daily Rent', main_image_url: 'https://images.unsplash.com/photo-1611892440504-42a792e24d32?w=800' },
      { title: 'Holiday Villa Kata Daily', description: 'Private pool villa for daily rental. Perfect for families. 3 bedrooms.', price: 8500, price_period: 'day', type: 'Villa', bedrooms: 3, bathrooms: 3, area: 180, location: 'Kata, Phuket', status: 'Available', type_of_sale: 'Daily Rent', main_image_url: 'https://images.unsplash.com/photo-1602343168117-bb8ffe3e2e9f?w=800' },
      { title: 'Luxury Suite Surin Beach', description: 'Beachfront luxury suite with ocean view. Daily housekeeping included.', price: 12000, price_period: 'day', type: 'Condo', bedrooms: 2, bathrooms: 2, area: 95, location: 'Surin, Phuket', status: 'Available', type_of_sale: 'Daily Rent', main_image_url: 'https://images.unsplash.com/photo-1616594039964-ae9021a400a0?w=800' },
      { title: 'Cozy Studio Karon Daily', description: 'Affordable studio for solo travelers or couples. Pool access.', price: 1800, price_period: 'day', type: 'Apartment', bedrooms: 1, bathrooms: 1, area: 30, location: 'Karon, Phuket', status: 'Available', type_of_sale: 'Daily Rent', main_image_url: 'https://images.unsplash.com/photo-1595526114035-0d45ed16cfbf?w=800' },
      { title: 'Sunset Villa Kamala Beach', description: 'Stunning sunset views! 4-bedroom villa with infinity pool.', price: 15000, price_period: 'day', type: 'Villa', bedrooms: 4, bathrooms: 4, area: 280, location: 'Kamala, Phuket', status: 'Reserved', type_of_sale: 'Daily Rent', main_image_url: 'https://images.unsplash.com/photo-1600585154363-67eb9e2e2099?w=800' },
      { title: 'Party Villa Bang Tao', description: 'Large villa for groups up to 12 guests. Private pool, BBQ area.', price: 18000, price_period: 'day', type: 'Villa', bedrooms: 6, bathrooms: 5, area: 450, location: 'Bang Tao, Phuket', status: 'Available', type_of_sale: 'Daily Rent', main_image_url: 'https://images.unsplash.com/photo-1600607687939-ce8a6c25118c?w=800' },
      { title: 'Seaview Apartment Kalim', description: 'Modern apartment with sea view. 2 bedrooms, walking distance to beach.', price: 3200, price_period: 'day', type: 'Apartment', bedrooms: 2, bathrooms: 1, area: 55, location: 'Kalim, Phuket', status: 'Available', type_of_sale: 'Daily Rent', main_image_url: 'https://images.unsplash.com/photo-1600566752355-35792bedcfea?w=800' },
      { title: 'Budget Room Near Beach', description: 'Clean and comfortable room for budget travelers. 5 min to Patong Beach.', price: 800, price_period: 'day', type: 'Apartment', bedrooms: 1, bathrooms: 1, area: 20, location: 'Patong, Phuket', status: 'Available', type_of_sale: 'Daily Rent', main_image_url: 'https://images.unsplash.com/photo-1631049307264-da0ec9d70304?w=800' },
      { title: 'Honeymoon Suite Nai Harn', description: 'Romantic suite with private jacuzzi. Perfect for couples.', price: 6500, price_period: 'day', type: 'Condo', bedrooms: 1, bathrooms: 1, area: 50, location: 'Nai Harn, Phuket', status: 'Available', type_of_sale: 'Daily Rent', main_image_url: 'https://images.unsplash.com/photo-1618773928121-c32242e63f39?w=800' },
      { title: 'Penthouse Daily Laguna', description: 'Luxury penthouse for short stays. Rooftop pool, golf course view.', price: 22000, price_period: 'day', type: 'Condo', bedrooms: 3, bathrooms: 3, area: 220, location: 'Laguna, Phuket', status: 'Available', type_of_sale: 'Daily Rent', main_image_url: 'https://images.unsplash.com/photo-1600585154340-be6161a56a0c?w=800' }
    ];

    // Insert all properties
    for (const prop of properties) {
      await pool.query(`
        INSERT INTO properties (
          title, description, price, price_period, type, bedrooms, bathrooms, 
          area, location, status, type_of_sale, main_image_url, view_count, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW())
      `, [
        prop.title, prop.description, prop.price, prop.price_period, prop.type,
        prop.bedrooms, prop.bathrooms, prop.area, prop.location, prop.status,
        prop.type_of_sale, prop.main_image_url,
        Math.floor(Math.random() * 800) + 100 // Random view count
      ]);
    }

    const summary = await pool.query(`
      SELECT type_of_sale, COUNT(*) as count 
      FROM properties 
      GROUP BY type_of_sale
    `);

    res.json({ 
      success: true, 
      message: `Successfully created ${properties.length} properties`,
      summary: summary.rows
    });
  } catch (error) {
    console.error('Reset properties error:', error);
    res.status(500).json({ error: 'Failed to reset properties' });
  }
});

// ==================== END ADMIN APIs ====================

// Create favorites table if not exists
async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS favorites (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        property_id INTEGER NOT NULL REFERENCES properties(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, property_id)
      )
    `);
    
    // Add full_name and phone columns to users table if they don't exist
    await pool.query(`
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS full_name VARCHAR(255),
      ADD COLUMN IF NOT EXISTS phone VARCHAR(20)
    `);
    
    // Add type_of_sale column to properties table if it doesn't exist
    await pool.query(`
      ALTER TABLE properties 
      ADD COLUMN IF NOT EXISTS type_of_sale VARCHAR(20) DEFAULT 'For Sale'
    `);
    
    // Update properties based on their titles
    await pool.query(`
      UPDATE properties 
      SET type_of_sale = 'Daily Rent' 
      WHERE LOWER(title) LIKE '%daily%'
    `);
    
    await pool.query(`
      UPDATE properties 
      SET type_of_sale = 'For Rent' 
      WHERE LOWER(title) LIKE '%rent%' 
      AND LOWER(title) NOT LIKE '%daily%'
      AND type_of_sale != 'Daily Rent'
    `);
    
    await pool.query(`
      UPDATE properties 
      SET type_of_sale = 'For Sale' 
      WHERE (LOWER(title) LIKE '%sale%' OR type_of_sale = 'For Sale')
      AND LOWER(title) NOT LIKE '%rent%'
    `);
    
    console.log('✅ Database tables initialized successfully');
  } catch (error) {
    console.error('❌ Error initializing database:', error);
  }
}

initializeDatabase();
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});