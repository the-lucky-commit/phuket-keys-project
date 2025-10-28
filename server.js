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

        // --- ⬇️ [แก้ไข SQL Query] ⬇️ ---
        // ⭐️ เพิ่มเงื่อนไข AND role = 'admin'
        const { rows } = await pool.query('SELECT * FROM users WHERE username = $1 AND role = $2', [username, 'admin']);
        // --- ⬆️ [สิ้นสุดการแก้ไข] ⬆️ ---

        if (rows.length === 0) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }
        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }
        // ⭐️ ส่ง role กลับไปด้วย (เผื่อ Frontend Admin อยากเช็ค)
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
        // ⭐️ 1. อัปเดต SQL query
        const statsQuery = `
            SELECT
                COUNT(*) AS total_properties,
                SUM(CASE WHEN status = 'For Sale' THEN 1 ELSE 0 END) AS for_sale,
                SUM(CASE WHEN status = 'For Rent' THEN 1 ELSE 0 END) AS for_rent,

                -- ⭐️ 2. เพิ่มการนับ 'availability' (ที่ลูกค้าต้องการ)
                SUM(CASE WHEN availability = 'Available' THEN 1 ELSE 0 END) AS available,
                SUM(CASE WHEN availability = 'Reserved' THEN 1 ELSE 0 END) AS reserved,

                -- ⭐️ 3. (Bonus) นับ "เช่ารายวัน" ที่เราเพิ่งเพิ่ม
                SUM(CASE WHEN status = 'For Rent (Daily)' THEN 1 ELSE 0 END) AS for_rent_daily
            FROM properties;
        `;
        const { rows } = await pool.query(statsQuery);
        res.json(rows[0]);
    } catch (error) {
        console.error('Error fetching dashboard stats:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

adminRouter.get('/properties', async (req, res) => {
    try {
        const { keyword, status } = req.query;

        let baseQuery = 'SELECT id, main_image_url, title, status, price, created_at FROM properties';
        const conditions = [];
        const values = [];
        let counter = 1;

        if (keyword) {
            conditions.push(`LOWER(title) LIKE $${counter++}`);
            values.push(`%${keyword.toLowerCase()}%`);
        }

        if (status && (status === 'For Sale' || status === 'For Rent')) {
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
        const { status, keyword, type, minPrice, maxPrice } = req.query;

        let baseQuery = 'FROM properties';
        const conditions = [];
        const values = [];
        let counter = 1;

        // --- 2. สร้าง WHERE clause (เพิ่มเงื่อนไข type, minPrice, maxPrice) ---
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
// --- SERVER START ---
// =================================================================
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});