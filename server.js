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

adminRouter.get('/stats', async (req, res) => {
    try {
        const statsQuery = `
            SELECT
                COUNT(*) AS total_properties,
                SUM(CASE WHEN status = 'For Sale' THEN 1 ELSE 0 END) AS for_sale,
                SUM(CASE WHEN status = 'For Rent' THEN 1 ELSE 0 END) AS for_rent
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

adminRouter.get('/properties/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const propertyRes = await pool.query('SELECT * FROM properties WHERE id = $1', [id]);
        if (propertyRes.rows.length === 0) return res.status(404).json({ message: 'Property not found' });
        
        const imagesRes = await pool.query('SELECT id, image_url FROM property_images WHERE property_id = $1 ORDER BY created_at ASC', [id]);
        
        const property = propertyRes.rows[0];
        property.images = imagesRes.rows;

        res.json(property);
    } catch (error) {
        console.error('Error fetching single property:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

// POST (Create new property)
adminRouter.post('/properties', async (req, res) => {
    try {
        // --- ⬇️ [แก้ไข] เพิ่ม main_image_public_id จาก req.body ---
        const { title, status, price, main_image_url, main_image_public_id, price_period, bedrooms, bathrooms, area_sqm, description } = req.body;
        const sql = `INSERT INTO properties (title, status, price, main_image_url, main_image_public_id, price_period, bedrooms, bathrooms, area_sqm, description) 
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`;
        const values = [title, status, price, main_image_url, main_image_public_id, price_period, bedrooms, bathrooms, area_sqm, description];
        // --- ⬆️ [แก้ไข] ---

        const { rows } = await pool.query(sql, values);
        res.status(201).json({ message: 'Property created successfully', id: rows[0].id });
    } catch (error) {
        console.error('Error creating property:', error);
        res.status(500).json({ error: 'Database query failed' });
    }
});

// PUT (Update property by id)
adminRouter.put('/properties/:id', async (req, res) => {
    try {
        const { id } = req.params;

        // --- ⬇️ [แก้ไข] รับ 'old_main_image_public_id' เพิ่ม ---
        const { 
            title, status, price, main_image_url, main_image_public_id, 
            price_period, bedrooms, bathrooms, area_sqm, description,
            old_main_image_public_id // ⭐️ รับค่าใหม่นี้จาก Frontend
        } = req.body;

        const sql = `UPDATE properties SET 
                        title = $1, status = $2, price = $3, main_image_url = $4, main_image_public_id = $5, 
                        price_period = $6, bedrooms = $7, bathrooms = $8, area_sqm = $9, description = $10 
                     WHERE id = $11`;
        const values = [
            title, status, price, main_image_url, main_image_public_id, 
            price_period, bedrooms, bathrooms, area_sqm, description, id
        ];
        // --- ⬆️ [แก้ไข] ---

        // 1. อัปเดตฐานข้อมูล
        const { rowCount } = await pool.query(sql, values);
        if (rowCount === 0) {
            return res.status(404).json({ message: 'Property not found' });
        }

        // --- ⬇️ [เพิ่ม] Logic การลบรูปเก่าออกจาก Cloudinary ---
        // 2. ถ้ามีการส่ง 'old_main_image_public_id' มา (แปลว่ามีการเปลี่ยนรูป) ให้ลบไฟล์เก่าทิ้ง
        if (old_main_image_public_id) {
            try {
                console.log(`Deleting old main image: ${old_main_image_public_id}`);
                await cloudinary.uploader.destroy(old_main_image_public_id);
            } catch (cldError) {
                // ไม่ต้องหยุดการทำงานหลัก แค่ log error ไว้
                // เพราะ DB อัปเดตสำเร็จแล้ว (รูปใหม่อยู่ในระบบแล้ว)
                console.warn('Cloudinary destroy error (old image may be deleted):', cldError.message);
            }
        }
        // --- ⬆️ [เพิ่ม] ---

        res.json({ message: 'Property updated successfully' });

    } catch (error) {
        console.error('Error updating property:', error);
        res.status(500).json({ error: 'Database query failed' });
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

app.get('/api/properties/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const propertyRes = await pool.query('SELECT * FROM properties WHERE id = $1', [id]);
        if (propertyRes.rows.length === 0) return res.status(404).json({ message: 'Property not found' });

        const imagesRes = await pool.query('SELECT id, image_url FROM property_images WHERE property_id = $1 ORDER BY created_at ASC', [id]);
        
        const property = propertyRes.rows[0];
        property.images = imagesRes.rows;

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

// =================================================================
// --- SERVER START ---
// =================================================================
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});