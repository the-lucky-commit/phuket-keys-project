import express from 'express';
import 'dotenv/config';
import cors from 'cors';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';
import sgMail from '@sendgrid/mail';


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
        const imageUrls = results.map(result => result.secure_url);

        const insertPromises = imageUrls.map(url => {
            return pool.query('INSERT INTO property_images (property_id, image_url) VALUES ($1, $2)', [id, url]);
        });

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
        // Optional: Delete from Cloudinary as well if needed
        const { rowCount } = await pool.query('DELETE FROM property_images WHERE id = $1', [imageId]);
        if (rowCount === 0) {
            return res.status(404).json({ message: 'Image not found' });
        }
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
    res.status(200).json({ imageUrl: result.secure_url });
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
        
        const { status, keyword } = req.query;

        let baseQuery = 'FROM properties';
        const conditions = [];
        // --- แก้ไขตรงนี้: ลบ ': any[]' ออก ---
        const values = []; 
        let counter = 1;

        if (status && status !== '') { 
            conditions.push(`status = $${counter++}`); 
            values.push(status); 
        }
        if (keyword && typeof keyword === 'string' && keyword.trim() !== '') { 
            const searchTerm = `%${keyword.toLowerCase()}%`;
            conditions.push(`(LOWER(title) LIKE $${counter++} OR LOWER(description) LIKE $${counter})`); 
            values.push(searchTerm, searchTerm); 
            counter++;
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