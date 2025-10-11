import pg from 'pg';
import bcrypt from 'bcryptjs';
import 'dotenv/config';

const { Pool } = pg;

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

async function createAdmin() {
    const username = 'admin';
    const password = 'password123'; // <-- ตั้งรหัสผ่านที่คุณต้องการใช้ล็อกอิน
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPassword]);
        console.log('✅ Admin user created successfully!');
        console.log(`Username: ${username}`);
        console.log(`Password: ${password}`);
    } catch (error) {
        console.error('Error creating admin user:', error);
    } finally {
        pool.end();
    }
}

createAdmin();