const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('../db/connection');

const secretKey = process.env.JWT_SECRET;

exports.register = async (request, h) => {
    const { username, password } = request.payload;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await pool.execute(
            'INSERT INTO users (username, password) VALUES (?, ?)', 
            [username, hashedPassword]
        );
        return h.response({ message: 'User registered successfully' }).code(201);
    } catch (error) {
        console.error(error);
        return h.response({ error: 'Error registering user' }).code(500);
    }
};

exports.login = async (request, h) => {
    const { username, password } = request.payload;
    try {
        const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);
        if (rows.length === 0) return h.response({ error: 'User not found' }).code(404);

        const user = rows[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) return h.response({ error: 'Invalid credentials' }).code(401);

        const token = jwt.sign({ id: user.id, username: user.username }, secretKey, { expiresIn: '1h' });
        return h.response({ token }).code(200);
    } catch (error) {
        console.error(error);
        return h.response({ error: 'Error logging in' }).code(500);
    }
};