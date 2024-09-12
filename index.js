const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const PORT = process.env.PORT || 5000;
const http = require('http');
const path = require('path'); // Ensure you include the path module
const fs = require('fs'); // Ensure you include the fs module
const jwt = require('jsonwebtoken'); // Ensure you include jwt module
const authRoutes = require('./routes/authRoutes');
const fileShareRoutes = require('./routes/fileShareRoutes');

require('./db');
require('./models/userModel');
require('./models/verificationModel');
require('dotenv').config();


const app = express(); // Create Express app
const server = http.createServer(app); // Create HTTP server using Express app


// Increase payload size limit
app.use(bodyParser.json({ limit: '10mb' })); // For JSON payloads
app.use(bodyParser.urlencoded({ limit: '10mb', extended: true })); // For URL-encoded payloads


// CORS Configuration
const allowedOrigins = [process.env.LOCAL_HOST]; // Frontend URL for local development
app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true); // Allow requests without origin (like Postman)
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true // Allow credentials (cookies) to be sent cross-origin
}));

app.use(bodyParser.json());
app.use(cookieParser({
  httpOnly: true, // Disallow cookies to be accessed via client-side scripts
  secure: true, // Only send cookies over HTTPS
  sameSite: 'none', // Only send cookies if the request is cross-site
  maxAge: 1000 * 60 * 60 * 24 * 7, // Set cookie max age to 7 days (in milliseconds)
  signed: true, // Enable signed cookies (using signature)
}));
app.use('/public', express.static('public'));

// Middleware to check for valid JWT
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;
  
  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  jwt.verify(token, process.env.JWT_SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token.' });
    }
    req.user = user;
    next();
  });
};

app.use((req, res, next) => {
  next();
});

app.use('/auth', authRoutes);
app.use('/file', fileShareRoutes);

// Route to serve files securely
app.get('/file/:filename', authenticateToken, (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(__dirname, 'public', 'uploads', filename);

  // Check if the file exists
  fs.access(filePath, fs.constants.F_OK, (err) => {
    if (err) {
      return res.status(404).json({ message: 'File not found.' });
    }
    res.sendFile(filePath);
  });
});

app.get('/', (req, res) => {
  res.send('API is running...');
});

server.listen(PORT, () => {
  console.log(`Server running`);
});
