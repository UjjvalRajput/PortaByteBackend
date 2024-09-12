const express = require('express'); // import express
const router = express.Router(); // create express router
const User = require('../models/userModel'); // import user model
const Verification = require('../models/verificationModel'); // import verification model
const responseFunction = require('../utils/responseFunction'); // import response functions
const fs = require('fs'); // import file system module
const bcrypt = require('bcrypt'); // import bcrypt
const jwt = require('jsonwebtoken'); // import jsonwebtoken
const nodemailer = require('nodemailer'); // import nodemailer
const multur = require('multer'); // import multer
const errorHandler = require('../middlewares/errorMiddleware'); // import error handler
const authTokenHandler = require('../middlewares/checkAuthToken'); // import auth token handler
const { body, validationResult } = require('express-validator'); // import express validator
require('dotenv').config(); // import dotenv


async function sendVerificationEmail(receiverEmail, code) { // send verification email
    const transporter = nodemailer.createTransport({ // create transporter
        service: 'gmail', 
        host: 'smtp.gmail.com', // host
        secure: true, // use SSL/TLS
        port: 465, // port for SSL/TLS
        auth: { // authentication
            user: process.env.EMAIL, // email
            pass: process.env.PASSWORD, // password
        },
    });

    const mailOptions = { // mail options
        from: process.env.EMAIL, // from
        to: receiverEmail, // to
        subject: 'PortaByte: Email Verification', // subject
        text: `Your verification code is ${code}`, // text
    };

    try {
        // Send mail
        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent:', info.response);
    } catch (error) {
        console.error('Error sending email:', error);
    }
} // send verification email

const storage = multur.diskStorage({ // storage
    destination: (req, file, cb) => { // destination
        cb(null, './public/uploads'); // callback
    },
    filename: (req, file, cb) => { // filename
        cb(null, `${Date.now()}-${file.originalname}`); // callback
    },
}); // storage for multer upload function

const upload = multur({ storage: storage }); // upload

const fileUploadFunction = (req, res, next) => { // file upload function
    upload.single('clientFile')(req, res, (err) => { // upload file
        if (err) { // if error
            return responseFunction(res, 400, 'File upload failed', null, false); // send response
        }
        next(); // pass to next middleware
    });
} // file upload function

router.get('/test', (req, res) => { // test route
    res.send('Auth route is working...'); // send response
}); // test route

router.post('/verification-code', // verification code route
    body('email').isEmail().withMessage('Invalid email address'), // validate email address 
    async (req, res) => { 
        // Validate request
        const errors = validationResult(req); // get validation errors
        if (!errors.isEmpty()) { // if errors exist
            return responseFunction(res, 400, 'Invalid request data', errors.array(), false); // send response
        }

        const { email } = req.body; // get email from request
        try {
            // Check if there's an existing verification code and delete if it is still valid
            const existingVerification = await Verification.findOne({ email });
            if (existingVerification && existingVerification.expiresAt > new Date()) {
                // If a valid code exists, delete it
                await Verification.deleteOne({ email });
            }
            const code = Math.floor(100000 + Math.random() * 900000).toString(); // generate code
            const expiresAt = new Date(Date.now() + 600000); // expires in 10 minutes
            
            await sendVerificationEmail(email, code); // send verification email
            // Create new verification record
            const verification = new Verification({ email, code, expiresAt }); // create verification record
            await verification.save(); // save verification record to database
            
            return responseFunction(res, 200, 'Verification code sent successfully', { expiresAt }, true); // send response
        }
        catch (error) {
            return responseFunction(res, 500, 'Internal server error', error, false); // send response
        }
    }
); // verification code route

router.post('/register', fileUploadFunction, async (req, res, next) => {
    // console.log(req.file);
    try {
        const { name, email, password, code } = req.body; // get name, email, password, code from request
        let user = await User.findOne({ email }); // find user by email
        let verificationQuery = await Verification.findOne({ email }); // find verification record by email
        if (user) { // if user exists
            if (req.file && req.file.path) { // if file exists
                fs.unlink(req.file.path, (err) => { // delete file
                    if (err) { // if error
                        console.error('Error deleting file:', err); // log error
                    } 
                    else {
                        console.log('File deleted successfully'); // log message
                    }
                });
            }
            // delete the verification code they used
            const existingVerification = await Verification.findOne({ email });
            if (existingVerification && existingVerification.expiresAt > new Date()) {
                // If a valid code exists, delete it
                await Verification.deleteOne({ email });
            }
            return responseFunction(res, 400, 'User already exists with that email', null, false); // send response
        }
        if (!verificationQuery) { // if verification record does not exist
            if (req.file && req.file.path) { // if file exists
                fs.unlink(req.file.path, (err) => { // delete file
                    if (err) { // if error
                        console.error('Error deleting file:', err); // log error
                    } 
                    else {
                        console.log('File deleted successfully'); // log message
                    }
                });
            }
            return responseFunction(res, 400, 'Email not verified', null, false); // send response
        }
        const isCodeValid = await bcrypt.compare(code, verificationQuery.code); // compare code
        if (!isCodeValid) { // if code is invalid
            if (req.file && req.file.path) { // if file exists
                fs.unlink(req.file.path, (err) => { // delete file
                    if (err) { // if error
                        console.error('Error deleting file:', err); // log error
                    } 
                    else {
                        console.log('File deleted successfully'); // log message
                    }
                });
            }
            return responseFunction(res, 400, 'Invalid verification code', null, false); // send response
        }
        if (verificationQuery.expiresAt < new Date()) { // if verification code is expired
            if (req.file && req.file.path) { // if file exists
                fs.unlink(req.file.path, (err) => { // delete file
                    if (err) { // if error
                        console.error('Error deleting file:', err); // log error
                    } 
                    else {
                        console.log('File deleted successfully'); // log message
                    }
                });
            }
            return responseFunction(res, 400, 'Verification code expired', null, false); // send response
        }
        user = new User({ name, email, password }); // create new user
        await user.save(); // save user to database
        await Verification.deleteOne({ email }); // delete verification record because email is verified now and user is registered
        return responseFunction(res, 200, 'User registered successfully', null, true); // send response
    }
    catch (error) { 
        return responseFunction(res, 500, 'Internal server error', error, false); // send response
    }
} // register route
); // register route

router.post('/update-password', async (req, res, next) => {
    try {
        const { email, password, code } = req.body; // get email, password, code from request
        let user = await User.findOne({ email }); // find user by email
        let verificationQuery = await Verification.findOne
        ({ email }); // find verification record by email
        if (!verificationQuery) { // if verification record does not exist
            return responseFunction(res, 400, 'Email not verified', null, false); // send response
        }
        const isCodeValid = await bcrypt.compare(code, verificationQuery.code); // compare code
        if (!isCodeValid) { // if code is invalid
            return responseFunction(res, 400, 'Invalid verification code', null, false); // send response
        }
        if (verificationQuery.expiresAt < new Date()) { // if verification code is expired
            return responseFunction(res, 400, 'Verification code expired', null, false); // send response
        }
        user.password = password; // update password
        await user.save(); // save user to database
        await Verification.deleteOne
        ({ email }); // delete verification record because email is verified now and password is updated
        return responseFunction(res, 200, 'Password updated successfully', null, true); // send response
    }
    catch (error) {
        return responseFunction(res, 500, 'Internal server error', error, false); // send response
    }
}); // update password route

router.post('/login', async (req, res, next) => { // login route
    try {
        console.log('Login request received');
        const { email, password } = req.body; // get email, password from request
        const user = await User.findOne ({ email }); // find user by email
        if (!user) { // if user does not exist
            return responseFunction(res, 400, 'Invalid email or password credentials', null, false); // send response
        }
        const isPasswordValid = await bcrypt.compare(password, user.password); // compare password
        if (!isPasswordValid) { // if password is invalid
            return responseFunction(res, 400, 'Invalid email or password credentials', null, false); // send response
        }
        const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET_KEY, { expiresIn: '10m' }); // create token with email and secret key with 10 minutes expiry
        const refreshToken = jwt.sign({ email: user.email }, process.env.JWT_REFRESH_SECRET_KEY, { expiresIn: '1h' }); // create refresh token with email and secret key with 1 hour expiry

        res.cookie('token', token, { 
            httpOnly: true,
            secure: true,
            sameSite: 'none'
        }); // set token in cookie
        res.cookie('refreshToken', refreshToken, { 
            httpOnly: true ,
            secure: true,
            sameSite: 'none'
        }); // set refresh token in cookie

        return responseFunction(res, 200, 'User logged in successfully', { token, refreshToken }, true); // send response
    }
    catch (error) {
        return responseFunction(res, 500, 'Internal server error', error, false); // send response
    }
}); // login route

router.get('/check-login', authTokenHandler, async (req, res, next) => {
    res.json({
        user: req.user,
        success: req.success,
        message: req.message,
    });
}); // check login route

router.post('/logout', authTokenHandler, async (req, res, next) => {
    res.clearCookie('token');
    res.clearCookie('refreshToken');
    res.json({ success: true, message: 'User logged out successfully' });
}); // logout route

router.get('/get-user', authTokenHandler, async (req, res, next) => {
    try {
        const user = await User.findOne({ email: req.user }); // find user by email
        if (!user) { // if user does not exist
            return responseFunction(res, 400, 'User not found', null, false); // send response
        }
        return responseFunction(res, 200, 'User found', user, true); // send response
    }
    catch (error) {
        next(error); // pass error to error handler
    }
}); // get user route

router.use(errorHandler); // use error handler

module.exports = router; // export router
// Path: backend/routes/authRoutes.js