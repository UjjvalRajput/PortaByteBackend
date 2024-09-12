const router = require('express').Router(); // import express router
const User = require('../models/userModel'); // import user model
const Verification = require('../models/verificationModel'); // import verification model
const responseFunction = require('../utils/responseFunction'); // import response functions
const fs = require('fs'); // import file system module
const bcrypt = require('bcrypt'); // import bcrypt
const jwt = require('jsonwebtoken'); // import jsonwebtoken
const nodemailer = require('nodemailer'); // import nodemailer
const multer = require('multer'); // import multer
const errorHandler = require('../middlewares/errorMiddleware'); // import error handler
const authTokenHandler = require('../middlewares/checkAuthToken'); // import auth token handler
const { body, validationResult } = require('express-validator'); // import express validator
const { S3Client, GetObjectCommand, PutObjectCommand } = require('@aws-sdk/client-s3'); // import S3Client, GetObjectCommand, PutObjectCommand
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner'); // import getSignedUrl
require('dotenv').config(); // import dotenv

const s3Client = new S3Client({ 
    region: process.env.AWS_REGION,
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    },
}); // create S3 client

async function sendNotificationEmail(receiverEmail, fileSenderEmail) { // send notification email
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
        subject: 'PortaByte: New File Received', // subject
        text: `PortaByte: You have received a new file from ${fileSenderEmail}`, // text
        html: `<p>PortaByte: You have received a new file from ${fileSenderEmail}</p>`, // html
    };

    try {
        // Send mail
        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent:', info.messageId);
        console.log('Preview URL:', nodemailer.getTestMessageUrl(info));
    } catch (error) {
        console.error('Error sending email:', error);
    }
} // send notification email

const getObjectUrl = async (key) => { // get object url
    const params = { // params
        Bucket: process.env.AWS_BUCKET_NAME, // bucket name
        Key: key, // key
    };

    return await getSignedUrl(s3Client, new GetObjectCommand(params)); // get signed url
} // get object url

const postObjectUrl = async (fileName, contentType) => { // post object url
    const params = { // params
        Bucket: process.env.AWS_BUCKET_NAME, // bucket name
        Key: fileName, // key
        ContentType: contentType, // content type
    };

    return await getSignedUrl(s3Client, new PutObjectCommand(params)); // get signed url
} // post object url

// const storage = multer.diskStorage({
//     destination: (req, file, cb) => {
//         cb(null, './public/uploads'); // callback
//     },
//     filename: (req, file, cb) => {
//         cb(null, `${Date.now()}-${file.originalname}`); // callback
//     },
// });

// const upload = multer({ storage: storage }); // upload function

// const fileUploadFunction = (req, res, next) => { // file upload function
//     upload.single('clientFile')(req, res, (err) => { // upload file
//         if (err) { // if error
//             return responseFunction(res, 400, 'File upload failed', null, false); // send response
//         }
//         next(); // pass to next middleware
//     });
// } // file upload function

router.get('/test', async (req, res) => { // test route
    let toUploadUrl = await postObjectUrl('test.pdf', '');
    res.json({
        toUploadUrl: toUploadUrl
    });
});

router.get('/generate-post-object-url', authTokenHandler, async (req, res, next) => { // generate post object url route
    try {
        const time = new Date().getTime(); // get current time
        const signedUrl = await postObjectUrl(time.toString(), ''); // get signed url
        return responseFunction(res, 200, 'Signed URL generated successfully', {
            signedUrl: signedUrl, // signed url
            fileKey: time.toString(), // file name
        }, true); // send response
    }
    catch (error) { // catch error
        return next(error); // pass to error handler
    }
});

// Validate the sender and receiver email
router.post('/validate-email', authTokenHandler, async (req, res, next) => {
    try {
      const { receiverEmail } = req.body;
      let sender = await User.findOne({ email: req.user });
      let receiver = await User.findOne({ email: receiverEmail });
  
      if (!sender) {
        return responseFunction(res, 404, 'Sender not found', null, false);
      }
      if (!receiver) {
        return responseFunction(res, 404, 'Receiver not registered with PortaByte', null, false);
      }
      if (sender.email === receiver.email) {
        return responseFunction(res, 400, 'Sender and receiver cannot be the same', null, false);
      }
  
      return responseFunction(res, 200, 'Email validation successful', null, true);
    } catch (error) {
      return next(error);
    }
  });

router.post('/share-file', authTokenHandler, async (req, res, next) => { // share file route
    const errors = validationResult(req); // get validation errors
    if (!errors.isEmpty()) { // if errors
        return responseFunction(res, 400, 'Validation failed', errors.array(), false); // send response
    }

    try {
        const { receiverEmail, fileName, fileKey, fileType } = req.body; // get receiver email, file name, file key, file type
        let sender = await User.findOne({ email: req.user }); // find sender
        let receiver = await User.findOne({ email: receiverEmail }); // find receiver
        if (!sender) { // if sender not found
            return responseFunction(res, 404, 'Sender not found', null, false); // send response
        }
        if (!receiver) { // if receiver not found
            return responseFunction(res, 404, 'Receiver not found', null, false); // send response
        }
        // if sender is same as receiver
        if (sender.email === receiver.email) { // if sender is same as receiver
            return responseFunction(res, 400, 'Sender and receiver cannot be the same', null, false); // send response
        }
        // if file key is not provided
        if (!fileKey) { // if file key is not provided
            return responseFunction(res, 400, 'File key is required', null, false); // send response
        }
        sender.files.push({ // push file to sender  
            senderEmail: sender.email, // sender email
            receiverEmail: receiverEmail, // receiver email
            fileUrl: fileKey, // file url
            fileType: fileType, // file type
            fileName: fileName ? fileName : new Date().toLocaleDateString(), // file name or date if user does not provide name of file
            sharedAt: Date.now(), // shared at
        });
        receiver.files.push({ // push file to receiver
            senderEmail: sender.email, // sender email
            receiverEmail: receiverEmail, // receiver email
            fileUrl: fileKey, // file url
            fileType: fileType, // file type
            fileName: fileName ? fileName : new Date().toLocaleDateString(), // file name or date if user does not provide name of file
            sharedAt: Date.now(), // shared at
        });

        await sender.save(); // save sender
        await receiver.save(); // save receiver
        await sendNotificationEmail(receiverEmail, sender.email); // send notification email
        return responseFunction(res, 200, 'File shared successfully', null, true); // send response
    } catch (error) { // catch error
        return next(error); // pass to error handler
    }
});

router.get('/all-files', authTokenHandler, async (req, res, next) => { // get all files route
    try {
        let user = await User.findOne({ email: req.user }); // find user
        if (!user) { // if user not found
            return responseFunction(res, 404, 'User not found', null, false); // send response
        }
        return responseFunction(res, 200, 'Files fetched successfully', user.files, true); // send response
    } catch (error) { // catch error
        return next(error); // pass to error handler
    }
});

router.get('/get-s3-url', authTokenHandler, async (req, res, next) => {
    try {
        const { key } = req.query; // Get the file key from query parameters
        if (!key) {
            return responseFunction(res, 400, 'File key is required', null, false); // Handle missing key
        }

        const signedUrl = await getObjectUrl(key); // Get signed URL from S3
        if (!signedUrl) {
            return responseFunction(res, 400, 'Signed URL not found', null, false); // Handle not found case
        }

        return responseFunction(res, 200, 'Signed URL generated successfully', signedUrl, true); // Send response with signed URL
    } catch (error) {
        return next(error); // Pass to error handler
    }
});

router.use(errorHandler); // use error handler
module.exports = router; // export router
