const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const fileSchema = new mongoose.Schema({
    senderEmail: {
        type: String,
        required: true,
    },
    receiverEmail: {
        type: String,
        required: true,
    },
    fileUrl: {
        type: String,
        required: true,
    },
    fileType: {
        type: String,
        required: false,
    },
    fileName: {
        type: String,
        required: true,
    },
    sharedAt: {
        type: Date,
        default: Date.now,
        required: true,
    }, 
}, {timestamps: true});

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true,
    },
    files: {
        type: [fileSchema],
        default: [],
    },
}, {timestamps: true});

// Hash password before saving to database
userSchema.pre('save', async function(next) {
    const user = this;
    if (!user.isModified('password')) {
        return next();
    }
    user.password = await bcrypt.hash(user.password, 10);
    next();
});

module.exports = mongoose.model('User', userSchema);