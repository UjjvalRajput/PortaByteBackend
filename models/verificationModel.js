const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const verificationSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
    },
    code: {
        type: String,
        required: true,
    },
    expiresAt: {
        type: Date,
        required: true,
    },
}, {timestamps: true});

// Hash verification code before saving to database
verificationSchema.pre('save', async function(next) {
    const verification = this;
    if (!verification.isModified('code')) {
        return next();
    }
    verification.code = await bcrypt.hash(verification.code, 10);
    next();
});

module.exports = mongoose.model('Verification', verificationSchema);