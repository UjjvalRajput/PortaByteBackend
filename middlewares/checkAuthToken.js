const jwt = require('jsonwebtoken');
require('dotenv').config();

function checkAuthToken(req, res, next) {
    const token = req.cookies.token;
    const refreshToken = req.cookies.refreshToken;

    if (!token) {
        return res.status(401).json({ message: 'Access denied. Token is not provided.', success: false });
    }

    // Verify the main token
    jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decoded) => {
        if (err) {
            // If the main token is invalid, try to verify the refresh token
            if (refreshToken) {
                jwt.verify(refreshToken, process.env.REFRESH_SECRET_KEY, (reErr, reDecoded) => {
                    if (reErr) {
                        return res.status(403).json({ message: 'Authentication failed: Both tokens are invalid', success: false });
                    } else {
                        // Generate new tokens
                        const newToken = jwt.sign({ email: reDecoded.email }, process.env.JWT_SECRET_KEY, { expiresIn: '10m' });
                        const newRefreshToken = jwt.sign({ email: reDecoded.email }, process.env.REFRESH_SECRET_KEY, { expiresIn: '1h' });

                        res.cookie('token', newToken, { 
                            httpOnly: true,
                            secure: true,
                            sameSite: 'none'
                        });
                        res.cookie('refreshToken', newRefreshToken, { 
                            httpOnly: true,
                            secure: true,
                            sameSite: 'none'
                        });

                        req.user = reDecoded.email;
                        req.success = true;
                        req.message = "Authenticated successfully";
                        next();
                    }
                });
            } else {
                return res.status(403).json({ message: 'No refresh token provided.', success: false });
            }
        } else {
            req.user = decoded.email;
            req.success = true;
            req.message = "Authenticated successfully";
            next();
        }
    });
}

module.exports = checkAuthToken;
