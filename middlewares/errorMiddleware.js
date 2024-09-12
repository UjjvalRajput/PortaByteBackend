function errorHandler(statusCode, err, req, res, next) {
    if (res.headersSent) {
        return next(err);
    }
    console.log("Error: ", err);
    res.status(statusCode || 500).json({
        message: err.message || "Internal Server Error", // Default message for internal server error
        success: false, // Default status for internal server error
        data: null, // Default data for internal server error
    });
}

module.exports = errorHandler; // export error handler