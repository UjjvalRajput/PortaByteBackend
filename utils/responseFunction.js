const responseFunction = (res, status, message, data, success) => { // response function
    res.status(status).json({ // send response
        message, // message to send in response
        data, // data to send in response
        success, // success status of response 
    });
};

module.exports = responseFunction; // export response function