require('dotenv').config();
const {generateUniqueValue} = require('../util/generateUniqueName');
const jwt = require('jsonwebtoken');
const User = require('../models/user'); // Your User model
const { UserDetail } = require('otpless-node-js-auth-sdk');


// Helper to generate a JWT
const generateJWTToken = (userId) => {
  const JWT_EXPIRATION_Value = process.env.JWT_EXPIRATION || '180d'
  return jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: JWT_EXPIRATION_Value, // e.g., '1d' for 1 day
  });
};

// Step 1: Send OTP
const sendOTP = async (req, res) => {
  try {
    const email = process.env.OTPLESS_EMAIL;
    const channel = process.env.OTPLESS_CHANNEL;
    const hash = process.env.OTPLESS_TOKEN_ID;
    const orderId = generateUniqueValue();
    const expiry=process.env.OTPLESS_EXPIRY;
    const otpLength=process.env.OTPLESS_OTP_LENGTH;
    const clientId = process.env.OTPLESS_CLIENT_ID;
    const clientSecret = process.env.OTPLESS_CLIENT_SECRET;
    const { mobileNumber } = req.body;

    if (!mobileNumber || !/^\d{10}$/.test(mobileNumber)) {
      return res.status(400).json({ message: 'Invalid mobile number' });
    }
    const phoneNumber = "+91"+mobileNumber;

    const response = await UserDetail.sendOTP(phoneNumber, email, channel, hash, orderId, expiry, otpLength, clientId, clientSecret);

    return res.status(200).json({ message: 'OTP sent successfully' ,response});
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Step 2: Verify OTP and Login
const verifyOTPAndLogin = async (req, res) => {
  try {
    const {mobileNumber, otp, orderId} = req.body; 
    const clientId = process.env.OTPLESS_CLIENT_ID;
    const clientSecret = process.env.OTPLESS_CLIENT_SECRET;
    
    if (!mobileNumber || !otp || !orderId) {
      return res.status(400).json({ 
        message: 'Mobile number, OTP, and orderId are required',
        received: { mobileNumber: !!mobileNumber, otp: !!otp, orderId: !!orderId }
      });
    }

    const phoneNumber = "+91"+mobileNumber;
    console.log('Verifying OTP with:', { phoneNumber, orderId, otp });
    
    try {
      const response = await UserDetail.verifyOTP("", phoneNumber, orderId, otp, clientId, clientSecret);
      console.log('OTP verification response:', response);

      if (!response || !response.isOTPVerified) {
        return res.status(400).json({ 
          message: 'Invalid OTP',
          details: 'OTP verification failed'
        });
      }

      // Find or create user in the database
      let user = await User.findOne({ mobileNumber });
      if (!user) {
        user = new User({ mobileNumber });
        await user.save();
      }

      // Generate JWT
      const token = generateJWTToken(user._id);

      return res.status(200).json({
        token,
        userStatus: user.status,
        message: 'Login successful'
      });
    } catch (verifyError) {
      console.error('OTP verification error:', verifyError);
      return res.status(400).json({ 
        message: 'OTP verification failed',
        error: verifyError.message
      });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      message: 'Server error during login',
      error: error.message
    });
  }
};

// Step 3: Middleware to Authenticate Requests
const authenticateRequest = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access denied, token missing!' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = decoded; // Attach user to request object
    next();
  });
};

module.exports = {
  sendOTP,
  verifyOTPAndLogin,
  authenticateRequest,
};
