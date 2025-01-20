const express = require("express");
const router = express.Router();
const {sendOTP,verifyOTPAndLogin} = require("../controllers/authController")
//const {registerUser} = require("../controllers/userController")

router.route("/")
  .get((req, res) => {
    res.status(200).json({ message: "Login endpoint is working. Please make a POST request to send OTP." });
  })
  .post(sendOTP);
  
router.route("/verify").post(verifyOTPAndLogin);

module.exports = router;
