const express = require("express");
const multer = require('multer');
const router = express.Router();

const storage = multer.memoryStorage(); // Store file in memory
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB limit
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) {
      return cb(new Error('File must be an image'), false);
    }
    cb(null, true);
  },
});


const { 
  addCattleForSell,
  getCattleSell,
  getAllCattleSell,
  getAllSaveCattleSell,
  addSaveCattleSell,
  deleteSaveCattleSell,
  deleteCattleForSell
} = require("../controllers/cattleSellController")

router.route("/sell").get(getAllCattleSell);
router.route("/sell/:id").get(getCattleSell);
router.route("/sell").post(upload.array('images',2),addCattleForSell);
router.route("/sell/:cattleId").delete(deleteCattleForSell);
router.route("/sell/save").get(getAllSaveCattleSell);
router.route("/sell/save").post(addSaveCattleSell);
router.route("/sell/save/:cattleSellId").delete(deleteSaveCattleSell);

module.exports = router;