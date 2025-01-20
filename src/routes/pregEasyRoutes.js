const express = require("express");
const router = express.Router();

const { addPregEasyData,getAllPregEasyData  } = require("../controllers/pregEasyController");

router.route("/add").post(addPregEasyData);
router.route("/getAll").get(getAllPregEasyData );

module.exports = router;