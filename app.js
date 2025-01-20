require('dotenv').config();
const express = require("express");
const app = express();
const apiTestRouter = require("./src/routes/apiTest");
const userRoutes = require("./src/routes/userRoutes");
const cattleSellRoutes = require("./src/routes/cattleSellRoutes");
// const otpRoutes = require("./src/routes/otpRoutes");
const authRoutes = require("./src/routes/authRoutes");
const pregEasyRoutes = require("./src/routes/pregEasyRoutes");
const { authenticateRequest } = require('./src/controllers/authController');
const mongoose = require('mongoose')

const PORT = process.env.PORT || 8000;
const DB_URL = process.env.DB_URL

// Middleware
app.use(express.json());
app.use(express.urlencoded({extended : true}))

app.get('/', (req, res) => {
  res.status(200).send('Welcome to Breedingo App Service');
});

app.get('/health', (req, res) => {
  res.status(200).send('Healthy');
});

app.use('/login', authRoutes);

// Routes
app.use("/user",authenticateRequest,userRoutes);
// app.use("/auth",otpRoutes);

app.use("/cattle",authenticateRequest,cattleSellRoutes);

app.use("/pregEasy",authenticateRequest,pregEasyRoutes);

app.use("/api/test", apiTestRouter); // Test the API

// Connect to DB
mongoose.connect(DB_URL).then(() => {
  console.log('Connected to MongoDB');
}).catch((err) => {
  console.log('Error connecting to MongoDB:', err);
});

// Server Start Function
const start = async () => {
  try {
    app.listen(PORT, () => {
      const timestamp = new Date().toLocaleString();
      console.log(`Server started on port ${PORT} at ${timestamp}`);
    });
  } catch (error) {
    console.error('Error starting server:', error);
    process.exit(1);
  }
};

// Graceful Shutdown
process.on('SIGTERM', () => {
  console.log('Process terminated');
  process.exit(0);
});

start();