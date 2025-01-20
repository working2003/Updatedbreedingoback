const mongoose = require('mongoose')
const AutoIncrement = require('mongoose-sequence')(mongoose);

//define schema
const userSchema = new mongoose.Schema({
  userId: {
    type: Number,
    unique: true,
    sparse: true, // Allow null values, only enforce uniqueness on non-null values
  },
  firstName: {
    type: String,
    trim: true,
  },
  lastName: {
    type: String,
    trim: true,
  },
  mobileNumber: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    validate: {
      validator: function(v) {
        return /^[0-9]{10}$/.test(v);
      },
      message: props => `${props.value} is not a valid mobile number!`
    },
    index: true // Add index for faster queries
  },
  farmName: {
    type: String,
    trim: true,
  },
  state: {
    type: String,
    trim: true,
  },
  district: {
    type: String,
    trim: true,
  },
  taluka: {
    type: String,
    trim: true,
  },
  village: {
    type: String,
    trim: true,
  },
  pinCode: {
    type: Number,
  },
  cowCount: {
    type: Number,
    required: true,
    default: 0,
  },
  buffaloCount: {
    type: Number,
    required: true,
    default: 0,
  },
  cowCalfCount: {
    type: Number,
    required: true,
    default: 0,
  },
  buffaloCalfCount: {
    type: Number,
    required: true,
    default: 0,
  },
  createdOn:{
    type:Date,
    required:true,
    default: Date.now
  },
  lastLogIn:{
    type:Date,
    required:false
  },
  status:{
    type: String,
    required: true,   
    enum :['In Progress', 'Active', 'InActive'],
    default: 'In Progress',
  },
  isDeleted: {
    type: Boolean,
    required: true,
    default: false,
  },
}, {
  timestamps: true, // Adds createdAt and updatedAt
  toJSON: { 
    transform: function(doc, ret) {
      delete ret.__v;
      return ret;
    }
  }
});

// Add compound index for common queries
userSchema.index({ mobileNumber: 1, status: 1 });

// Add the auto-increment plugin
userSchema.plugin(AutoIncrement, {inc_field: 'userId'});

const User = mongoose.model('User', userSchema)

module.exports = User
