const mongoose = require('mongoose')
const AutoIncrement = require('mongoose-sequence')(mongoose);

//define schema
const pregEasySchema = new mongoose.Schema({
  pregEasyId: {
    type: Number,
    unique: true,
    auto: true, // Automatically generated (use a plugin like 'mongoose-sequence' for auto-increment)
  },
  userId:{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User', // Reference to User model
    required: true,
  },
  type:{
    type: String,
    required: true,   
    enum :['cows', 'Buffalo', 'Cow-calf', 'Buffalo calf']
  },
  breed:{
    type:String,
    required:true
  },
  tagNumber:{
    type:String,
    required:true
  },
  dateOfLastDelivery:{
    type:Date,
    required:true
  },
  dateOfFirstHeat:{
    type:Date,
    required:true
  },
  dateOfInsemination:{
    type:Date,
    required:true
  },
  dateOfBirth:{
    type:Date,
    required:false
  },
  numberOfLactation:{
    type:Number,
    required:false,
    default: 0,
  },
  dailyMilkProduction:{
    type:Number,
    required:false,
    default: 0,
  },
  estimatedDailyMilkCapacity:{
    type:Number,
    required:false,
    default: 0,
  },
  isPregnant:{
    type:Boolean,
    required:true,
    default: false,
  },
  usedSemen:{
    type:String,
    required:true,
  },
  isDeworming:{
    type:Boolean,
    required:true,
    default: false,
  },
  isVaccination:{
    type:Boolean,
    required:true,
    default: false,
  },
  isDeleted: {
    type: Boolean,
    required: true,
    default: false,
  },
});

pregEasySchema.plugin(AutoIncrement, { inc_field: 'pregEasyId' });

//model create by using schema
const pregEasy = mongoose.model('pregEasy',pregEasySchema);

module.exports = pregEasy;