const pregEasy = require('../models/pregEasy')

const getCurrentDateTime = () => {
  const currentDate = new Date();
  const year = currentDate.getFullYear();
  const month = String(currentDate.getMonth() + 1).padStart(2, '0');
  const day = String(currentDate.getDate()).padStart(2, '0');
  const hours = String(currentDate.getHours()).padStart(2, '0');
  const minutes = String(currentDate.getMinutes()).padStart(2, '0');
  const seconds = String(currentDate.getSeconds()).padStart(2, '0');
  
  const formattedDateTime = `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
  return formattedDateTime;
}

const addPregEasyData = async (request,response) =>{
  const pregEasy = new pregEasy(request.body);
  await pregEasy.save();
  response.status(200).json({msg:""});
}

const getAllPregEasyData = async (request,response) =>{
  const {userId} = request.user;
  const pregEasyList = await pregEasy.find({userId});
  response.status(200).json(pregEasyList);
}

module.exports = {addPregEasyData , getAllPregEasyData};