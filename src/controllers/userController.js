require('dotenv').config();
const User = require('../models/user');
const UserCoin = require('../models/userCoin');
const UserTransactions = require('../models/userTransactions');

const findMaxCount = async () => {
  console.log(await User.find().select('userId').sort({userId:-1}).limit(1));
}

const ViewPrice = process.env.ViewPrice;

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

const registerUser = async (request,response) =>{
  const userData = request.body;
  userData.lastLogIn = getCurrentDateTime();
  userData.status = "Active";
  const user = await User.findOneAndUpdate(
    { 
      mobileNumber:userData.mobileNumber, 
      status : 'In Progress'
    },
    userData,
    {new:true}
  );
  if(!user){
    return response.status(403).json({msg:"User not found or Already Present"});
  }
  else{
    const userCoinObject = {
      userId :user._id,
      totalCoin:200,
    }
    const userCoin = new UserCoin(userCoinObject);
    const userCoinSave = await userCoin.save();
    if(!userCoinSave)
        return response.status(403).json({msg:"Coin wallet not create"});
  }
  return response.status(200).json({msg:"User created successfully"});
}

const getUserInfo = async (request,response) =>{
  const userId = request.user.userId;
  const userData = await User.findById(userId);
  if(!userData){
    return response.status(403).json({msg:"User not found"});
  }
  const userCoinData = await UserCoin.findOne({userId:userId});
  if(!userCoinData){
    return response.status(403).json({msg:"wallet not found"});
  }
  console.log(userData);
  console.log(userCoinData.totalCoin);
  const userResponse = userData.toObject();
    userResponse.totalCoin = userCoinData.totalCoin;
  return response.status(200).json(userResponse);
}

const userUpdate = async (request,response) =>{
  const user = request.body;
  const userData = await User.findOneAndUpdate(
    {_id : request.user.userId},
    user,
    {new:true}
  )
  if(!userData){
    return response.status(403).json({msg:"User not found"});
  }
  return response.status(200).json({msg:"User data updated successfully"});

}

const updateDebitCoin = async (request,response) =>{
  const buyerId = request.body.buyerId;
  const sellerId = request.body.sellerId;

  // const buyerObjectId = mongoose.Types.ObjectId(buyerId);
  //   const sellerObjectId = mongoose.Types.ObjectId(sellerId);

  const buyerData = await User.find({ userId:buyerId})
  if(!buyerData){
    return response.status(404).json({ msg: "User not found" });
  }
  else{
    const buyerCoinData = await UserCoin.findOne({ userId:buyerId});
    if(buyerCoinData.totalCoin-ViewPrice <0)
      return response.status(404).json({ msg: "insufficient balance" });
    else{
      try {
        
        buyerCoinData.totalCoin -= ViewPrice;
        await buyerCoinData.save();

        const sellerData = await User.findOne({ userId:sellerId})
        const transaction = {
          userId:buyerId,
          transactionDescription:`Viewed seller ${sellerId}'s contact.`,
          transactionAmount : ViewPrice,
          transactionType : 'debited'
        }
        new UserTransactions(transaction).save();
        response.status(200).json({ msg: "User coin updated successfully",'userMobile':sellerData.mobileNumber});
      } catch (error) {
        response.status(500).json({ error: error.message }); 
      }
    }
  }
}

module.exports = {registerUser,userUpdate,updateDebitCoin,getUserInfo};