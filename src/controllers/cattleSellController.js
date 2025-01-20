const imageFileStore = require('../util/imageFileStore');

const cattleSell = require('../models/cattleSell')
const saveCattleSell = require('../models/saveCattleSell')


const addCattleForSell = async (request,response) =>{
  const {files} = request;
  const CattleData = request.body;
  const userId = request.user.userId;
  if(files && files.length > 0){
  try {
      const images = [];
      for(const file of files){
        const filePath = await imageFileStore(file.buffer,file.originalname,'cattle');
        console.log(`File saved successfully at: ${filePath}`)
      
        images.push({filePath: filePath});
      }
      CattleData.images = images;
    } catch (err) {
        console.error(`Error: ${err.message}`);
    }
  }
    CattleData.userId = userId
  const cattleForSell = new cattleSell(CattleData);
  await cattleForSell.save();

  response.status(200).json({msg:"cattleSell added successfully"});
}

const getCattleSell = async (request,response) =>{

  const cattleForSell = await cattleSell.findById(request.params.id);
  response.status(200).json(cattleForSell);
}

const deleteCattleForSell = async (request,response) => {
    const userId = request.user.userId;
    const cattleId = request.params.cattleId;
    const deletedCattle = await cattleSell.findOneAndDelete({
        userId : userId,
        _id : cattleId
    })
    console.log(deletedCattle);
    if (!deletedCattle) {
      return response.status(404).json({ message: "Cattle not found or already deleted" });
    }

    // If successfully deleted, return the response
    return response.status(200).json({
      message: "Cattle successfully deleted"
    });
}

const getAllCattleSell = async (request,response) =>{
  /* pagination*/
  const pageNumber = parseInt(request.query.page||1);
  const limitPerPage = parseInt(request.query.limit||1);
  const skip = (pageNumber-1)*limitPerPage;
  const totalCount = await cattleSell.countDocuments();

  const cattleForSell = await cattleSell.find()
    .skip(skip)
    .limit(limitPerPage)
    .exec();
  ;
  response.status(200).json({
    cattleForSell,
    currentPage:pageNumber,
    totalRecord:totalCount,
    totalPages: Math.ceil(totalCount/limitPerPage)
  });
}

const getUserCattleForSale = async (request,response) =>{
  const {userId} = request.user;
  const cattleForSell = await cattleSell.find({userId});
  response.status(200).json(cattleForSell);
}

const getAllSaveCattleSell= async (request,response) =>{
  const {userId} = request.user;
  const saveUserCattleSellList = await saveCattleSell.find({userId})
  .populate({
    path:"cattleSellId", // populates all details from the cattleSell document
  } 
  )
    .exec();

    const UserCattleSellList = saveUserCattleSellList.map(item=>item.cattleSellId); //only get cattleSell information
  response.status(200).json(UserCattleSellList);
}

const addSaveCattleSell= async (request,response) =>{
  const {cattleSellId} = request.body;
  const {userId} = request.user;
  const saveUserCattleSell = new saveCattleSell({userId,cattleSellId});
  await saveUserCattleSell.save();
  response.status(200).json({msg:"cattleSell saved successfully"});
}

const deleteSaveCattleSell= async (request,response) =>{
  console.log(request.param.cattleSellId)
  const cattleSellId = request.param.cattleSellId;
  const {userId} = request.user;
  const deletedRecord = await saveCattleSell.findOneAndDelete({userId,cattleSellId});
  if (!deletedRecord) {
    return response.status(404).json({ message: 'Record not found' });
  }
  return response.status(200).json({msg:"Record deleted successfully"});
}

module.exports = {
  addCattleForSell,
  getCattleSell,
  getAllCattleSell,
  deleteCattleForSell,
  getUserCattleForSale,
  getAllSaveCattleSell,
  addSaveCattleSell,
  deleteSaveCattleSell
};