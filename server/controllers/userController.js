const User = require('../models/User');
const CustomError = require('../errors');
const {StatusCodes}= require('http-status-codes');
const{createTokenUser,attachCookiesToResponse,checkPermissions}=require('../utils');

const getAllUsers= async(req,res)=>{
    console.log(req.user);
    let users = await User.find({role:'user'}).select('-password');
    res.status(StatusCodes.OK).json({users});
}

const getSingleUser= async(req,res)=>{
    const {params:{id:userId}} = req;
    const user = await User.findOne({_id:userId}).select('-password');

    if(!user){
        throw new CustomError.notFoundError(`No user with id ${userId}`);
    }

    checkPermissions(req.user,user._id);
    res.status(StatusCodes.OK).json({user});
}

const showCurrentUser= async(req,res)=>{
    res.status(StatusCodes.OK).json({user : req.user});
}

const updateUser= async(req,res)=>{
    // we want to modify only name and email, password and role are not required
    const {name,email}=req.body;
    if(!name || !email){
        throw new CustomError.BadRequestError('Please provide all values');
    }

    //updateUser can also be made using findOne and then updating the values manually, but in that case we have to make the user.save() which invokes the 'pre' save hook which may re hash the password, but this is not the case with 'User' methods like User.findOneAndUpdate

    // this.modifiedPaths() is an array of all the paths that have been modified
    
    const user = await User.findOneAndUpdate({_id:req.user.userId},{name,email},{
        runValidators:true,
        new :true,
    })

    const tokenUser = createTokenUser(user);
    attachCookiesToResponse({res,user:tokenUser});

    res.status(StatusCodes.OK).json({user : tokenUser});
}

const updateUserPassword= async(req,res)=>{
    const {oldPassword , newPassword} = req.body;
    if(!oldPassword || !newPassword){
        throw new CustomError.BadRequestError('Please provide old and new password');
    }
    const user = await User.findOne({_id : req.user.userId});
    
    const isPasswordCorrect = user.comparePassword(oldPassword);
    if(!isPasswordCorrect){
        throw new CustomError.UnauthenticatedError('Invalid credentials');
    }

    user.password = newPassword;
    await user.save();// this invokes the hash password may be, and updates user with the new hashed password
    res.status(StatusCodes.OK).json({msg : 'Success updating password'});
}

module.exports={getAllUsers,getSingleUser,showCurrentUser,updateUser,updateUserPassword};