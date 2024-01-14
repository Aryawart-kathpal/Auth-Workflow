require('dotenv').config();
const User =require('../models/User');
const Token = require('../models/Token');
const {StatusCodes} = require('http-status-codes');
const CustomError = require('../errors');
const jwt = require('jsonwebtoken');
const {attachCookiesToResponse,createTokenUser,sendVerificationEmail} = require('../utils');
const crypto = require('crypto');

const register = async(req,res)=>{
    //This may not have to be done, as it is already being handled in the schema, unique:true
    const {email,name,password} =req.body;
    // we extract email,name,password only from req.body so that the role can't be sent from the frontend, it is just to make the 'role' in the backend more secure
    // setting the admin therefore can be done from postman or manually in the Database
    const emailAlreadyExists = await User.findOne({email});
    if(emailAlreadyExists){
        throw new CustomError.BadRequestError("Email already exists!!");
    }

    // First registered user is the admin
    const isFirstAccout = await User.countDocuments({}) === 0;
    const role = isFirstAccout?'admin':'user';

    const verificationToken = crypto.randomBytes(40).toString('hex'); // create 40 random hexadecimal bytes

    const user = await User.create({email,name,password,role,verificationToken});

    const origin = 'http://localhost:3000';
    // const newOrigin = 'http://react-node-user-workflow-frront-end.netlify.app';

    // const tempOrigin = req.get(`origin`);// this will be where backend is functioning
    // console.log(`origin: ${tempOrigin}`);
    // const protocol = req.protocol;
    // console.log(`protocol: ${protocol}`);
    // const host = req.get(`host`);
    // console.log(`host: ${host}`);

    // const forwardedHost = req.get(`x-forwarded-host`);
    // console.log(`forwarded host: ${forwardedHost}`);
    // const forwardedProtocol = req.get(`x-forwarded-proto`);
    // console.log(`Forwarded Protocol: ${forwardedProtocol}`);
    
    await sendVerificationEmail({email:user.email,name:user.name,verificationToken:user.verificationToken,origin});

   //send verification token back only while testing in postman
   res.status(StatusCodes.CREATED).json({msg:'Sucess!! please verify your email account'});
}

const verifyEmail = async(req,res)=>{
    const {verificationToken,email} = req.body;

    const user = await User.findOne({email});
    if(!user){
        throw new CustomError.UnauthenticatedError('Verification Failed');
    }

    if(user.verificationToken!==verificationToken){
        throw new CustomError.UnauthenticatedError('Verification Failed');
    }

    user.isVerified=true;
    user.verified=Date.now();
    user.verificationToken='';    

    await user.save();

    res.status(StatusCodes.OK).json({msg:'Email verified'});
}

const login = async(req,res)=>{
    const {email,password}=req.body;
    if(!email || !password){
        throw new CustomError.BadRequestError("Please provide email and password");
    }
    const user = await User.findOne({email});

    if(!user){
        throw new CustomError.UnauthenticatedError(`No user exists with email ${email}`);
    }

    const isPasswordCorrect = await user.comparePassword(password);// await is must here
    if(!isPasswordCorrect){
        throw new CustomError.UnauthenticatedError("Incorrect password entered");
    }

    if(!user.isVerified){
        throw new CustomError.UnauthenticatedError('Please verify your email');
    }

    const tokenUser =createTokenUser(user);

    //create refresh token
    let refreshToken ='';
    //check for existing token
    const existingToken=await Token.findOne({user:user._id});
    if(existingToken){
        const {isValid} = existingToken;    
        if(!isValid){
            throw new CustomError.UnauthenticatedError('Invalid Credentials');
        }
        refreshToken=existingToken.refreshToken;
        attachCookiesToResponse({res,user:tokenUser,refreshToken});
        res.status(StatusCodes.OK).json({user : tokenUser});
        return;
    }

    refreshToken=crypto.randomBytes(40).toString('hex');
    const userAgent = req.headers['user-agent'];
    const ip=req.ip;
    const userToken = {refreshToken,ip,userAgent,user:user._id};

    await Token.create(userToken);

    attachCookiesToResponse({res,user:tokenUser,refreshToken});
    res.status(StatusCodes.OK).json({user : tokenUser});
}

// we expire the cookie and in console, we find that req.signedCookies has empty object with no token 
const logout = async(req,res)=>{
    await Token.findOneAndDelete({user:req.user.userId});

    res.cookie('accessToken','logout',{
        httpOnly:true,
        expires : new Date(Date.now()/*+5*1000*/),
    })

    res.cookie('refreshToken','logout',{
        httpOnly:true,
        expires : new Date(Date.now()/*+5*1000*/),
    })
    res.status(StatusCodes.OK).json({msg:"user logged out"});
}


module.exports={register,login,logout,verifyEmail};