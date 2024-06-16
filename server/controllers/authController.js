require('dotenv').config();
const User =require('../models/User');
const Token = require('../models/Token');
const {StatusCodes} = require('http-status-codes');
const CustomError = require('../errors');
const jwt = require('jsonwebtoken');
const {attachCookiesToResponse,createTokenUser,sendVerificationEmail,sendResetPasswordEmail,createHash} = require('../utils');
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

const forgotPassword = async(req,res)=>{
    const {email} = req.body;
    if(!email){
        throw new CustomError.BadRequestError('Please provide email');
    }
    const user = await User.findOne({email});

    // we always send the message because we don't want to tell any random user if the given email exists or not in my database
    if(user){
        const passwordToken = crypto.randomBytes(70).toString('hex');
        // send email
        const origin = 'http://localhost:3000';
        await sendResetPasswordEmail({name:user.name,email:user.email,token:passwordToken,origin});

        const tenMinutes= 10*60*1000;
        const passwordTokenExpirationDate = new Date(Date.now()+tenMinutes);

        user.passwordToken=createHash(passwordToken);
        user.passwordTokenExpirationDate=passwordTokenExpirationDate;
        await user.save();
    }
    res.status(StatusCodes.OK).json({msg:"Please check email for verification link"})
}

const resetPassword = async(req,res)=>{
    const{email,token,password}= req.body;
    if(!email || !token || !password){
        throw new CustomError.BadRequestError('Please provide all values');
    }
    const user = await User.findOne({email});
    
    if(user){
        const currentDate = new Date();
        if(user.passwordToken===createHash(token) && user.passwordTokenExpirationDate>currentDate){
            console.log("Hello");
            user.password=password;
            user.passwordToken=null;
            user.passwordTokenExpirationDate=null;
            await user.save();
        }
    }
    res.status(StatusCodes.OK).json({msg:"Password reset"});
}

module.exports={register,login,logout,verifyEmail,forgotPassword,resetPassword};