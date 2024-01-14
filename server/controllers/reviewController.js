const Review = require('../models/Review');
const Product = require('../models/Product');
const {StatusCodes}= require('http-status-codes');
const {checkPermissions}= require('../utils');
const CustomError = require('../errors');

const createReview= async(req,res)=>{
    const {product:productId} =req.body;

    const isValidProduct = await Product.findOne({_id:productId});
    if(!isValidProduct){
        throw new CustomError.notFoundError(`No product exists with id ${productId}`);
    }

    req.body.user = req.user.userId;

    const alreadySubmitted = await Review.findOne({
        product:productId,
        user:req.user.userId,
    });

    if(alreadySubmitted){
        throw new CustomError.BadRequestError('Already submitted the review!!');
    }

    const review = await Review.create(req.body);
    res.status(StatusCodes.CREATED).json({review});
}

//if we would like to get some more info about the product or user then we can use the populate method for it
// in path property we will provide the ref: property
const getAllReviews= async(req,res)=>{
    // same populate thing can be done with user also just path:'user' and select as required
    const reviews = await Review.find({}).populate({
        path:'product',
        select:'name price company',
    });
    res.status(StatusCodes.OK).json({reviews ,count:reviews.length});
}

// the above populate can also be used for getSingleReview if required
const getSingleReview= async(req,res)=>{
    const {id:reviewId} = req.params;
    const review = await Review.findOne({_id:reviewId});

    if(!review){
        throw new CustomError.notFoundError(`No review exists with id ${reviewId}`);
    }

    res.status(StatusCodes.OK).json({review});
}

const updateReview= async(req,res)=>{
    const {id:reviewId}= req.params;
    const {rating,title,comment}=req.body;
    const review = await Review.findOne({_id:reviewId});
    if(!review){
        throw new CustomError.notFoundError(`No review exists with id ${reviewId}`);
    }

    checkPermissions(req.user,review.user);
    review.rating=rating;
    review.title=title;
    review.comment=comment;

    await review.save();
    res.status(StatusCodes.OK).json({review});
}

const deleteReview= async(req,res)=>{
    const {id:reviewId} = req.params;
    const review = await Review.findOne({_id:reviewId});
    if(!review){
        throw new CustomError.notFoundError(`No review exists with id ${reviewId}`);
    }
    
    checkPermissions(req.user,review.user);// aren't both of same data types
    await review.remove();// will discuss the use of this way later
    res.status(StatusCodes.OK).json({msg:'Deleted the review!!'});
}

// using this we can setup any querying we require unlike in the virtuals
const getSingleProductReviews = async(req,res)=>{
    const{id:productId} = req.params;
    const reviews = await Review.find({product:productId});
    res.status(StatusCodes.OK).json({reviews,count:reviews.length});
}

module.exports={createReview,getAllReviews,getSingleReview,updateReview,deleteReview,getSingleProductReviews};