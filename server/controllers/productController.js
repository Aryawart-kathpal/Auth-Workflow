const Product = require('../models/Product');
const {StatusCodes}=require('http-status-codes');
const CustomError = require('../errors');
const path = require('path');
 
const createProduct = async(req,res)=>{
    req.body.user= req.user.userId;// req.body mein user ki id bharna
    const product = await Product.create(req.body);
    res.status(StatusCodes.CREATED).json({product});
}

const getAllProducts = async(req,res)=>{
    const products = await Product.find({}).populate('reviews');// using the mongo virtuals, we populate and send all the reviews corresponding to that product

    res.status(StatusCodes.OK).json({products,count:products.length});
}

// we might need to populate the reviews that are associated with the product, but as in the productSchema, there is no ref: to 'reviews' so we have to use mongoose virtuals for that
const getSingleProduct = async(req,res)=>{
    const {id:productId} = req.params;
    const product = await Product.findOne({_id:productId});

    if(!product){
        throw new CustomError.notFoundError(`No product found with id ${productId}`);
    }
    res.status(StatusCodes.OK).json({product});
}

const updateProduct = async(req,res)=>{
    const {id:productId}=req.params;
    const product = await Product.findOneAndUpdate({_id:productId},req.body,{
        runValidators:true,
        new:true,
    })

    if(!product){
        throw new CustomError.notFoundError(`No product found with id ${productId}`);
    }

    res.status(StatusCodes.OK).json({product});
}

const deleteProduct = async(req,res)=>{
    const {id:productId}=req.params;
    const product = await Product.findOne({_id:productId});

    if(!product){
        throw new CustomError.notFoundError(`No product found with id ${productId}`);
    }

    await product.remove();// we setup this functionality beacause when we try to remove the product we also want that the corresponding reviews to be removed too, so we make a pre hook that is triggered at the time of this step that removes the reviews related to this
    res.status(StatusCodes.OK).json({msg:"Successfully deleted the product"});
}

const uploadImage = async(req,res)=>{
    
    if(!req.files){
        throw new CustomError.BadRequestError('No file uploaded');
    }

    const productImage = req.files.image;
    if(!productImage.mimetype.startsWith('image')){
        throw new CustomError.BadRequestError('Please upload image');
    }

    const maxSize = 1024*1024;
    if(productImage.size > maxSize){
        throw new CustomError.BadRequestError('Please upload image less than 1 MB');
    }

    const imagePath = path.join(__dirname,'../public/uploads/'+`${productImage.name}`);
    await productImage.mv(imagePath);
    
    res.status(StatusCodes.OK).json({image:`uploads/${productImage.name}`});
}

module.exports={createProduct,getAllProducts,getSingleProduct,updateProduct,deleteProduct,uploadImage}
