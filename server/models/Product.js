const mongoose = require('mongoose');

const productSchema = mongoose.Schema({
  name : {
    type:String,
    trim:true,
    required:[true,'Please provide product name'],
    maxlength:[100,"Name can't be more than 100 characters"],
  },
  price :{
    type:Number,
    required:[true,'Please provide price'],
  },
  description:{
    type:String,
    required:[true,'Please provide product description'],
    maxlentgh:[1000,"Description can't be more than 100 characters"],
  },
  image:{
    type:String,
    default:'/uploads/example.jpg',
  },
  category:{
    type:String,
    required:[true,'Please provide the product category'],
    enum:['office','kitchen','bedroom'],
  },
  company:{
    type:String,
    required:[true,'Please provide company name'],
    enum:{
        values:['ikea','liddy','marcos'],
        message:'{VALUE} is not supported',
    },
  },
  colors:{
    type:[String],
    default:['#222',],
    required:true,
  },
  featured:{
    type:Boolean,
    default:false,
  },
  freeShipping:{
    type:Boolean,
    default:false,
  },
  inventory:{
    type:Number,
    required:true,
    default:15,
  },
  averageRating:{
    type:Number,
    deafult:0,
  },
  numOfReviews :{
    type:Number,
    default:0,
  },
  user:{
    type: mongoose.Types.ObjectId,
    ref:'User',
    required:true,
  }
},{timestamps:true, toJSON :{virtuals :true},toObject : {virtuals:true}});

// to link the reviews with the product we will have to use mongoose virtuals
productSchema.virtual('reviews',{
  ref:'Review',
  localField:'_id',
  foreignField : 'product',
  justOne:false,
  // match :{rating:5},->only fetch those with rating 5
});
// the above method has a disadvantage that we can't perform queries on the reviews like findOne,etc.

productSchema.pre('remove',async function(next){
  await this.model('Review').deleteMany({product:this._id});
})

module.exports = mongoose.model('Product',productSchema);