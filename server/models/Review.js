const mongoose = require('mongoose');

const reviewSchema = mongoose.Schema({
    rating:{
        type:Number,
        min:1,
        max:5,
        required:[true,'Please provide rating'],
    },
    title:{
        type:String,
        trim:true,
        required:[true,'Please provide review title'],
        maxlength:100,
    },
    comment:{
        type:String,
        required:[true,'Please provide review text'],
    },
    user:{
        type:mongoose.Schema.ObjectId,//== mongoose.Types.ObjectId
        ref:'User',
        required:true,
    },
    product:{
        type:mongoose.Schema.ObjectId,
        ref:'Product',
        required:true
    }
},{timestamps:true});

// We want that a user gives only 1 review for a product but if we do unique:true for both user and product it is not going to work
// we call this property as index -> for ex. setting unique:true is also setting index
// Here we would want to set a compound index, i.e. which contains multiple fields
reviewSchema.index({product:1,user:1},{unique:true});

//static methods are used to make a call inside this file only
reviewSchema.statics.calculateAverageRating = async function (productId){
    const result = await this.aggregate([
        {$match : {product:productId}},
        {
            $group : {
                _id:null,// if we want to do for specific product then '$product' , null means for all products
                averageRating : {$avg : '$rating'},
                numOfReviews : {$sum : 1},
            },
        },
    ])
    console.log(result);

    try {
        await this.model('Product').findOneAndUpdate(
            {_id:productId},
            {
                averageRating: Math.ceil(result[0]?.averageRating || 0),
                numOfReviews : result[0]?.numOfReviews || 0,
            }
        )
    } catch (error) {
        console.log(error);
    }

}

reviewSchema.post('save',async function(){
    // console.log('Pre save hook called');
    await this.constructor.calculateAverageRating(this.product);
});

reviewSchema.post('remove',async function(){
    // console.log('Pre remove hook called');
    await this.constructor.calculateAverageRating(this.product);
});



module.exports = mongoose.model('Review',reviewSchema);