const mongoose = require('mongoose');

// while setting up the schema for cartItems we can include many items, so instead of writing the whole there, we create a new Schema and tie it to the cartItems
const singleOrderItemSchema = mongoose.Schema({
    name:{type:String,required:true},
    image:{type:String,required:true},
    price:{type:String,required:true},
    amount:{type:String,required:true},
    product:{
        type:mongoose.Schema.ObjectId,
        ref:'Product',
        required:true,
    },
})

const orderSchema = mongoose.Schema({
    tax:{
        type:Number,
        required:true,
    },
    shippingFee : {
        type:Number,
        required:true,
    },
    subtotal : {
        type:Number,
        required:true,
    },
    total : {
        type:Number,
        required:true,
    },
    orderItems : [singleOrderItemSchema],
    status:{
        type:String,
        enum : ['pending','failed','paid','cancelled','delivered'],
        default:'pending',
    },
    user:{
        type:mongoose.Schema.ObjectId,
        required:true,
    },
    clientSecret:{
        type:String,
        required:true,
    },
    paymentIntentId:{
        type:String,
    }
},{timestamps:true});

module.exports= mongoose.model('Order',orderSchema);