const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    name:{
        type:String,
        required:[true,'Please provide name'],
        minlength:3,
        maxlength:50,
    },
    email:{
        type:String,
        required:[true,'Please provide email'],
        validate:{
            validator : validator.isEmail,
            message:'Please provide valid email'
        }
        //we use the inbuilt validator package that contains many validations in it easy to implement, instead of writing everytime
        // match: [ 
        //     /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
        //     'Please provide a valid email'],
        // unique:true,
    },
    password:{
        type:String,
        required:[true,'Please provide passsword'],
        minlength:6,
    },
    role:{
        type:String,
        enum:['user','admin'],
        default:'user',
    },
    verificationToken:String,
    isVerified:{
        type:Boolean,
        default:false,
    },
    verified:Date,
})

// this.modifiedPaths() is an array of all the paths that have been modified
userSchema.pre('save',async function(){
    const salt = await bcrypt.genSalt(10);
    if(!this.isModified('password')) return;// to avoid rehashing of the password 
    this.password= await bcrypt.hash(this.password,salt);
})

userSchema.methods.comparePassword= async function(candidatePassword){
    const isMatch = await bcrypt.compare(candidatePassword,this.password);
    return isMatch;
}

module.exports = mongoose.model('User',userSchema);