const CustomError = require('../errors');
const {isTokenValid}= require('../utils');

const authenticateUser = async(req,res,next)=>{
    const token = req.signedCookies.token;
    if(!token){
        throw new CustomError.UnauthenticatedError("Authnetication Invalid");
    }
    
    try {
        // const paylod = isTokenValid({token}); can do like this also
        const {name,userId,role} = isTokenValid({token});
        req.user ={name,userId,role};
        next();
    } catch (error) {
        throw new CustomError.UnauthenticatedError("Authnetication Invalid");
    }
}

//This is just hardcoded for single role only, but there can be many roles in the company
// const authorizePermissions = (req,res,next)=>{
//     if(req.user.role!=='admin'){
//         throw new CustomError.UnauthorizedError('Unauthorized to access this route');
//     }
//     next();
// }

const authorizePermissions = (...roles)=>{
    return (req,res,next)=>{//req,res,next makes a middleware so it has not not be passed in the calling function
        if(!roles.includes(req.user.role)){
            throw new CustomError.UnauthorizedError("Authorization invalid");
        }
        next();
    }
}

module.exports={authenticateUser,authorizePermissions};