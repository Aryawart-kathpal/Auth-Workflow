require('dotenv').config();
const jwt = require('jsonwebtoken');

// as now we are controlling the xpiration with the cookie, so now we no longer have to use that expiration in the jwt
const createJWT =({payload})=>{
    const token = jwt.sign(payload,process.env.JWT_SECRET);
    return token;
}

// Now there will be 2 cookies running one, will be the accessToken and other refreshToken
const attachCookiesToResponse = ({res,user,refreshToken})=>{
    const accessTokenJWT = createJWT({payload:{user}});// this will be for short term, say 15mins,1hr,1day
    const refreshTokenJWT = createJWT({payload:{user,refreshToken}});// but this will have an expiration time of longer period say 1month or more

    const oneDay = 1000*60*60*24;
    const longerExp = 1000*60*60*24*30;//30days

    res.cookie('accessToken',accessTokenJWT,{
        httpOnly:true,
        secure : process.env.NODE_ENV==='production',
        signed:true,
        // maxAge:1000,// sets the expiration time in milliseconds, for now we are setting it much less
        expires: new Date(Date.now()+oneDay),
    })

    res.cookie('refreshToken',refreshTokenJWT,{
        httpOnly:true,
        secure : process.env.NODE_ENV==='production',
        signed:true,
        expires: new Date(Date.now()+longerExp),// for now we are setting it for one day but will modify it later
    })
}

// const attachSingleCookieToResponse = ({res,user})=>{
//     const token = createJWT({payload:user});

//     const oneDay = 1000*60*60*24;

//     res.cookie('token',token,{
//         httpOnly:true,
//         expires: new Date(Date.now()+oneDay),
//         secure : process.env.NODE_ENV==='production',
//         signed:true,// to check that the user can not manually modify the cookie in the browser, so we send it signed with some value in cookieParser
//     })
// }

const isTokenValid = (token)=> jwt.verify(token,process.env.JWT_SECRET);

module.exports ={createJWT,isTokenValid,attachCookiesToResponse};