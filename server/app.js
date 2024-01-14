require('dotenv').config();
require('express-async-errors');// to avoid try-catch

// express
const express = require('express');
const app =express();

//all other packages
const morgan = require('morgan');
const fileUpload= require('express-fileupload');

// database
const connectDB = require('./db/connect');

const xss=require('xss-clean');
const cors = require('cors');
const rateLimiter = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const helmet = require('helmet');

// routes
const authRouter = require('./routes/authRoutes');
const userRouter = require('./routes/userRoutes');
const productRouter = require('./routes/productRoutes');
const reviewRouter = require('./routes/reviewRoutes');
const orderRouter = require('./routes/orderRoutes');

// impoort middleware
const cookieParser = require('cookie-parser');
const notFoundMiddleware= require('./middleware/not-found');
const errorHandlerMiddleware = require('./middleware/error-handler');

// middleware

app.use(helmet());
app.use(cors());
app.use(xss());
app.use(mongoSanitize());
app.use(rateLimiter({
    windowMs:15*60*1000,
    max:60,
}));

app.use(cookieParser(process.env.JWT_SECRET));// using the cookieParser middleware we can now access the req.cookies, which contains the token in it, so that we now not have to take the token from frontend everytime
app.use(express.json());
// app.use(morgan('tiny'));

app.use(express.static('./public'));
app.use(fileUpload());

//routes

app.use('/api/v1/auth',authRouter);
app.use('/api/v1/users',userRouter);

app.use('/api/v1/products',productRouter);
app.use('/api/v1/reviews',reviewRouter);
app.use('/api/v1/orders',orderRouter);

app.use(notFoundMiddleware);// in the notFoundMiddleware we are not calling next() so the call gets ended here only
app.use(errorHandlerMiddleware);// this is only thrown in the errors from the already existing routes, it can't be invoked from the routes that doesn't even exist

const port=process.env.PORT||5000;

const start = async()=>{
    try {
        await connectDB(process.env.MONGO_URI);
        console.log("Successfully connected to the databse...");
        app.listen(port,()=>console.log(`Server is listening at port ${port}...`));
    } catch (error) {
        console.log(error);
    }
}

start();