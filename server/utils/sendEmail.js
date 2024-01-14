const nodemailer = require('nodemailer');
const nodemailerConfig = require('./nodemailerConfig');

const sendEmail = async({to,html,subject})=>{
    const testAccount = nodemailer.createTestAccount();

    const transporter = nodemailer.createTransport(nodemailerConfig);

    // Although, it is promise returning but here it doesn't require await as it is already using in await sendEmail() in the authController
    return transporter.sendMail({ 
        from: '"Aryawart Kathpal" <arya@gmail.com>', // sender address
        to,subject,html,
    });
}

module.exports=sendEmail;