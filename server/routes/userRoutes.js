const express = require('express');
const router = express.Router();
const {authenticateUser,authorizePermissions}= require('../middleware/authentication');

const {getAllUsers,getSingleUser,updateUser,updateUserPassword,showCurrentUser} = require('../controllers/userController');

router.route('/').get(authenticateUser,authorizePermissions('admin','owner'),getAllUsers);
router.route('/showMe').get(authenticateUser,showCurrentUser);

router.route('/updateUser').patch(authenticateUser,updateUser);
router.route('/updateUserPassword').patch(authenticateUser,updateUserPassword);

router.route('/:id').get(authenticateUser,getSingleUser);// this mstep has to be at last because if it is above the showMe,updateUser,updateUserPassword then they will be considered as id, and id not found error will be thrown unncessarily

module.exports= router;