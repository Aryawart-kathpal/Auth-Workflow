const express = require('express');
const router = express.Router();

const { authenticateUser, authorizePermissions } = require('../middleware/authentication');

// updateReview createReview deletReview only available for a logged in user

const { createReview, updateReview, getSingleReview, getAllReviews, deleteReview } = require('../controllers/reviewController');

router.route('/')
    .get(getAllReviews)
    .post(authenticateUser,createReview);

router.route('/:id')
    .get(getSingleReview)
    .patch(authenticateUser, updateReview)
    .delete(authenticateUser, deleteReview);

module.exports = router;