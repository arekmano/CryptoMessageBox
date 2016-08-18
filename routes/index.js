var express = require('express');
var router = express.Router();

var DocumentService = require('../services/document_service');

/* GET Home Page. */
router.get('/', function(req, res) {
  res.render('partials/write', {title: 'Enter a Key / Value Pair.'});
});

module.exports = router;
