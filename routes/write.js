var express = require('express');
var router = express.Router();

var MongoClient = require('mongodb').MongoClient;
var Constants = require('../app/constants');
var MongoQuery = require('../app/mongo_query');

/* GET home page. */

router.get('/', function(req, res) {
  res.render('write', { title: 'Enter Key / Value Pair' });
});

module.exports = router;
