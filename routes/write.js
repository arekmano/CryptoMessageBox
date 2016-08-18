var express = require('express');
var router = express.Router();

var DocumentService = require('../services/document_service');


/* GET home page. */

router.post('/', function(req, res) {
  console.log('New Key / Value Pair posted:');
  console.log(req.body);
  DocumentService.write(req, res);
});

module.exports = router;
