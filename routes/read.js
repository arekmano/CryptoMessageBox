var express = require('express');
var router = express.Router();

var DocumentService = require('../services/document_service');

/* GET documents listing. */
router.get('/', function(req, res) {
  DocumentService.read(res);
});

module.exports = router;
