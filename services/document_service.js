var MongoClient = require('mongodb').MongoClient;
var Constants = require('../app/constants');

var read = function(res) {
  MongoClient.connect(Constants.mongo_url, function(err, db) {
    readDocuments(db, function(documents){
      res.json(documents);
    });
  });
};

var readDocuments = function(db, callback) {
  db.collection('test').find(
    {},
    { _id: 0, key: 1}
  ).toArray(function(err, docs) {
    db.close();
    callback(docs);
  });
};

var write = function(req, res) {
  MongoClient.connect(Constants.mongo_url, function(err, db) {
    db.collection('test').insert(req.body);
    db.close();
    response_json = req.body;
    response_json.message = 'OK';
    res.json(response_json);
  });
};

module.exports = {
  read: read,
  write: write
};