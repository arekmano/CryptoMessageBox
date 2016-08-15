var MongoClient = require('mongodb').MongoClient;
var Constants = require('../app/constants');
var MongoQuery = require('../app/mongo_query');

var read = function(res) {
  MongoClient.connect(Constants.mongo_url, function(err, db) {
    readDocuments(db, function(documents){
      db.close();
      res.json(documents);
    });
  });
};

var readDocuments = function(db, callback) {
   var cursor =db.collection('test').find({}, { _id: 0 });
   var documents = [];
   cursor.each(function(err, doc) {
      if (doc !== null) {
        documents.push(doc);
      } else {
         callback(documents);
      }
   });
};

var write = function(db, callback) {
  callback({written: 'ok'});
};

module.exports = {
  read: read,
  write: ""
};