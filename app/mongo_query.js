var read = function(db, callback) {
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
  write: write
}