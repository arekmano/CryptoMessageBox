/*jshint multistr: true */

PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuj9SZS3++QeQWdueiU2J\
w4qf9BMTYHNyKY0pbNBQYl7ScpUc6QGWDpyAPPfwHaQ+nxtefFfhZfgJWlzZ7E0G\
JvYeORCHv0P88OcXI1B/7/WsU6y6j/zb2zm/B6qiyJls6zla6WfdfBS0exIDmcxj\
xcFYf9n9JyfL5oDakf5CD442LBENp7wBHxYYbbi9S3tNiQLcqrWvbCd64n02kgnM\
HTiFv5ww5mTPE15GBPRP4m1Cf4F0PbuLSO6pHro2rgaIlWieDDw6fDAjJ6FsAPIR\
ZhKcwUDO/I8D3gk0DTI3Bo4iG7/hAI+0lMDOPjpaHyuU4gkf7tdW3oRukQF+342q\
9QIDAQAB\
-----END PUBLIC KEY-----";

function encryptKeyValuePair(pair){
  var crypt = new JSEncrypt();
  crypt.setPublicKey(PUBLIC_KEY);
  encrypted_pair = {
    key: crypt.encrypt(pair.key),
    value: crypt.encrypt(pair.value)
  };
  return encrypted_pair;
}

function submitKeyValuePair(event) {
  event.preventDefault();
  key_element = document.getElementById("key");
  value_element = document.getElementById("value");

  var pair = {
    key : key_element.value,
    value : value_element.value
  };

  var encrypted_pair = encryptKeyValuePair(pair);

  send(encrypted_pair);
}

function send(encrypted_pair) {
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function() {
    if (xhttp.readyState == 4 && xhttp.status == 200) {
     alert('Sent successfully');
    }
  };
  xhttp.open("POST", "write", true);
  xhttp.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
  xhttp.send(JSON.stringify(encrypted_pair));
}

window.onload = function(){
  var form = document.getElementById("form");
  form.addEventListener('submit', submitKeyValuePair);
};
