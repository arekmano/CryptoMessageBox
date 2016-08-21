/*jshint multistr: true */
JSEncrypt = require('jsencrypt').JSEncrypt;
Constants = require('./constants');

function encryptKeyValuePair(pair){
  var crypt = new JSEncrypt();
  crypt.setPublicKey(Constants.public_key);
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

  if (value_element.value == ""){
    value_element = document.getElementById("value_select");
  }

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
  var form = form.appendChild(createSelect());
};

function createSelect(){
  var select = document.createElement("select");
  select.id = "value_select";
  Constants.value_options.forEach(function(element){
    var option = document.createElement("option");
    option.text = element;
    select.add(option);
  })
  return select;
}