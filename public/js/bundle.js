(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
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
},{"./constants":2,"jsencrypt":3}],2:[function(require,module,exports){
/*jshint multistr: true */

module.exports = {
  public_key: "-----BEGIN PUBLIC KEY-----\
              MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5nip3X6DGvRnTCF7hQko\
              Tggz3q1MUNXVbDgacR9daeINJJ+iKUqGM4N2ipJsaKdaX2OnwFqOca/Wh08Dqrfu\
              A6uWmusrQnK4mhMRz4eLT4NdITUe/F0rEyUwVGjTC4YSzacBCeJJs731JGiFO7Zk\
              bbxPHUAgu0tDk5KBnDYXJ647fniBQxNKE9vYDt8LcYfv+Xa/np3o/vWaahGQT41h\
              TaudLDDbMce3vHNnM4bIHeajrJ9flzco7sZ4WhgmGZ1dFt4h0T4+w1ACf3+s39hp\
              pHe7jGr5WT1GOqFvrrJYJ7hD1QPCKfSpxX14btHx6KyHPb/Jtnob/1h1EXmaV4F9\
              dtr9OggRfEQd7HRpBIPHqTE/L4sgfoZlaeyuHTU+tg+vXa/y2b0tuXm8cTVEEWZf\
              4s6esLKDOeZ6ZjJDZ0G3IG9VV1FAgeMqbkEwhcxEt+WeafMJC0Wd/NhVIHFWZSw3\
              NgOvLsQmcQy1MnadvpmPtjDvQXCQPnGAdKUEuotHWVaF+p06XxKeZ9k2BzQ4RLPA\
              xZOUQ+HQNxHJN3vgqDyb6nrRWrmRpFW6fD9im8wfcJxO77ySduCDq+hcHk7UqvnL\
              I/6EcMujiI0Ryg0tnQteAU9CF6+xVyHpYASHo0t5SZDm1bKdWrjkJUsPzpdjzc1/\
              zY6+FSxBhtvkJ+egyCKdMhsCAwEAAQ==\
              -----END PUBLIC KEY-----",
  value_options: [
    101,
    201,
    205,
    301,
    401,
    601,
    602
  ]
};

},{}],3:[function(require,module,exports){
/*! JSEncrypt v2.3.1 | https://npmcdn.com/jsencrypt@2.3.1/LICENSE.txt */
(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD
    define(['exports'], factory);
  } else if (typeof exports === 'object' && typeof exports.nodeName !== 'string') {
    // Node, CommonJS-like
    factory(module.exports);
  } else {
    factory(root);
  }
})(this, function (exports) {
  // Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Basic JavaScript BN library - subset useful for RSA encryption.

// Bits per digit
var dbits;

// JavaScript engine analysis
var canary = 0xdeadbeefcafe;
var j_lm = ((canary&0xffffff)==0xefcafe);

// (public) Constructor
function BigInteger(a,b,c) {
  if(a != null)
    if("number" == typeof a) this.fromNumber(a,b,c);
    else if(b == null && "string" != typeof a) this.fromString(a,256);
    else this.fromString(a,b);
}

// return new, unset BigInteger
function nbi() { return new BigInteger(null); }

// am: Compute w_j += (x*this_i), propagate carries,
// c is initial carry, returns final carry.
// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
// We need to select the fastest one that works in this environment.

// am1: use a single mult and divide to get the high bits,
// max digit bits should be 26 because
// max internal value = 2*dvalue^2-2*dvalue (< 2^53)
function am1(i,x,w,j,c,n) {
  while(--n >= 0) {
    var v = x*this[i++]+w[j]+c;
    c = Math.floor(v/0x4000000);
    w[j++] = v&0x3ffffff;
  }
  return c;
}
// am2 avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
function am2(i,x,w,j,c,n) {
  var xl = x&0x7fff, xh = x>>15;
  while(--n >= 0) {
    var l = this[i]&0x7fff;
    var h = this[i++]>>15;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x7fff)<<15)+w[j]+(c&0x3fffffff);
    c = (l>>>30)+(m>>>15)+xh*h+(c>>>30);
    w[j++] = l&0x3fffffff;
  }
  return c;
}
// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.
function am3(i,x,w,j,c,n) {
  var xl = x&0x3fff, xh = x>>14;
  while(--n >= 0) {
    var l = this[i]&0x3fff;
    var h = this[i++]>>14;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x3fff)<<14)+w[j]+c;
    c = (l>>28)+(m>>14)+xh*h;
    w[j++] = l&0xfffffff;
  }
  return c;
}
if(j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
  BigInteger.prototype.am = am2;
  dbits = 30;
}
else if(j_lm && (navigator.appName != "Netscape")) {
  BigInteger.prototype.am = am1;
  dbits = 26;
}
else { // Mozilla/Netscape seems to prefer am3
  BigInteger.prototype.am = am3;
  dbits = 28;
}

BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = ((1<<dbits)-1);
BigInteger.prototype.DV = (1<<dbits);

var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2,BI_FP);
BigInteger.prototype.F1 = BI_FP-dbits;
BigInteger.prototype.F2 = 2*dbits-BI_FP;

// Digit conversions
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr,vv;
rr = "0".charCodeAt(0);
for(vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
rr = "a".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
rr = "A".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

function int2char(n) { return BI_RM.charAt(n); }
function intAt(s,i) {
  var c = BI_RC[s.charCodeAt(i)];
  return (c==null)?-1:c;
}

// (protected) copy this to r
function bnpCopyTo(r) {
  for(var i = this.t-1; i >= 0; --i) r[i] = this[i];
  r.t = this.t;
  r.s = this.s;
}

// (protected) set from integer value x, -DV <= x < DV
function bnpFromInt(x) {
  this.t = 1;
  this.s = (x<0)?-1:0;
  if(x > 0) this[0] = x;
  else if(x < -1) this[0] = x+this.DV;
  else this.t = 0;
}

// return bigint initialized to value
function nbv(i) { var r = nbi(); r.fromInt(i); return r; }

// (protected) set from string and radix
function bnpFromString(s,b) {
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 256) k = 8; // byte array
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else { this.fromRadix(s,b); return; }
  this.t = 0;
  this.s = 0;
  var i = s.length, mi = false, sh = 0;
  while(--i >= 0) {
    var x = (k==8)?s[i]&0xff:intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-") mi = true;
      continue;
    }
    mi = false;
    if(sh == 0)
      this[this.t++] = x;
    else if(sh+k > this.DB) {
      this[this.t-1] |= (x&((1<<(this.DB-sh))-1))<<sh;
      this[this.t++] = (x>>(this.DB-sh));
    }
    else
      this[this.t-1] |= x<<sh;
    sh += k;
    if(sh >= this.DB) sh -= this.DB;
  }
  if(k == 8 && (s[0]&0x80) != 0) {
    this.s = -1;
    if(sh > 0) this[this.t-1] |= ((1<<(this.DB-sh))-1)<<sh;
  }
  this.clamp();
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) clamp off excess high words
function bnpClamp() {
  var c = this.s&this.DM;
  while(this.t > 0 && this[this.t-1] == c) --this.t;
}

// (public) return string representation in given radix
function bnToString(b) {
  if(this.s < 0) return "-"+this.negate().toString(b);
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else return this.toRadix(b);
  var km = (1<<k)-1, d, m = false, r = "", i = this.t;
  var p = this.DB-(i*this.DB)%k;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) > 0) { m = true; r = int2char(d); }
    while(i >= 0) {
      if(p < k) {
        d = (this[i]&((1<<p)-1))<<(k-p);
        d |= this[--i]>>(p+=this.DB-k);
      }
      else {
        d = (this[i]>>(p-=k))&km;
        if(p <= 0) { p += this.DB; --i; }
      }
      if(d > 0) m = true;
      if(m) r += int2char(d);
    }
  }
  return m?r:"0";
}

// (public) -this
function bnNegate() { var r = nbi(); BigInteger.ZERO.subTo(this,r); return r; }

// (public) |this|
function bnAbs() { return (this.s<0)?this.negate():this; }

// (public) return + if this > a, - if this < a, 0 if equal
function bnCompareTo(a) {
  var r = this.s-a.s;
  if(r != 0) return r;
  var i = this.t;
  r = i-a.t;
  if(r != 0) return (this.s<0)?-r:r;
  while(--i >= 0) if((r=this[i]-a[i]) != 0) return r;
  return 0;
}

// returns bit length of the integer x
function nbits(x) {
  var r = 1, t;
  if((t=x>>>16) != 0) { x = t; r += 16; }
  if((t=x>>8) != 0) { x = t; r += 8; }
  if((t=x>>4) != 0) { x = t; r += 4; }
  if((t=x>>2) != 0) { x = t; r += 2; }
  if((t=x>>1) != 0) { x = t; r += 1; }
  return r;
}

// (public) return the number of bits in "this"
function bnBitLength() {
  if(this.t <= 0) return 0;
  return this.DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this.DM));
}

// (protected) r = this << n*DB
function bnpDLShiftTo(n,r) {
  var i;
  for(i = this.t-1; i >= 0; --i) r[i+n] = this[i];
  for(i = n-1; i >= 0; --i) r[i] = 0;
  r.t = this.t+n;
  r.s = this.s;
}

// (protected) r = this >> n*DB
function bnpDRShiftTo(n,r) {
  for(var i = n; i < this.t; ++i) r[i-n] = this[i];
  r.t = Math.max(this.t-n,0);
  r.s = this.s;
}

// (protected) r = this << n
function bnpLShiftTo(n,r) {
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<cbs)-1;
  var ds = Math.floor(n/this.DB), c = (this.s<<bs)&this.DM, i;
  for(i = this.t-1; i >= 0; --i) {
    r[i+ds+1] = (this[i]>>cbs)|c;
    c = (this[i]&bm)<<bs;
  }
  for(i = ds-1; i >= 0; --i) r[i] = 0;
  r[ds] = c;
  r.t = this.t+ds+1;
  r.s = this.s;
  r.clamp();
}

// (protected) r = this >> n
function bnpRShiftTo(n,r) {
  r.s = this.s;
  var ds = Math.floor(n/this.DB);
  if(ds >= this.t) { r.t = 0; return; }
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<bs)-1;
  r[0] = this[ds]>>bs;
  for(var i = ds+1; i < this.t; ++i) {
    r[i-ds-1] |= (this[i]&bm)<<cbs;
    r[i-ds] = this[i]>>bs;
  }
  if(bs > 0) r[this.t-ds-1] |= (this.s&bm)<<cbs;
  r.t = this.t-ds;
  r.clamp();
}

// (protected) r = this - a
function bnpSubTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]-a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c -= a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c -= a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c -= a.s;
  }
  r.s = (c<0)?-1:0;
  if(c < -1) r[i++] = this.DV+c;
  else if(c > 0) r[i++] = c;
  r.t = i;
  r.clamp();
}

// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.
function bnpMultiplyTo(a,r) {
  var x = this.abs(), y = a.abs();
  var i = x.t;
  r.t = i+y.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < y.t; ++i) r[i+x.t] = x.am(0,y[i],r,i,0,x.t);
  r.s = 0;
  r.clamp();
  if(this.s != a.s) BigInteger.ZERO.subTo(r,r);
}

// (protected) r = this^2, r != this (HAC 14.16)
function bnpSquareTo(r) {
  var x = this.abs();
  var i = r.t = 2*x.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < x.t-1; ++i) {
    var c = x.am(i,x[i],r,2*i,0,1);
    if((r[i+x.t]+=x.am(i+1,2*x[i],r,2*i+1,c,x.t-i-1)) >= x.DV) {
      r[i+x.t] -= x.DV;
      r[i+x.t+1] = 1;
    }
  }
  if(r.t > 0) r[r.t-1] += x.am(i,x[i],r,2*i,0,1);
  r.s = 0;
  r.clamp();
}

// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.
function bnpDivRemTo(m,q,r) {
  var pm = m.abs();
  if(pm.t <= 0) return;
  var pt = this.abs();
  if(pt.t < pm.t) {
    if(q != null) q.fromInt(0);
    if(r != null) this.copyTo(r);
    return;
  }
  if(r == null) r = nbi();
  var y = nbi(), ts = this.s, ms = m.s;
  var nsh = this.DB-nbits(pm[pm.t-1]);	// normalize modulus
  if(nsh > 0) { pm.lShiftTo(nsh,y); pt.lShiftTo(nsh,r); }
  else { pm.copyTo(y); pt.copyTo(r); }
  var ys = y.t;
  var y0 = y[ys-1];
  if(y0 == 0) return;
  var yt = y0*(1<<this.F1)+((ys>1)?y[ys-2]>>this.F2:0);
  var d1 = this.FV/yt, d2 = (1<<this.F1)/yt, e = 1<<this.F2;
  var i = r.t, j = i-ys, t = (q==null)?nbi():q;
  y.dlShiftTo(j,t);
  if(r.compareTo(t) >= 0) {
    r[r.t++] = 1;
    r.subTo(t,r);
  }
  BigInteger.ONE.dlShiftTo(ys,t);
  t.subTo(y,y);	// "negative" y so we can replace sub with am later
  while(y.t < ys) y[y.t++] = 0;
  while(--j >= 0) {
    // Estimate quotient digit
    var qd = (r[--i]==y0)?this.DM:Math.floor(r[i]*d1+(r[i-1]+e)*d2);
    if((r[i]+=y.am(0,qd,r,j,0,ys)) < qd) {	// Try it out
      y.dlShiftTo(j,t);
      r.subTo(t,r);
      while(r[i] < --qd) r.subTo(t,r);
    }
  }
  if(q != null) {
    r.drShiftTo(ys,q);
    if(ts != ms) BigInteger.ZERO.subTo(q,q);
  }
  r.t = ys;
  r.clamp();
  if(nsh > 0) r.rShiftTo(nsh,r);	// Denormalize remainder
  if(ts < 0) BigInteger.ZERO.subTo(r,r);
}

// (public) this mod a
function bnMod(a) {
  var r = nbi();
  this.abs().divRemTo(a,null,r);
  if(this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r,r);
  return r;
}

// Modular reduction using "classic" algorithm
function Classic(m) { this.m = m; }
function cConvert(x) {
  if(x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
  else return x;
}
function cRevert(x) { return x; }
function cReduce(x) { x.divRemTo(this.m,null,x); }
function cMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }
function cSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

Classic.prototype.convert = cConvert;
Classic.prototype.revert = cRevert;
Classic.prototype.reduce = cReduce;
Classic.prototype.mulTo = cMulTo;
Classic.prototype.sqrTo = cSqrTo;

// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.
function bnpInvDigit() {
  if(this.t < 1) return 0;
  var x = this[0];
  if((x&1) == 0) return 0;
  var y = x&3;		// y == 1/x mod 2^2
  y = (y*(2-(x&0xf)*y))&0xf;	// y == 1/x mod 2^4
  y = (y*(2-(x&0xff)*y))&0xff;	// y == 1/x mod 2^8
  y = (y*(2-(((x&0xffff)*y)&0xffff)))&0xffff;	// y == 1/x mod 2^16
  // last step - calculate inverse mod DV directly;
  // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
  y = (y*(2-x*y%this.DV))%this.DV;		// y == 1/x mod 2^dbits
  // we really want the negative inverse, and -DV < y < DV
  return (y>0)?this.DV-y:-y;
}

// Montgomery reduction
function Montgomery(m) {
  this.m = m;
  this.mp = m.invDigit();
  this.mpl = this.mp&0x7fff;
  this.mph = this.mp>>15;
  this.um = (1<<(m.DB-15))-1;
  this.mt2 = 2*m.t;
}

// xR mod m
function montConvert(x) {
  var r = nbi();
  x.abs().dlShiftTo(this.m.t,r);
  r.divRemTo(this.m,null,r);
  if(x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r,r);
  return r;
}

// x/R mod m
function montRevert(x) {
  var r = nbi();
  x.copyTo(r);
  this.reduce(r);
  return r;
}

// x = x/R mod m (HAC 14.32)
function montReduce(x) {
  while(x.t <= this.mt2)	// pad x so am has enough room later
    x[x.t++] = 0;
  for(var i = 0; i < this.m.t; ++i) {
    // faster way of calculating u0 = x[i]*mp mod DV
    var j = x[i]&0x7fff;
    var u0 = (j*this.mpl+(((j*this.mph+(x[i]>>15)*this.mpl)&this.um)<<15))&x.DM;
    // use am to combine the multiply-shift-add into one call
    j = i+this.m.t;
    x[j] += this.m.am(0,u0,x,i,0,this.m.t);
    // propagate carry
    while(x[j] >= x.DV) { x[j] -= x.DV; x[++j]++; }
  }
  x.clamp();
  x.drShiftTo(this.m.t,x);
  if(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = "x^2/R mod m"; x != r
function montSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = "xy/R mod m"; x,y != r
function montMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;

// (protected) true iff this is even
function bnpIsEven() { return ((this.t>0)?(this[0]&1):this.s) == 0; }

// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
function bnpExp(e,z) {
  if(e > 0xffffffff || e < 1) return BigInteger.ONE;
  var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e)-1;
  g.copyTo(r);
  while(--i >= 0) {
    z.sqrTo(r,r2);
    if((e&(1<<i)) > 0) z.mulTo(r2,g,r);
    else { var t = r; r = r2; r2 = t; }
  }
  return z.revert(r);
}

// (public) this^e % m, 0 <= e < 2^32
function bnModPowInt(e,m) {
  var z;
  if(e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
  return this.exp(e,z);
}

// protected
BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.isEven = bnpIsEven;
BigInteger.prototype.exp = bnpExp;

// public
BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;

// "constants"
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);

// Copyright (c) 2005-2009  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Extended JavaScript BN functions, required for RSA private ops.

// Version 1.1: new BigInteger("0", 10) returns "proper" zero
// Version 1.2: square() API, isProbablePrime fix

// (public)
function bnClone() { var r = nbi(); this.copyTo(r); return r; }

// (public) return value as integer
function bnIntValue() {
  if(this.s < 0) {
    if(this.t == 1) return this[0]-this.DV;
    else if(this.t == 0) return -1;
  }
  else if(this.t == 1) return this[0];
  else if(this.t == 0) return 0;
  // assumes 16 < DB < 32
  return ((this[1]&((1<<(32-this.DB))-1))<<this.DB)|this[0];
}

// (public) return value as byte
function bnByteValue() { return (this.t==0)?this.s:(this[0]<<24)>>24; }

// (public) return value as short (assumes DB>=16)
function bnShortValue() { return (this.t==0)?this.s:(this[0]<<16)>>16; }

// (protected) return x s.t. r^x < DV
function bnpChunkSize(r) { return Math.floor(Math.LN2*this.DB/Math.log(r)); }

// (public) 0 if this == 0, 1 if this > 0
function bnSigNum() {
  if(this.s < 0) return -1;
  else if(this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
  else return 1;
}

// (protected) convert to radix string
function bnpToRadix(b) {
  if(b == null) b = 10;
  if(this.signum() == 0 || b < 2 || b > 36) return "0";
  var cs = this.chunkSize(b);
  var a = Math.pow(b,cs);
  var d = nbv(a), y = nbi(), z = nbi(), r = "";
  this.divRemTo(d,y,z);
  while(y.signum() > 0) {
    r = (a+z.intValue()).toString(b).substr(1) + r;
    y.divRemTo(d,y,z);
  }
  return z.intValue().toString(b) + r;
}

// (protected) convert from radix string
function bnpFromRadix(s,b) {
  this.fromInt(0);
  if(b == null) b = 10;
  var cs = this.chunkSize(b);
  var d = Math.pow(b,cs), mi = false, j = 0, w = 0;
  for(var i = 0; i < s.length; ++i) {
    var x = intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-" && this.signum() == 0) mi = true;
      continue;
    }
    w = b*w+x;
    if(++j >= cs) {
      this.dMultiply(d);
      this.dAddOffset(w,0);
      j = 0;
      w = 0;
    }
  }
  if(j > 0) {
    this.dMultiply(Math.pow(b,j));
    this.dAddOffset(w,0);
  }
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) alternate constructor
function bnpFromNumber(a,b,c) {
  if("number" == typeof b) {
    // new BigInteger(int,int,RNG)
    if(a < 2) this.fromInt(1);
    else {
      this.fromNumber(a,c);
      if(!this.testBit(a-1))	// force MSB set
        this.bitwiseTo(BigInteger.ONE.shiftLeft(a-1),op_or,this);
      if(this.isEven()) this.dAddOffset(1,0); // force odd
      while(!this.isProbablePrime(b)) {
        this.dAddOffset(2,0);
        if(this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a-1),this);
      }
    }
  }
  else {
    // new BigInteger(int,RNG)
    var x = new Array(), t = a&7;
    x.length = (a>>3)+1;
    b.nextBytes(x);
    if(t > 0) x[0] &= ((1<<t)-1); else x[0] = 0;
    this.fromString(x,256);
  }
}

// (public) convert to bigendian byte array
function bnToByteArray() {
  var i = this.t, r = new Array();
  r[0] = this.s;
  var p = this.DB-(i*this.DB)%8, d, k = 0;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) != (this.s&this.DM)>>p)
      r[k++] = d|(this.s<<(this.DB-p));
    while(i >= 0) {
      if(p < 8) {
        d = (this[i]&((1<<p)-1))<<(8-p);
        d |= this[--i]>>(p+=this.DB-8);
      }
      else {
        d = (this[i]>>(p-=8))&0xff;
        if(p <= 0) { p += this.DB; --i; }
      }
      if((d&0x80) != 0) d |= -256;
      if(k == 0 && (this.s&0x80) != (d&0x80)) ++k;
      if(k > 0 || d != this.s) r[k++] = d;
    }
  }
  return r;
}

function bnEquals(a) { return(this.compareTo(a)==0); }
function bnMin(a) { return(this.compareTo(a)<0)?this:a; }
function bnMax(a) { return(this.compareTo(a)>0)?this:a; }

// (protected) r = this op a (bitwise)
function bnpBitwiseTo(a,op,r) {
  var i, f, m = Math.min(a.t,this.t);
  for(i = 0; i < m; ++i) r[i] = op(this[i],a[i]);
  if(a.t < this.t) {
    f = a.s&this.DM;
    for(i = m; i < this.t; ++i) r[i] = op(this[i],f);
    r.t = this.t;
  }
  else {
    f = this.s&this.DM;
    for(i = m; i < a.t; ++i) r[i] = op(f,a[i]);
    r.t = a.t;
  }
  r.s = op(this.s,a.s);
  r.clamp();
}

// (public) this & a
function op_and(x,y) { return x&y; }
function bnAnd(a) { var r = nbi(); this.bitwiseTo(a,op_and,r); return r; }

// (public) this | a
function op_or(x,y) { return x|y; }
function bnOr(a) { var r = nbi(); this.bitwiseTo(a,op_or,r); return r; }

// (public) this ^ a
function op_xor(x,y) { return x^y; }
function bnXor(a) { var r = nbi(); this.bitwiseTo(a,op_xor,r); return r; }

// (public) this & ~a
function op_andnot(x,y) { return x&~y; }
function bnAndNot(a) { var r = nbi(); this.bitwiseTo(a,op_andnot,r); return r; }

// (public) ~this
function bnNot() {
  var r = nbi();
  for(var i = 0; i < this.t; ++i) r[i] = this.DM&~this[i];
  r.t = this.t;
  r.s = ~this.s;
  return r;
}

// (public) this << n
function bnShiftLeft(n) {
  var r = nbi();
  if(n < 0) this.rShiftTo(-n,r); else this.lShiftTo(n,r);
  return r;
}

// (public) this >> n
function bnShiftRight(n) {
  var r = nbi();
  if(n < 0) this.lShiftTo(-n,r); else this.rShiftTo(n,r);
  return r;
}

// return index of lowest 1-bit in x, x < 2^31
function lbit(x) {
  if(x == 0) return -1;
  var r = 0;
  if((x&0xffff) == 0) { x >>= 16; r += 16; }
  if((x&0xff) == 0) { x >>= 8; r += 8; }
  if((x&0xf) == 0) { x >>= 4; r += 4; }
  if((x&3) == 0) { x >>= 2; r += 2; }
  if((x&1) == 0) ++r;
  return r;
}

// (public) returns index of lowest 1-bit (or -1 if none)
function bnGetLowestSetBit() {
  for(var i = 0; i < this.t; ++i)
    if(this[i] != 0) return i*this.DB+lbit(this[i]);
  if(this.s < 0) return this.t*this.DB;
  return -1;
}

// return number of 1 bits in x
function cbit(x) {
  var r = 0;
  while(x != 0) { x &= x-1; ++r; }
  return r;
}

// (public) return number of set bits
function bnBitCount() {
  var r = 0, x = this.s&this.DM;
  for(var i = 0; i < this.t; ++i) r += cbit(this[i]^x);
  return r;
}

// (public) true iff nth bit is set
function bnTestBit(n) {
  var j = Math.floor(n/this.DB);
  if(j >= this.t) return(this.s!=0);
  return((this[j]&(1<<(n%this.DB)))!=0);
}

// (protected) this op (1<<n)
function bnpChangeBit(n,op) {
  var r = BigInteger.ONE.shiftLeft(n);
  this.bitwiseTo(r,op,r);
  return r;
}

// (public) this | (1<<n)
function bnSetBit(n) { return this.changeBit(n,op_or); }

// (public) this & ~(1<<n)
function bnClearBit(n) { return this.changeBit(n,op_andnot); }

// (public) this ^ (1<<n)
function bnFlipBit(n) { return this.changeBit(n,op_xor); }

// (protected) r = this + a
function bnpAddTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]+a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c += a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c += a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += a.s;
  }
  r.s = (c<0)?-1:0;
  if(c > 0) r[i++] = c;
  else if(c < -1) r[i++] = this.DV+c;
  r.t = i;
  r.clamp();
}

// (public) this + a
function bnAdd(a) { var r = nbi(); this.addTo(a,r); return r; }

// (public) this - a
function bnSubtract(a) { var r = nbi(); this.subTo(a,r); return r; }

// (public) this * a
function bnMultiply(a) { var r = nbi(); this.multiplyTo(a,r); return r; }

// (public) this^2
function bnSquare() { var r = nbi(); this.squareTo(r); return r; }

// (public) this / a
function bnDivide(a) { var r = nbi(); this.divRemTo(a,r,null); return r; }

// (public) this % a
function bnRemainder(a) { var r = nbi(); this.divRemTo(a,null,r); return r; }

// (public) [this/a,this%a]
function bnDivideAndRemainder(a) {
  var q = nbi(), r = nbi();
  this.divRemTo(a,q,r);
  return new Array(q,r);
}

// (protected) this *= n, this >= 0, 1 < n < DV
function bnpDMultiply(n) {
  this[this.t] = this.am(0,n-1,this,0,0,this.t);
  ++this.t;
  this.clamp();
}

// (protected) this += n << w words, this >= 0
function bnpDAddOffset(n,w) {
  if(n == 0) return;
  while(this.t <= w) this[this.t++] = 0;
  this[w] += n;
  while(this[w] >= this.DV) {
    this[w] -= this.DV;
    if(++w >= this.t) this[this.t++] = 0;
    ++this[w];
  }
}

// A "null" reducer
function NullExp() {}
function nNop(x) { return x; }
function nMulTo(x,y,r) { x.multiplyTo(y,r); }
function nSqrTo(x,r) { x.squareTo(r); }

NullExp.prototype.convert = nNop;
NullExp.prototype.revert = nNop;
NullExp.prototype.mulTo = nMulTo;
NullExp.prototype.sqrTo = nSqrTo;

// (public) this^e
function bnPow(e) { return this.exp(e,new NullExp()); }

// (protected) r = lower n words of "this * a", a.t <= n
// "this" should be the larger one if appropriate.
function bnpMultiplyLowerTo(a,n,r) {
  var i = Math.min(this.t+a.t,n);
  r.s = 0; // assumes a,this >= 0
  r.t = i;
  while(i > 0) r[--i] = 0;
  var j;
  for(j = r.t-this.t; i < j; ++i) r[i+this.t] = this.am(0,a[i],r,i,0,this.t);
  for(j = Math.min(a.t,n); i < j; ++i) this.am(0,a[i],r,i,0,n-i);
  r.clamp();
}

// (protected) r = "this * a" without lower n words, n > 0
// "this" should be the larger one if appropriate.
function bnpMultiplyUpperTo(a,n,r) {
  --n;
  var i = r.t = this.t+a.t-n;
  r.s = 0; // assumes a,this >= 0
  while(--i >= 0) r[i] = 0;
  for(i = Math.max(n-this.t,0); i < a.t; ++i)
    r[this.t+i-n] = this.am(n-i,a[i],r,0,0,this.t+i-n);
  r.clamp();
  r.drShiftTo(1,r);
}

// Barrett modular reduction
function Barrett(m) {
  // setup Barrett
  this.r2 = nbi();
  this.q3 = nbi();
  BigInteger.ONE.dlShiftTo(2*m.t,this.r2);
  this.mu = this.r2.divide(m);
  this.m = m;
}

function barrettConvert(x) {
  if(x.s < 0 || x.t > 2*this.m.t) return x.mod(this.m);
  else if(x.compareTo(this.m) < 0) return x;
  else { var r = nbi(); x.copyTo(r); this.reduce(r); return r; }
}

function barrettRevert(x) { return x; }

// x = x mod m (HAC 14.42)
function barrettReduce(x) {
  x.drShiftTo(this.m.t-1,this.r2);
  if(x.t > this.m.t+1) { x.t = this.m.t+1; x.clamp(); }
  this.mu.multiplyUpperTo(this.r2,this.m.t+1,this.q3);
  this.m.multiplyLowerTo(this.q3,this.m.t+1,this.r2);
  while(x.compareTo(this.r2) < 0) x.dAddOffset(1,this.m.t+1);
  x.subTo(this.r2,x);
  while(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = x^2 mod m; x != r
function barrettSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = x*y mod m; x,y != r
function barrettMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Barrett.prototype.convert = barrettConvert;
Barrett.prototype.revert = barrettRevert;
Barrett.prototype.reduce = barrettReduce;
Barrett.prototype.mulTo = barrettMulTo;
Barrett.prototype.sqrTo = barrettSqrTo;

// (public) this^e % m (HAC 14.85)
function bnModPow(e,m) {
  var i = e.bitLength(), k, r = nbv(1), z;
  if(i <= 0) return r;
  else if(i < 18) k = 1;
  else if(i < 48) k = 3;
  else if(i < 144) k = 4;
  else if(i < 768) k = 5;
  else k = 6;
  if(i < 8)
    z = new Classic(m);
  else if(m.isEven())
    z = new Barrett(m);
  else
    z = new Montgomery(m);

  // precomputation
  var g = new Array(), n = 3, k1 = k-1, km = (1<<k)-1;
  g[1] = z.convert(this);
  if(k > 1) {
    var g2 = nbi();
    z.sqrTo(g[1],g2);
    while(n <= km) {
      g[n] = nbi();
      z.mulTo(g2,g[n-2],g[n]);
      n += 2;
    }
  }

  var j = e.t-1, w, is1 = true, r2 = nbi(), t;
  i = nbits(e[j])-1;
  while(j >= 0) {
    if(i >= k1) w = (e[j]>>(i-k1))&km;
    else {
      w = (e[j]&((1<<(i+1))-1))<<(k1-i);
      if(j > 0) w |= e[j-1]>>(this.DB+i-k1);
    }

    n = k;
    while((w&1) == 0) { w >>= 1; --n; }
    if((i -= n) < 0) { i += this.DB; --j; }
    if(is1) {	// ret == 1, don't bother squaring or multiplying it
      g[w].copyTo(r);
      is1 = false;
    }
    else {
      while(n > 1) { z.sqrTo(r,r2); z.sqrTo(r2,r); n -= 2; }
      if(n > 0) z.sqrTo(r,r2); else { t = r; r = r2; r2 = t; }
      z.mulTo(r2,g[w],r);
    }

    while(j >= 0 && (e[j]&(1<<i)) == 0) {
      z.sqrTo(r,r2); t = r; r = r2; r2 = t;
      if(--i < 0) { i = this.DB-1; --j; }
    }
  }
  return z.revert(r);
}

// (public) gcd(this,a) (HAC 14.54)
function bnGCD(a) {
  var x = (this.s<0)?this.negate():this.clone();
  var y = (a.s<0)?a.negate():a.clone();
  if(x.compareTo(y) < 0) { var t = x; x = y; y = t; }
  var i = x.getLowestSetBit(), g = y.getLowestSetBit();
  if(g < 0) return x;
  if(i < g) g = i;
  if(g > 0) {
    x.rShiftTo(g,x);
    y.rShiftTo(g,y);
  }
  while(x.signum() > 0) {
    if((i = x.getLowestSetBit()) > 0) x.rShiftTo(i,x);
    if((i = y.getLowestSetBit()) > 0) y.rShiftTo(i,y);
    if(x.compareTo(y) >= 0) {
      x.subTo(y,x);
      x.rShiftTo(1,x);
    }
    else {
      y.subTo(x,y);
      y.rShiftTo(1,y);
    }
  }
  if(g > 0) y.lShiftTo(g,y);
  return y;
}

// (protected) this % n, n < 2^26
function bnpModInt(n) {
  if(n <= 0) return 0;
  var d = this.DV%n, r = (this.s<0)?n-1:0;
  if(this.t > 0)
    if(d == 0) r = this[0]%n;
    else for(var i = this.t-1; i >= 0; --i) r = (d*r+this[i])%n;
  return r;
}

// (public) 1/this % m (HAC 14.61)
function bnModInverse(m) {
  var ac = m.isEven();
  if((this.isEven() && ac) || m.signum() == 0) return BigInteger.ZERO;
  var u = m.clone(), v = this.clone();
  var a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1);
  while(u.signum() != 0) {
    while(u.isEven()) {
      u.rShiftTo(1,u);
      if(ac) {
        if(!a.isEven() || !b.isEven()) { a.addTo(this,a); b.subTo(m,b); }
        a.rShiftTo(1,a);
      }
      else if(!b.isEven()) b.subTo(m,b);
      b.rShiftTo(1,b);
    }
    while(v.isEven()) {
      v.rShiftTo(1,v);
      if(ac) {
        if(!c.isEven() || !d.isEven()) { c.addTo(this,c); d.subTo(m,d); }
        c.rShiftTo(1,c);
      }
      else if(!d.isEven()) d.subTo(m,d);
      d.rShiftTo(1,d);
    }
    if(u.compareTo(v) >= 0) {
      u.subTo(v,u);
      if(ac) a.subTo(c,a);
      b.subTo(d,b);
    }
    else {
      v.subTo(u,v);
      if(ac) c.subTo(a,c);
      d.subTo(b,d);
    }
  }
  if(v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
  if(d.compareTo(m) >= 0) return d.subtract(m);
  if(d.signum() < 0) d.addTo(m,d); else return d;
  if(d.signum() < 0) return d.add(m); else return d;
}

var lowprimes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997];
var lplim = (1<<26)/lowprimes[lowprimes.length-1];

// (public) test primality with certainty >= 1-.5^t
function bnIsProbablePrime(t) {
  var i, x = this.abs();
  if(x.t == 1 && x[0] <= lowprimes[lowprimes.length-1]) {
    for(i = 0; i < lowprimes.length; ++i)
      if(x[0] == lowprimes[i]) return true;
    return false;
  }
  if(x.isEven()) return false;
  i = 1;
  while(i < lowprimes.length) {
    var m = lowprimes[i], j = i+1;
    while(j < lowprimes.length && m < lplim) m *= lowprimes[j++];
    m = x.modInt(m);
    while(i < j) if(m%lowprimes[i++] == 0) return false;
  }
  return x.millerRabin(t);
}

// (protected) true if probably prime (HAC 4.24, Miller-Rabin)
function bnpMillerRabin(t) {
  var n1 = this.subtract(BigInteger.ONE);
  var k = n1.getLowestSetBit();
  if(k <= 0) return false;
  var r = n1.shiftRight(k);
  t = (t+1)>>1;
  if(t > lowprimes.length) t = lowprimes.length;
  var a = nbi();
  for(var i = 0; i < t; ++i) {
    //Pick bases at random, instead of starting at 2
    a.fromInt(lowprimes[Math.floor(Math.random()*lowprimes.length)]);
    var y = a.modPow(r,this);
    if(y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
      var j = 1;
      while(j++ < k && y.compareTo(n1) != 0) {
        y = y.modPowInt(2,this);
        if(y.compareTo(BigInteger.ONE) == 0) return false;
      }
      if(y.compareTo(n1) != 0) return false;
    }
  }
  return true;
}

// protected
BigInteger.prototype.chunkSize = bnpChunkSize;
BigInteger.prototype.toRadix = bnpToRadix;
BigInteger.prototype.fromRadix = bnpFromRadix;
BigInteger.prototype.fromNumber = bnpFromNumber;
BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
BigInteger.prototype.changeBit = bnpChangeBit;
BigInteger.prototype.addTo = bnpAddTo;
BigInteger.prototype.dMultiply = bnpDMultiply;
BigInteger.prototype.dAddOffset = bnpDAddOffset;
BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
BigInteger.prototype.modInt = bnpModInt;
BigInteger.prototype.millerRabin = bnpMillerRabin;

// public
BigInteger.prototype.clone = bnClone;
BigInteger.prototype.intValue = bnIntValue;
BigInteger.prototype.byteValue = bnByteValue;
BigInteger.prototype.shortValue = bnShortValue;
BigInteger.prototype.signum = bnSigNum;
BigInteger.prototype.toByteArray = bnToByteArray;
BigInteger.prototype.equals = bnEquals;
BigInteger.prototype.min = bnMin;
BigInteger.prototype.max = bnMax;
BigInteger.prototype.and = bnAnd;
BigInteger.prototype.or = bnOr;
BigInteger.prototype.xor = bnXor;
BigInteger.prototype.andNot = bnAndNot;
BigInteger.prototype.not = bnNot;
BigInteger.prototype.shiftLeft = bnShiftLeft;
BigInteger.prototype.shiftRight = bnShiftRight;
BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
BigInteger.prototype.bitCount = bnBitCount;
BigInteger.prototype.testBit = bnTestBit;
BigInteger.prototype.setBit = bnSetBit;
BigInteger.prototype.clearBit = bnClearBit;
BigInteger.prototype.flipBit = bnFlipBit;
BigInteger.prototype.add = bnAdd;
BigInteger.prototype.subtract = bnSubtract;
BigInteger.prototype.multiply = bnMultiply;
BigInteger.prototype.divide = bnDivide;
BigInteger.prototype.remainder = bnRemainder;
BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
BigInteger.prototype.modPow = bnModPow;
BigInteger.prototype.modInverse = bnModInverse;
BigInteger.prototype.pow = bnPow;
BigInteger.prototype.gcd = bnGCD;
BigInteger.prototype.isProbablePrime = bnIsProbablePrime;

// JSBN-specific extension
BigInteger.prototype.square = bnSquare;

// BigInteger interfaces not implemented in jsbn:

// BigInteger(int signum, byte[] magnitude)
// double doubleValue()
// float floatValue()
// int hashCode()
// long longValue()
// static BigInteger valueOf(long val)

// prng4.js - uses Arcfour as a PRNG

function Arcfour() {
  this.i = 0;
  this.j = 0;
  this.S = new Array();
}

// Initialize arcfour context from key, an array of ints, each from [0..255]
function ARC4init(key) {
  var i, j, t;
  for(i = 0; i < 256; ++i)
    this.S[i] = i;
  j = 0;
  for(i = 0; i < 256; ++i) {
    j = (j + this.S[i] + key[i % key.length]) & 255;
    t = this.S[i];
    this.S[i] = this.S[j];
    this.S[j] = t;
  }
  this.i = 0;
  this.j = 0;
}

function ARC4next() {
  var t;
  this.i = (this.i + 1) & 255;
  this.j = (this.j + this.S[this.i]) & 255;
  t = this.S[this.i];
  this.S[this.i] = this.S[this.j];
  this.S[this.j] = t;
  return this.S[(t + this.S[this.i]) & 255];
}

Arcfour.prototype.init = ARC4init;
Arcfour.prototype.next = ARC4next;

// Plug in your RNG constructor here
function prng_newstate() {
  return new Arcfour();
}

// Pool size must be a multiple of 4 and greater than 32.
// An array of bytes the size of the pool will be passed to init()
var rng_psize = 256;

// Random number generator - requires a PRNG backend, e.g. prng4.js
var rng_state;
var rng_pool;
var rng_pptr;

// Initialize the pool with junk if needed.
if(rng_pool == null) {
  rng_pool = new Array();
  rng_pptr = 0;
  var t;
  if(window.crypto && window.crypto.getRandomValues) {
    // Extract entropy (2048 bits) from RNG if available
    var z = new Uint32Array(256);
    window.crypto.getRandomValues(z);
    for (t = 0; t < z.length; ++t)
      rng_pool[rng_pptr++] = z[t] & 255;
  }

  // Use mouse events for entropy, if we do not have enough entropy by the time
  // we need it, entropy will be generated by Math.random.
  var onMouseMoveListener = function(ev) {
    this.count = this.count || 0;
    if (this.count >= 256 || rng_pptr >= rng_psize) {
      if (window.removeEventListener)
        window.removeEventListener("mousemove", onMouseMoveListener, false);
      else if (window.detachEvent)
        window.detachEvent("onmousemove", onMouseMoveListener);
      return;
    }
    try {
      var mouseCoordinates = ev.x + ev.y;
      rng_pool[rng_pptr++] = mouseCoordinates & 255;
      this.count += 1;
    } catch (e) {
      // Sometimes Firefox will deny permission to access event properties for some reason. Ignore.
    }
  };
  if (window.addEventListener)
    window.addEventListener("mousemove", onMouseMoveListener, false);
  else if (window.attachEvent)
    window.attachEvent("onmousemove", onMouseMoveListener);

}

function rng_get_byte() {
  if(rng_state == null) {
    rng_state = prng_newstate();
    // At this point, we may not have collected enough entropy.  If not, fall back to Math.random
    while (rng_pptr < rng_psize) {
      var random = Math.floor(65536 * Math.random());
      rng_pool[rng_pptr++] = random & 255;
    }
    rng_state.init(rng_pool);
    for(rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr)
      rng_pool[rng_pptr] = 0;
    rng_pptr = 0;
  }
  // TODO: allow reseeding after first request
  return rng_state.next();
}

function rng_get_bytes(ba) {
  var i;
  for(i = 0; i < ba.length; ++i) ba[i] = rng_get_byte();
}

function SecureRandom() {}

SecureRandom.prototype.nextBytes = rng_get_bytes;

// Depends on jsbn.js and rng.js

// Version 1.1: support utf-8 encoding in pkcs1pad2

// convert a (hex) string to a bignum object
function parseBigInt(str,r) {
  return new BigInteger(str,r);
}

function linebrk(s,n) {
  var ret = "";
  var i = 0;
  while(i + n < s.length) {
    ret += s.substring(i,i+n) + "\n";
    i += n;
  }
  return ret + s.substring(i,s.length);
}

function byte2Hex(b) {
  if(b < 0x10)
    return "0" + b.toString(16);
  else
    return b.toString(16);
}

// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
function pkcs1pad2(s,n) {
  if(n < s.length + 11) { // TODO: fix for utf-8
    console.error("Message too long for RSA");
    return null;
  }
  var ba = new Array();
  var i = s.length - 1;
  while(i >= 0 && n > 0) {
    var c = s.charCodeAt(i--);
    if(c < 128) { // encode using utf-8
      ba[--n] = c;
    }
    else if((c > 127) && (c < 2048)) {
      ba[--n] = (c & 63) | 128;
      ba[--n] = (c >> 6) | 192;
    }
    else {
      ba[--n] = (c & 63) | 128;
      ba[--n] = ((c >> 6) & 63) | 128;
      ba[--n] = (c >> 12) | 224;
    }
  }
  ba[--n] = 0;
  var rng = new SecureRandom();
  var x = new Array();
  while(n > 2) { // random non-zero pad
    x[0] = 0;
    while(x[0] == 0) rng.nextBytes(x);
    ba[--n] = x[0];
  }
  ba[--n] = 2;
  ba[--n] = 0;
  return new BigInteger(ba);
}

// "empty" RSA key constructor
function RSAKey() {
  this.n = null;
  this.e = 0;
  this.d = null;
  this.p = null;
  this.q = null;
  this.dmp1 = null;
  this.dmq1 = null;
  this.coeff = null;
}

// Set the public key fields N and e from hex strings
function RSASetPublic(N,E) {
  if(N != null && E != null && N.length > 0 && E.length > 0) {
    this.n = parseBigInt(N,16);
    this.e = parseInt(E,16);
  }
  else
    console.error("Invalid RSA public key");
}

// Perform raw public operation on "x": return x^e (mod n)
function RSADoPublic(x) {
  return x.modPowInt(this.e, this.n);
}

// Return the PKCS#1 RSA encryption of "text" as an even-length hex string
function RSAEncrypt(text) {
  var m = pkcs1pad2(text,(this.n.bitLength()+7)>>3);
  if(m == null) return null;
  var c = this.doPublic(m);
  if(c == null) return null;
  var h = c.toString(16);
  if((h.length & 1) == 0) return h; else return "0" + h;
}

// Return the PKCS#1 RSA encryption of "text" as a Base64-encoded string
//function RSAEncryptB64(text) {
//  var h = this.encrypt(text);
//  if(h) return hex2b64(h); else return null;
//}

// protected
RSAKey.prototype.doPublic = RSADoPublic;

// public
RSAKey.prototype.setPublic = RSASetPublic;
RSAKey.prototype.encrypt = RSAEncrypt;
//RSAKey.prototype.encrypt_b64 = RSAEncryptB64;

// Depends on rsa.js and jsbn2.js

// Version 1.1: support utf-8 decoding in pkcs1unpad2

// Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext
function pkcs1unpad2(d,n) {
  var b = d.toByteArray();
  var i = 0;
  while(i < b.length && b[i] == 0) ++i;
  if(b.length-i != n-1 || b[i] != 2)
    return null;
  ++i;
  while(b[i] != 0)
    if(++i >= b.length) return null;
  var ret = "";
  while(++i < b.length) {
    var c = b[i] & 255;
    if(c < 128) { // utf-8 decode
      ret += String.fromCharCode(c);
    }
    else if((c > 191) && (c < 224)) {
      ret += String.fromCharCode(((c & 31) << 6) | (b[i+1] & 63));
      ++i;
    }
    else {
      ret += String.fromCharCode(((c & 15) << 12) | ((b[i+1] & 63) << 6) | (b[i+2] & 63));
      i += 2;
    }
  }
  return ret;
}

// Set the private key fields N, e, and d from hex strings
function RSASetPrivate(N,E,D) {
  if(N != null && E != null && N.length > 0 && E.length > 0) {
    this.n = parseBigInt(N,16);
    this.e = parseInt(E,16);
    this.d = parseBigInt(D,16);
  }
  else
    console.error("Invalid RSA private key");
}

// Set the private key fields N, e, d and CRT params from hex strings
function RSASetPrivateEx(N,E,D,P,Q,DP,DQ,C) {
  if(N != null && E != null && N.length > 0 && E.length > 0) {
    this.n = parseBigInt(N,16);
    this.e = parseInt(E,16);
    this.d = parseBigInt(D,16);
    this.p = parseBigInt(P,16);
    this.q = parseBigInt(Q,16);
    this.dmp1 = parseBigInt(DP,16);
    this.dmq1 = parseBigInt(DQ,16);
    this.coeff = parseBigInt(C,16);
  }
  else
    console.error("Invalid RSA private key");
}

// Generate a new random private key B bits long, using public expt E
function RSAGenerate(B,E) {
  var rng = new SecureRandom();
  var qs = B>>1;
  this.e = parseInt(E,16);
  var ee = new BigInteger(E,16);
  for(;;) {
    for(;;) {
      this.p = new BigInteger(B-qs,1,rng);
      if(this.p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.p.isProbablePrime(10)) break;
    }
    for(;;) {
      this.q = new BigInteger(qs,1,rng);
      if(this.q.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.q.isProbablePrime(10)) break;
    }
    if(this.p.compareTo(this.q) <= 0) {
      var t = this.p;
      this.p = this.q;
      this.q = t;
    }
    var p1 = this.p.subtract(BigInteger.ONE);
    var q1 = this.q.subtract(BigInteger.ONE);
    var phi = p1.multiply(q1);
    if(phi.gcd(ee).compareTo(BigInteger.ONE) == 0) {
      this.n = this.p.multiply(this.q);
      this.d = ee.modInverse(phi);
      this.dmp1 = this.d.mod(p1);
      this.dmq1 = this.d.mod(q1);
      this.coeff = this.q.modInverse(this.p);
      break;
    }
  }
}

// Perform raw private operation on "x": return x^d (mod n)
function RSADoPrivate(x) {
  if(this.p == null || this.q == null)
    return x.modPow(this.d, this.n);

  // TODO: re-calculate any missing CRT params
  var xp = x.mod(this.p).modPow(this.dmp1, this.p);
  var xq = x.mod(this.q).modPow(this.dmq1, this.q);

  while(xp.compareTo(xq) < 0)
    xp = xp.add(this.p);
  return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
}

// Return the PKCS#1 RSA decryption of "ctext".
// "ctext" is an even-length hex string and the output is a plain string.
function RSADecrypt(ctext) {
  var c = parseBigInt(ctext, 16);
  var m = this.doPrivate(c);
  if(m == null) return null;
  return pkcs1unpad2(m, (this.n.bitLength()+7)>>3);
}

// Return the PKCS#1 RSA decryption of "ctext".
// "ctext" is a Base64-encoded string and the output is a plain string.
//function RSAB64Decrypt(ctext) {
//  var h = b64tohex(ctext);
//  if(h) return this.decrypt(h); else return null;
//}

// protected
RSAKey.prototype.doPrivate = RSADoPrivate;

// public
RSAKey.prototype.setPrivate = RSASetPrivate;
RSAKey.prototype.setPrivateEx = RSASetPrivateEx;
RSAKey.prototype.generate = RSAGenerate;
RSAKey.prototype.decrypt = RSADecrypt;
//RSAKey.prototype.b64_decrypt = RSAB64Decrypt;

// Copyright (c) 2011  Kevin M Burns Jr.
// All Rights Reserved.
// See "LICENSE" for details.
//
// Extension to jsbn which adds facilities for asynchronous RSA key generation
// Primarily created to avoid execution timeout on mobile devices
//
// http://www-cs-students.stanford.edu/~tjw/jsbn/
//
// ---

(function(){

// Generate a new random private key B bits long, using public expt E
var RSAGenerateAsync = function (B, E, callback) {
    //var rng = new SeededRandom();
    var rng = new SecureRandom();
    var qs = B >> 1;
    this.e = parseInt(E, 16);
    var ee = new BigInteger(E, 16);
    var rsa = this;
    // These functions have non-descript names because they were originally for(;;) loops.
    // I don't know about cryptography to give them better names than loop1-4.
    var loop1 = function() {
        var loop4 = function() {
            if (rsa.p.compareTo(rsa.q) <= 0) {
                var t = rsa.p;
                rsa.p = rsa.q;
                rsa.q = t;
            }
            var p1 = rsa.p.subtract(BigInteger.ONE);
            var q1 = rsa.q.subtract(BigInteger.ONE);
            var phi = p1.multiply(q1);
            if (phi.gcd(ee).compareTo(BigInteger.ONE) == 0) {
                rsa.n = rsa.p.multiply(rsa.q);
                rsa.d = ee.modInverse(phi);
                rsa.dmp1 = rsa.d.mod(p1);
                rsa.dmq1 = rsa.d.mod(q1);
                rsa.coeff = rsa.q.modInverse(rsa.p);
                setTimeout(function(){callback()},0); // escape
            } else {
                setTimeout(loop1,0);
            }
        };
        var loop3 = function() {
            rsa.q = nbi();
            rsa.q.fromNumberAsync(qs, 1, rng, function(){
                rsa.q.subtract(BigInteger.ONE).gcda(ee, function(r){
                    if (r.compareTo(BigInteger.ONE) == 0 && rsa.q.isProbablePrime(10)) {
                        setTimeout(loop4,0);
                    } else {
                        setTimeout(loop3,0);
                    }
                });
            });
        };
        var loop2 = function() {
            rsa.p = nbi();
            rsa.p.fromNumberAsync(B - qs, 1, rng, function(){
                rsa.p.subtract(BigInteger.ONE).gcda(ee, function(r){
                    if (r.compareTo(BigInteger.ONE) == 0 && rsa.p.isProbablePrime(10)) {
                        setTimeout(loop3,0);
                    } else {
                        setTimeout(loop2,0);
                    }
                });
            });
        };
        setTimeout(loop2,0);
    };
    setTimeout(loop1,0);
};
RSAKey.prototype.generateAsync = RSAGenerateAsync;

// Public API method
var bnGCDAsync = function (a, callback) {
    var x = (this.s < 0) ? this.negate() : this.clone();
    var y = (a.s < 0) ? a.negate() : a.clone();
    if (x.compareTo(y) < 0) {
        var t = x;
        x = y;
        y = t;
    }
    var i = x.getLowestSetBit(),
        g = y.getLowestSetBit();
    if (g < 0) {
        callback(x);
        return;
    }
    if (i < g) g = i;
    if (g > 0) {
        x.rShiftTo(g, x);
        y.rShiftTo(g, y);
    }
    // Workhorse of the algorithm, gets called 200 - 800 times per 512 bit keygen.
    var gcda1 = function() {
        if ((i = x.getLowestSetBit()) > 0){ x.rShiftTo(i, x); }
        if ((i = y.getLowestSetBit()) > 0){ y.rShiftTo(i, y); }
        if (x.compareTo(y) >= 0) {
            x.subTo(y, x);
            x.rShiftTo(1, x);
        } else {
            y.subTo(x, y);
            y.rShiftTo(1, y);
        }
        if(!(x.signum() > 0)) {
            if (g > 0) y.lShiftTo(g, y);
            setTimeout(function(){callback(y)},0); // escape
        } else {
            setTimeout(gcda1,0);
        }
    };
    setTimeout(gcda1,10);
};
BigInteger.prototype.gcda = bnGCDAsync;

// (protected) alternate constructor
var bnpFromNumberAsync = function (a,b,c,callback) {
  if("number" == typeof b) {
    if(a < 2) {
        this.fromInt(1);
    } else {
      this.fromNumber(a,c);
      if(!this.testBit(a-1)){
        this.bitwiseTo(BigInteger.ONE.shiftLeft(a-1),op_or,this);
      }
      if(this.isEven()) {
        this.dAddOffset(1,0);
      }
      var bnp = this;
      var bnpfn1 = function(){
        bnp.dAddOffset(2,0);
        if(bnp.bitLength() > a) bnp.subTo(BigInteger.ONE.shiftLeft(a-1),bnp);
        if(bnp.isProbablePrime(b)) {
            setTimeout(function(){callback()},0); // escape
        } else {
            setTimeout(bnpfn1,0);
        }
      };
      setTimeout(bnpfn1,0);
    }
  } else {
    var x = new Array(), t = a&7;
    x.length = (a>>3)+1;
    b.nextBytes(x);
    if(t > 0) x[0] &= ((1<<t)-1); else x[0] = 0;
    this.fromString(x,256);
  }
};
BigInteger.prototype.fromNumberAsync = bnpFromNumberAsync;

})();
var b64map="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
var b64pad="=";

function hex2b64(h) {
  var i;
  var c;
  var ret = "";
  for(i = 0; i+3 <= h.length; i+=3) {
    c = parseInt(h.substring(i,i+3),16);
    ret += b64map.charAt(c >> 6) + b64map.charAt(c & 63);
  }
  if(i+1 == h.length) {
    c = parseInt(h.substring(i,i+1),16);
    ret += b64map.charAt(c << 2);
  }
  else if(i+2 == h.length) {
    c = parseInt(h.substring(i,i+2),16);
    ret += b64map.charAt(c >> 2) + b64map.charAt((c & 3) << 4);
  }
  while((ret.length & 3) > 0) ret += b64pad;
  return ret;
}

// convert a base64 string to hex
function b64tohex(s) {
  var ret = ""
  var i;
  var k = 0; // b64 state, 0-3
  var slop;
  for(i = 0; i < s.length; ++i) {
    if(s.charAt(i) == b64pad) break;
    v = b64map.indexOf(s.charAt(i));
    if(v < 0) continue;
    if(k == 0) {
      ret += int2char(v >> 2);
      slop = v & 3;
      k = 1;
    }
    else if(k == 1) {
      ret += int2char((slop << 2) | (v >> 4));
      slop = v & 0xf;
      k = 2;
    }
    else if(k == 2) {
      ret += int2char(slop);
      ret += int2char(v >> 2);
      slop = v & 3;
      k = 3;
    }
    else {
      ret += int2char((slop << 2) | (v >> 4));
      ret += int2char(v & 0xf);
      k = 0;
    }
  }
  if(k == 1)
    ret += int2char(slop << 2);
  return ret;
}

// convert a base64 string to a byte/number array
function b64toBA(s) {
  //piggyback on b64tohex for now, optimize later
  var h = b64tohex(s);
  var i;
  var a = new Array();
  for(i = 0; 2*i < h.length; ++i) {
    a[i] = parseInt(h.substring(2*i,2*i+2),16);
  }
  return a;
}

/*! asn1-1.0.2.js (c) 2013 Kenji Urushima | kjur.github.com/jsrsasign/license
 */

var JSX = JSX || {};
JSX.env = JSX.env || {};

var L = JSX, OP = Object.prototype, FUNCTION_TOSTRING = '[object Function]',ADD = ["toString", "valueOf"];

JSX.env.parseUA = function(agent) {

    var numberify = function(s) {
        var c = 0;
        return parseFloat(s.replace(/\./g, function() {
            return (c++ == 1) ? '' : '.';
        }));
    },

    nav = navigator,
    o = {
        ie: 0,
        opera: 0,
        gecko: 0,
        webkit: 0,
        chrome: 0,
        mobile: null,
        air: 0,
        ipad: 0,
        iphone: 0,
        ipod: 0,
        ios: null,
        android: 0,
        webos: 0,
        caja: nav && nav.cajaVersion,
        secure: false,
        os: null

    },

    ua = agent || (navigator && navigator.userAgent),
    loc = window && window.location,
    href = loc && loc.href,
    m;

    o.secure = href && (href.toLowerCase().indexOf("https") === 0);

    if (ua) {

        if ((/windows|win32/i).test(ua)) {
            o.os = 'windows';
        } else if ((/macintosh/i).test(ua)) {
            o.os = 'macintosh';
        } else if ((/rhino/i).test(ua)) {
            o.os = 'rhino';
        }
        if ((/KHTML/).test(ua)) {
            o.webkit = 1;
        }
        m = ua.match(/AppleWebKit\/([^\s]*)/);
        if (m && m[1]) {
            o.webkit = numberify(m[1]);
            if (/ Mobile\//.test(ua)) {
                o.mobile = 'Apple'; // iPhone or iPod Touch
                m = ua.match(/OS ([^\s]*)/);
                if (m && m[1]) {
                    m = numberify(m[1].replace('_', '.'));
                }
                o.ios = m;
                o.ipad = o.ipod = o.iphone = 0;
                m = ua.match(/iPad|iPod|iPhone/);
                if (m && m[0]) {
                    o[m[0].toLowerCase()] = o.ios;
                }
            } else {
                m = ua.match(/NokiaN[^\/]*|Android \d\.\d|webOS\/\d\.\d/);
                if (m) {
                    o.mobile = m[0];
                }
                if (/webOS/.test(ua)) {
                    o.mobile = 'WebOS';
                    m = ua.match(/webOS\/([^\s]*);/);
                    if (m && m[1]) {
                        o.webos = numberify(m[1]);
                    }
                }
                if (/ Android/.test(ua)) {
                    o.mobile = 'Android';
                    m = ua.match(/Android ([^\s]*);/);
                    if (m && m[1]) {
                        o.android = numberify(m[1]);
                    }
                }
            }
            m = ua.match(/Chrome\/([^\s]*)/);
            if (m && m[1]) {
                o.chrome = numberify(m[1]); // Chrome
            } else {
                m = ua.match(/AdobeAIR\/([^\s]*)/);
                if (m) {
                    o.air = m[0]; // Adobe AIR 1.0 or better
                }
            }
        }
        if (!o.webkit) {
            m = ua.match(/Opera[\s\/]([^\s]*)/);
            if (m && m[1]) {
                o.opera = numberify(m[1]);
                m = ua.match(/Version\/([^\s]*)/);
                if (m && m[1]) {
                    o.opera = numberify(m[1]); // opera 10+
                }
                m = ua.match(/Opera Mini[^;]*/);
                if (m) {
                    o.mobile = m[0]; // ex: Opera Mini/2.0.4509/1316
                }
            } else { // not opera or webkit
                m = ua.match(/MSIE\s([^;]*)/);
                if (m && m[1]) {
                    o.ie = numberify(m[1]);
                } else { // not opera, webkit, or ie
                    m = ua.match(/Gecko\/([^\s]*)/);
                    if (m) {
                        o.gecko = 1; // Gecko detected, look for revision
                        m = ua.match(/rv:([^\s\)]*)/);
                        if (m && m[1]) {
                            o.gecko = numberify(m[1]);
                        }
                    }
                }
            }
        }
    }
    return o;
};

JSX.env.ua = JSX.env.parseUA();

JSX.isFunction = function(o) {
    return (typeof o === 'function') || OP.toString.apply(o) === FUNCTION_TOSTRING;
};

JSX._IEEnumFix = (JSX.env.ua.ie) ? function(r, s) {
    var i, fname, f;
    for (i=0;i<ADD.length;i=i+1) {

        fname = ADD[i];
        f = s[fname];

        if (L.isFunction(f) && f!=OP[fname]) {
            r[fname]=f;
        }
    }
} : function(){};

JSX.extend = function(subc, superc, overrides) {
    if (!superc||!subc) {
        throw new Error("extend failed, please check that " +
                        "all dependencies are included.");
    }
    var F = function() {}, i;
    F.prototype=superc.prototype;
    subc.prototype=new F();
    subc.prototype.constructor=subc;
    subc.superclass=superc.prototype;
    if (superc.prototype.constructor == OP.constructor) {
        superc.prototype.constructor=superc;
    }

    if (overrides) {
        for (i in overrides) {
            if (L.hasOwnProperty(overrides, i)) {
                subc.prototype[i]=overrides[i];
            }
        }

        L._IEEnumFix(subc.prototype, overrides);
    }
};

/*
 * asn1.js - ASN.1 DER encoder classes
 *
 * Copyright (c) 2013 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name asn1-1.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 1.0.2 (2013-May-30)
 * @since 2.1
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/** 
 * kjur's class library name space
 * <p>
 * This name space provides following name spaces:
 * <ul>
 * <li>{@link KJUR.asn1} - ASN.1 primitive hexadecimal encoder</li>
 * <li>{@link KJUR.asn1.x509} - ASN.1 structure for X.509 certificate and CRL</li>
 * <li>{@link KJUR.crypto} - Java Cryptographic Extension(JCE) style MessageDigest/Signature 
 * class and utilities</li>
 * </ul>
 * </p> 
 * NOTE: Please ignore method summary and document of this namespace. This caused by a bug of jsdoc2.
  * @name KJUR
 * @namespace kjur's class library name space
 */
if (typeof KJUR == "undefined" || !KJUR) KJUR = {};

/**
 * kjur's ASN.1 class library name space
 * <p>
 * This is ITU-T X.690 ASN.1 DER encoder class library and
 * class structure and methods is very similar to 
 * org.bouncycastle.asn1 package of 
 * well known BouncyCaslte Cryptography Library.
 *
 * <h4>PROVIDING ASN.1 PRIMITIVES</h4>
 * Here are ASN.1 DER primitive classes.
 * <ul>
 * <li>{@link KJUR.asn1.DERBoolean}</li>
 * <li>{@link KJUR.asn1.DERInteger}</li>
 * <li>{@link KJUR.asn1.DERBitString}</li>
 * <li>{@link KJUR.asn1.DEROctetString}</li>
 * <li>{@link KJUR.asn1.DERNull}</li>
 * <li>{@link KJUR.asn1.DERObjectIdentifier}</li>
 * <li>{@link KJUR.asn1.DERUTF8String}</li>
 * <li>{@link KJUR.asn1.DERNumericString}</li>
 * <li>{@link KJUR.asn1.DERPrintableString}</li>
 * <li>{@link KJUR.asn1.DERTeletexString}</li>
 * <li>{@link KJUR.asn1.DERIA5String}</li>
 * <li>{@link KJUR.asn1.DERUTCTime}</li>
 * <li>{@link KJUR.asn1.DERGeneralizedTime}</li>
 * <li>{@link KJUR.asn1.DERSequence}</li>
 * <li>{@link KJUR.asn1.DERSet}</li>
 * </ul>
 *
 * <h4>OTHER ASN.1 CLASSES</h4>
 * <ul>
 * <li>{@link KJUR.asn1.ASN1Object}</li>
 * <li>{@link KJUR.asn1.DERAbstractString}</li>
 * <li>{@link KJUR.asn1.DERAbstractTime}</li>
 * <li>{@link KJUR.asn1.DERAbstractStructured}</li>
 * <li>{@link KJUR.asn1.DERTaggedObject}</li>
 * </ul>
 * </p>
 * NOTE: Please ignore method summary and document of this namespace. This caused by a bug of jsdoc2.
 * @name KJUR.asn1
 * @namespace
 */
if (typeof KJUR.asn1 == "undefined" || !KJUR.asn1) KJUR.asn1 = {};

/**
 * ASN1 utilities class
 * @name KJUR.asn1.ASN1Util
 * @classs ASN1 utilities class
 * @since asn1 1.0.2
 */
KJUR.asn1.ASN1Util = new function() {
    this.integerToByteHex = function(i) {
	var h = i.toString(16);
	if ((h.length % 2) == 1) h = '0' + h;
	return h;
    };
    this.bigIntToMinTwosComplementsHex = function(bigIntegerValue) {
	var h = bigIntegerValue.toString(16);
	if (h.substr(0, 1) != '-') {
	    if (h.length % 2 == 1) {
		h = '0' + h;
	    } else {
		if (! h.match(/^[0-7]/)) {
		    h = '00' + h;
		}
	    }
	} else {
	    var hPos = h.substr(1);
	    var xorLen = hPos.length;
	    if (xorLen % 2 == 1) {
		xorLen += 1;
	    } else {
		if (! h.match(/^[0-7]/)) {
		    xorLen += 2;
		}
	    }
	    var hMask = '';
	    for (var i = 0; i < xorLen; i++) {
		hMask += 'f';
	    }
	    var biMask = new BigInteger(hMask, 16);
	    var biNeg = biMask.xor(bigIntegerValue).add(BigInteger.ONE);
	    h = biNeg.toString(16).replace(/^-/, '');
	}
	return h;
    };
    /**
     * get PEM string from hexadecimal data and header string
     * @name getPEMStringFromHex
     * @memberOf KJUR.asn1.ASN1Util
     * @function
     * @param {String} dataHex hexadecimal string of PEM body
     * @param {String} pemHeader PEM header string (ex. 'RSA PRIVATE KEY')
     * @return {String} PEM formatted string of input data
     * @description
     * @example
     * var pem  = KJUR.asn1.ASN1Util.getPEMStringFromHex('616161', 'RSA PRIVATE KEY');
     * // value of pem will be:
     * -----BEGIN PRIVATE KEY-----
     * YWFh
     * -----END PRIVATE KEY-----
     */
    this.getPEMStringFromHex = function(dataHex, pemHeader) {
	var dataWA = CryptoJS.enc.Hex.parse(dataHex);
	var dataB64 = CryptoJS.enc.Base64.stringify(dataWA);
	var pemBody = dataB64.replace(/(.{64})/g, "$1\r\n");
        pemBody = pemBody.replace(/\r\n$/, '');
	return "-----BEGIN " + pemHeader + "-----\r\n" + 
               pemBody + 
               "\r\n-----END " + pemHeader + "-----\r\n";
    };
};

// ********************************************************************
//  Abstract ASN.1 Classes
// ********************************************************************

// ********************************************************************

/**
 * base class for ASN.1 DER encoder object
 * @name KJUR.asn1.ASN1Object
 * @class base class for ASN.1 DER encoder object
 * @property {Boolean} isModified flag whether internal data was changed
 * @property {String} hTLV hexadecimal string of ASN.1 TLV
 * @property {String} hT hexadecimal string of ASN.1 TLV tag(T)
 * @property {String} hL hexadecimal string of ASN.1 TLV length(L)
 * @property {String} hV hexadecimal string of ASN.1 TLV value(V)
 * @description
 */
KJUR.asn1.ASN1Object = function() {
    var isModified = true;
    var hTLV = null;
    var hT = '00'
    var hL = '00';
    var hV = '';

    /**
     * get hexadecimal ASN.1 TLV length(L) bytes from TLV value(V)
     * @name getLengthHexFromValue
     * @memberOf KJUR.asn1.ASN1Object
     * @function
     * @return {String} hexadecimal string of ASN.1 TLV length(L)
     */
    this.getLengthHexFromValue = function() {
	if (typeof this.hV == "undefined" || this.hV == null) {
	    throw "this.hV is null or undefined.";
	}
	if (this.hV.length % 2 == 1) {
	    throw "value hex must be even length: n=" + hV.length + ",v=" + this.hV;
	}
	var n = this.hV.length / 2;
	var hN = n.toString(16);
	if (hN.length % 2 == 1) {
	    hN = "0" + hN;
	}
	if (n < 128) {
	    return hN;
	} else {
	    var hNlen = hN.length / 2;
	    if (hNlen > 15) {
		throw "ASN.1 length too long to represent by 8x: n = " + n.toString(16);
	    }
	    var head = 128 + hNlen;
	    return head.toString(16) + hN;
	}
    };

    /**
     * get hexadecimal string of ASN.1 TLV bytes
     * @name getEncodedHex
     * @memberOf KJUR.asn1.ASN1Object
     * @function
     * @return {String} hexadecimal string of ASN.1 TLV
     */
    this.getEncodedHex = function() {
	if (this.hTLV == null || this.isModified) {
	    this.hV = this.getFreshValueHex();
	    this.hL = this.getLengthHexFromValue();
	    this.hTLV = this.hT + this.hL + this.hV;
	    this.isModified = false;
	    //console.error("first time: " + this.hTLV);
	}
	return this.hTLV;
    };

    /**
     * get hexadecimal string of ASN.1 TLV value(V) bytes
     * @name getValueHex
     * @memberOf KJUR.asn1.ASN1Object
     * @function
     * @return {String} hexadecimal string of ASN.1 TLV value(V) bytes
     */
    this.getValueHex = function() {
	this.getEncodedHex();
	return this.hV;
    }

    this.getFreshValueHex = function() {
	return '';
    };
};

// == BEGIN DERAbstractString ================================================
/**
 * base class for ASN.1 DER string classes
 * @name KJUR.asn1.DERAbstractString
 * @class base class for ASN.1 DER string classes
 * @param {Array} params associative array of parameters (ex. {'str': 'aaa'})
 * @property {String} s internal string of value
 * @extends KJUR.asn1.ASN1Object
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>str - specify initial ASN.1 value(V) by a string</li>
 * <li>hex - specify initial ASN.1 value(V) by a hexadecimal string</li>
 * </ul>
 * NOTE: 'params' can be omitted.
 */
KJUR.asn1.DERAbstractString = function(params) {
    KJUR.asn1.DERAbstractString.superclass.constructor.call(this);
    var s = null;
    var hV = null;

    /**
     * get string value of this string object
     * @name getString
     * @memberOf KJUR.asn1.DERAbstractString
     * @function
     * @return {String} string value of this string object
     */
    this.getString = function() {
	return this.s;
    };

    /**
     * set value by a string
     * @name setString
     * @memberOf KJUR.asn1.DERAbstractString
     * @function
     * @param {String} newS value by a string to set
     */
    this.setString = function(newS) {
	this.hTLV = null;
	this.isModified = true;
	this.s = newS;
	this.hV = stohex(this.s);
    };

    /**
     * set value by a hexadecimal string
     * @name setStringHex
     * @memberOf KJUR.asn1.DERAbstractString
     * @function
     * @param {String} newHexString value by a hexadecimal string to set
     */
    this.setStringHex = function(newHexString) {
	this.hTLV = null;
	this.isModified = true;
	this.s = null;
	this.hV = newHexString;
    };

    this.getFreshValueHex = function() {
	return this.hV;
    };

    if (typeof params != "undefined") {
	if (typeof params['str'] != "undefined") {
	    this.setString(params['str']);
	} else if (typeof params['hex'] != "undefined") {
	    this.setStringHex(params['hex']);
	}
    }
};
JSX.extend(KJUR.asn1.DERAbstractString, KJUR.asn1.ASN1Object);
// == END   DERAbstractString ================================================

// == BEGIN DERAbstractTime ==================================================
/**
 * base class for ASN.1 DER Generalized/UTCTime class
 * @name KJUR.asn1.DERAbstractTime
 * @class base class for ASN.1 DER Generalized/UTCTime class
 * @param {Array} params associative array of parameters (ex. {'str': '130430235959Z'})
 * @extends KJUR.asn1.ASN1Object
 * @description
 * @see KJUR.asn1.ASN1Object - superclass
 */
KJUR.asn1.DERAbstractTime = function(params) {
    KJUR.asn1.DERAbstractTime.superclass.constructor.call(this);
    var s = null;
    var date = null;

    // --- PRIVATE METHODS --------------------
    this.localDateToUTC = function(d) {
	utc = d.getTime() + (d.getTimezoneOffset() * 60000);
	var utcDate = new Date(utc);
	return utcDate;
    };

    this.formatDate = function(dateObject, type) {
	var pad = this.zeroPadding;
	var d = this.localDateToUTC(dateObject);
	var year = String(d.getFullYear());
	if (type == 'utc') year = year.substr(2, 2);
	var month = pad(String(d.getMonth() + 1), 2);
	var day = pad(String(d.getDate()), 2);
	var hour = pad(String(d.getHours()), 2);
	var min = pad(String(d.getMinutes()), 2);
	var sec = pad(String(d.getSeconds()), 2);
	return year + month + day + hour + min + sec + 'Z';
    };

    this.zeroPadding = function(s, len) {
	if (s.length >= len) return s;
	return new Array(len - s.length + 1).join('0') + s;
    };

    // --- PUBLIC METHODS --------------------
    /**
     * get string value of this string object
     * @name getString
     * @memberOf KJUR.asn1.DERAbstractTime
     * @function
     * @return {String} string value of this time object
     */
    this.getString = function() {
	return this.s;
    };

    /**
     * set value by a string
     * @name setString
     * @memberOf KJUR.asn1.DERAbstractTime
     * @function
     * @param {String} newS value by a string to set such like "130430235959Z"
     */
    this.setString = function(newS) {
	this.hTLV = null;
	this.isModified = true;
	this.s = newS;
	this.hV = stohex(this.s);
    };

    /**
     * set value by a Date object
     * @name setByDateValue
     * @memberOf KJUR.asn1.DERAbstractTime
     * @function
     * @param {Integer} year year of date (ex. 2013)
     * @param {Integer} month month of date between 1 and 12 (ex. 12)
     * @param {Integer} day day of month
     * @param {Integer} hour hours of date
     * @param {Integer} min minutes of date
     * @param {Integer} sec seconds of date
     */
    this.setByDateValue = function(year, month, day, hour, min, sec) {
	var dateObject = new Date(Date.UTC(year, month - 1, day, hour, min, sec, 0));
	this.setByDate(dateObject);
    };

    this.getFreshValueHex = function() {
	return this.hV;
    };
};
JSX.extend(KJUR.asn1.DERAbstractTime, KJUR.asn1.ASN1Object);
// == END   DERAbstractTime ==================================================

// == BEGIN DERAbstractStructured ============================================
/**
 * base class for ASN.1 DER structured class
 * @name KJUR.asn1.DERAbstractStructured
 * @class base class for ASN.1 DER structured class
 * @property {Array} asn1Array internal array of ASN1Object
 * @extends KJUR.asn1.ASN1Object
 * @description
 * @see KJUR.asn1.ASN1Object - superclass
 */
KJUR.asn1.DERAbstractStructured = function(params) {
    KJUR.asn1.DERAbstractString.superclass.constructor.call(this);
    var asn1Array = null;

    /**
     * set value by array of ASN1Object
     * @name setByASN1ObjectArray
     * @memberOf KJUR.asn1.DERAbstractStructured
     * @function
     * @param {array} asn1ObjectArray array of ASN1Object to set
     */
    this.setByASN1ObjectArray = function(asn1ObjectArray) {
	this.hTLV = null;
	this.isModified = true;
	this.asn1Array = asn1ObjectArray;
    };

    /**
     * append an ASN1Object to internal array
     * @name appendASN1Object
     * @memberOf KJUR.asn1.DERAbstractStructured
     * @function
     * @param {ASN1Object} asn1Object to add
     */
    this.appendASN1Object = function(asn1Object) {
	this.hTLV = null;
	this.isModified = true;
	this.asn1Array.push(asn1Object);
    };

    this.asn1Array = new Array();
    if (typeof params != "undefined") {
	if (typeof params['array'] != "undefined") {
	    this.asn1Array = params['array'];
	}
    }
};
JSX.extend(KJUR.asn1.DERAbstractStructured, KJUR.asn1.ASN1Object);


// ********************************************************************
//  ASN.1 Object Classes
// ********************************************************************

// ********************************************************************
/**
 * class for ASN.1 DER Boolean
 * @name KJUR.asn1.DERBoolean
 * @class class for ASN.1 DER Boolean
 * @extends KJUR.asn1.ASN1Object
 * @description
 * @see KJUR.asn1.ASN1Object - superclass
 */
KJUR.asn1.DERBoolean = function() {
    KJUR.asn1.DERBoolean.superclass.constructor.call(this);
    this.hT = "01";
    this.hTLV = "0101ff";
};
JSX.extend(KJUR.asn1.DERBoolean, KJUR.asn1.ASN1Object);

// ********************************************************************
/**
 * class for ASN.1 DER Integer
 * @name KJUR.asn1.DERInteger
 * @class class for ASN.1 DER Integer
 * @extends KJUR.asn1.ASN1Object
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>int - specify initial ASN.1 value(V) by integer value</li>
 * <li>bigint - specify initial ASN.1 value(V) by BigInteger object</li>
 * <li>hex - specify initial ASN.1 value(V) by a hexadecimal string</li>
 * </ul>
 * NOTE: 'params' can be omitted.
 */
KJUR.asn1.DERInteger = function(params) {
    KJUR.asn1.DERInteger.superclass.constructor.call(this);
    this.hT = "02";

    /**
     * set value by Tom Wu's BigInteger object
     * @name setByBigInteger
     * @memberOf KJUR.asn1.DERInteger
     * @function
     * @param {BigInteger} bigIntegerValue to set
     */
    this.setByBigInteger = function(bigIntegerValue) {
	this.hTLV = null;
	this.isModified = true;
	this.hV = KJUR.asn1.ASN1Util.bigIntToMinTwosComplementsHex(bigIntegerValue);
    };

    /**
     * set value by integer value
     * @name setByInteger
     * @memberOf KJUR.asn1.DERInteger
     * @function
     * @param {Integer} integer value to set
     */
    this.setByInteger = function(intValue) {
	var bi = new BigInteger(String(intValue), 10);
	this.setByBigInteger(bi);
    };

    /**
     * set value by integer value
     * @name setValueHex
     * @memberOf KJUR.asn1.DERInteger
     * @function
     * @param {String} hexadecimal string of integer value
     * @description
     * <br/>
     * NOTE: Value shall be represented by minimum octet length of
     * two's complement representation.
     */
    this.setValueHex = function(newHexString) {
	this.hV = newHexString;
    };

    this.getFreshValueHex = function() {
	return this.hV;
    };

    if (typeof params != "undefined") {
	if (typeof params['bigint'] != "undefined") {
	    this.setByBigInteger(params['bigint']);
	} else if (typeof params['int'] != "undefined") {
	    this.setByInteger(params['int']);
	} else if (typeof params['hex'] != "undefined") {
	    this.setValueHex(params['hex']);
	}
    }
};
JSX.extend(KJUR.asn1.DERInteger, KJUR.asn1.ASN1Object);

// ********************************************************************
/**
 * class for ASN.1 DER encoded BitString primitive
 * @name KJUR.asn1.DERBitString
 * @class class for ASN.1 DER encoded BitString primitive
 * @extends KJUR.asn1.ASN1Object
 * @description 
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>bin - specify binary string (ex. '10111')</li>
 * <li>array - specify array of boolean (ex. [true,false,true,true])</li>
 * <li>hex - specify hexadecimal string of ASN.1 value(V) including unused bits</li>
 * </ul>
 * NOTE: 'params' can be omitted.
 */
KJUR.asn1.DERBitString = function(params) {
    KJUR.asn1.DERBitString.superclass.constructor.call(this);
    this.hT = "03";

    /**
     * set ASN.1 value(V) by a hexadecimal string including unused bits
     * @name setHexValueIncludingUnusedBits
     * @memberOf KJUR.asn1.DERBitString
     * @function
     * @param {String} newHexStringIncludingUnusedBits
     */
    this.setHexValueIncludingUnusedBits = function(newHexStringIncludingUnusedBits) {
	this.hTLV = null;
	this.isModified = true;
	this.hV = newHexStringIncludingUnusedBits;
    };

    /**
     * set ASN.1 value(V) by unused bit and hexadecimal string of value
     * @name setUnusedBitsAndHexValue
     * @memberOf KJUR.asn1.DERBitString
     * @function
     * @param {Integer} unusedBits
     * @param {String} hValue
     */
    this.setUnusedBitsAndHexValue = function(unusedBits, hValue) {
	if (unusedBits < 0 || 7 < unusedBits) {
	    throw "unused bits shall be from 0 to 7: u = " + unusedBits;
	}
	var hUnusedBits = "0" + unusedBits;
	this.hTLV = null;
	this.isModified = true;
	this.hV = hUnusedBits + hValue;
    };

    /**
     * set ASN.1 DER BitString by binary string
     * @name setByBinaryString
     * @memberOf KJUR.asn1.DERBitString
     * @function
     * @param {String} binaryString binary value string (i.e. '10111')
     * @description
     * Its unused bits will be calculated automatically by length of 
     * 'binaryValue'. <br/>
     * NOTE: Trailing zeros '0' will be ignored.
     */
    this.setByBinaryString = function(binaryString) {
	binaryString = binaryString.replace(/0+$/, '');
	var unusedBits = 8 - binaryString.length % 8;
	if (unusedBits == 8) unusedBits = 0;
	for (var i = 0; i <= unusedBits; i++) {
	    binaryString += '0';
	}
	var h = '';
	for (var i = 0; i < binaryString.length - 1; i += 8) {
	    var b = binaryString.substr(i, 8);
	    var x = parseInt(b, 2).toString(16);
	    if (x.length == 1) x = '0' + x;
	    h += x;  
	}
	this.hTLV = null;
	this.isModified = true;
	this.hV = '0' + unusedBits + h;
    };

    /**
     * set ASN.1 TLV value(V) by an array of boolean
     * @name setByBooleanArray
     * @memberOf KJUR.asn1.DERBitString
     * @function
     * @param {array} booleanArray array of boolean (ex. [true, false, true])
     * @description
     * NOTE: Trailing falses will be ignored.
     */
    this.setByBooleanArray = function(booleanArray) {
	var s = '';
	for (var i = 0; i < booleanArray.length; i++) {
	    if (booleanArray[i] == true) {
		s += '1';
	    } else {
		s += '0';
	    }
	}
	this.setByBinaryString(s);
    };

    /**
     * generate an array of false with specified length
     * @name newFalseArray
     * @memberOf KJUR.asn1.DERBitString
     * @function
     * @param {Integer} nLength length of array to generate
     * @return {array} array of boolean faluse
     * @description
     * This static method may be useful to initialize boolean array.
     */
    this.newFalseArray = function(nLength) {
	var a = new Array(nLength);
	for (var i = 0; i < nLength; i++) {
	    a[i] = false;
	}
	return a;
    };

    this.getFreshValueHex = function() {
	return this.hV;
    };

    if (typeof params != "undefined") {
	if (typeof params['hex'] != "undefined") {
	    this.setHexValueIncludingUnusedBits(params['hex']);
	} else if (typeof params['bin'] != "undefined") {
	    this.setByBinaryString(params['bin']);
	} else if (typeof params['array'] != "undefined") {
	    this.setByBooleanArray(params['array']);
	}
    }
};
JSX.extend(KJUR.asn1.DERBitString, KJUR.asn1.ASN1Object);

// ********************************************************************
/**
 * class for ASN.1 DER OctetString
 * @name KJUR.asn1.DEROctetString
 * @class class for ASN.1 DER OctetString
 * @param {Array} params associative array of parameters (ex. {'str': 'aaa'})
 * @extends KJUR.asn1.DERAbstractString
 * @description
 * @see KJUR.asn1.DERAbstractString - superclass
 */
KJUR.asn1.DEROctetString = function(params) {
    KJUR.asn1.DEROctetString.superclass.constructor.call(this, params);
    this.hT = "04";
};
JSX.extend(KJUR.asn1.DEROctetString, KJUR.asn1.DERAbstractString);

// ********************************************************************
/**
 * class for ASN.1 DER Null
 * @name KJUR.asn1.DERNull
 * @class class for ASN.1 DER Null
 * @extends KJUR.asn1.ASN1Object
 * @description
 * @see KJUR.asn1.ASN1Object - superclass
 */
KJUR.asn1.DERNull = function() {
    KJUR.asn1.DERNull.superclass.constructor.call(this);
    this.hT = "05";
    this.hTLV = "0500";
};
JSX.extend(KJUR.asn1.DERNull, KJUR.asn1.ASN1Object);

// ********************************************************************
/**
 * class for ASN.1 DER ObjectIdentifier
 * @name KJUR.asn1.DERObjectIdentifier
 * @class class for ASN.1 DER ObjectIdentifier
 * @param {Array} params associative array of parameters (ex. {'oid': '2.5.4.5'})
 * @extends KJUR.asn1.ASN1Object
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>oid - specify initial ASN.1 value(V) by a oid string (ex. 2.5.4.13)</li>
 * <li>hex - specify initial ASN.1 value(V) by a hexadecimal string</li>
 * </ul>
 * NOTE: 'params' can be omitted.
 */
KJUR.asn1.DERObjectIdentifier = function(params) {
    var itox = function(i) {
	var h = i.toString(16);
	if (h.length == 1) h = '0' + h;
	return h;
    };
    var roidtox = function(roid) {
	var h = '';
	var bi = new BigInteger(roid, 10);
	var b = bi.toString(2);
	var padLen = 7 - b.length % 7;
	if (padLen == 7) padLen = 0;
	var bPad = '';
	for (var i = 0; i < padLen; i++) bPad += '0';
	b = bPad + b;
	for (var i = 0; i < b.length - 1; i += 7) {
	    var b8 = b.substr(i, 7);
	    if (i != b.length - 7) b8 = '1' + b8;
	    h += itox(parseInt(b8, 2));
	}
	return h;
    }

    KJUR.asn1.DERObjectIdentifier.superclass.constructor.call(this);
    this.hT = "06";

    /**
     * set value by a hexadecimal string
     * @name setValueHex
     * @memberOf KJUR.asn1.DERObjectIdentifier
     * @function
     * @param {String} newHexString hexadecimal value of OID bytes
     */
    this.setValueHex = function(newHexString) {
	this.hTLV = null;
	this.isModified = true;
	this.s = null;
	this.hV = newHexString;
    };

    /**
     * set value by a OID string
     * @name setValueOidString
     * @memberOf KJUR.asn1.DERObjectIdentifier
     * @function
     * @param {String} oidString OID string (ex. 2.5.4.13)
     */
    this.setValueOidString = function(oidString) {
	if (! oidString.match(/^[0-9.]+$/)) {
	    throw "malformed oid string: " + oidString;
	}
	var h = '';
	var a = oidString.split('.');
	var i0 = parseInt(a[0]) * 40 + parseInt(a[1]);
	h += itox(i0);
	a.splice(0, 2);
	for (var i = 0; i < a.length; i++) {
	    h += roidtox(a[i]);
	}
	this.hTLV = null;
	this.isModified = true;
	this.s = null;
	this.hV = h;
    };

    /**
     * set value by a OID name
     * @name setValueName
     * @memberOf KJUR.asn1.DERObjectIdentifier
     * @function
     * @param {String} oidName OID name (ex. 'serverAuth')
     * @since 1.0.1
     * @description
     * OID name shall be defined in 'KJUR.asn1.x509.OID.name2oidList'.
     * Otherwise raise error.
     */
    this.setValueName = function(oidName) {
	if (typeof KJUR.asn1.x509.OID.name2oidList[oidName] != "undefined") {
	    var oid = KJUR.asn1.x509.OID.name2oidList[oidName];
	    this.setValueOidString(oid);
	} else {
	    throw "DERObjectIdentifier oidName undefined: " + oidName;
	}
    };

    this.getFreshValueHex = function() {
	return this.hV;
    };

    if (typeof params != "undefined") {
	if (typeof params['oid'] != "undefined") {
	    this.setValueOidString(params['oid']);
	} else if (typeof params['hex'] != "undefined") {
	    this.setValueHex(params['hex']);
	} else if (typeof params['name'] != "undefined") {
	    this.setValueName(params['name']);
	}
    }
};
JSX.extend(KJUR.asn1.DERObjectIdentifier, KJUR.asn1.ASN1Object);

// ********************************************************************
/**
 * class for ASN.1 DER UTF8String
 * @name KJUR.asn1.DERUTF8String
 * @class class for ASN.1 DER UTF8String
 * @param {Array} params associative array of parameters (ex. {'str': 'aaa'})
 * @extends KJUR.asn1.DERAbstractString
 * @description
 * @see KJUR.asn1.DERAbstractString - superclass
 */
KJUR.asn1.DERUTF8String = function(params) {
    KJUR.asn1.DERUTF8String.superclass.constructor.call(this, params);
    this.hT = "0c";
};
JSX.extend(KJUR.asn1.DERUTF8String, KJUR.asn1.DERAbstractString);

// ********************************************************************
/**
 * class for ASN.1 DER NumericString
 * @name KJUR.asn1.DERNumericString
 * @class class for ASN.1 DER NumericString
 * @param {Array} params associative array of parameters (ex. {'str': 'aaa'})
 * @extends KJUR.asn1.DERAbstractString
 * @description
 * @see KJUR.asn1.DERAbstractString - superclass
 */
KJUR.asn1.DERNumericString = function(params) {
    KJUR.asn1.DERNumericString.superclass.constructor.call(this, params);
    this.hT = "12";
};
JSX.extend(KJUR.asn1.DERNumericString, KJUR.asn1.DERAbstractString);

// ********************************************************************
/**
 * class for ASN.1 DER PrintableString
 * @name KJUR.asn1.DERPrintableString
 * @class class for ASN.1 DER PrintableString
 * @param {Array} params associative array of parameters (ex. {'str': 'aaa'})
 * @extends KJUR.asn1.DERAbstractString
 * @description
 * @see KJUR.asn1.DERAbstractString - superclass
 */
KJUR.asn1.DERPrintableString = function(params) {
    KJUR.asn1.DERPrintableString.superclass.constructor.call(this, params);
    this.hT = "13";
};
JSX.extend(KJUR.asn1.DERPrintableString, KJUR.asn1.DERAbstractString);

// ********************************************************************
/**
 * class for ASN.1 DER TeletexString
 * @name KJUR.asn1.DERTeletexString
 * @class class for ASN.1 DER TeletexString
 * @param {Array} params associative array of parameters (ex. {'str': 'aaa'})
 * @extends KJUR.asn1.DERAbstractString
 * @description
 * @see KJUR.asn1.DERAbstractString - superclass
 */
KJUR.asn1.DERTeletexString = function(params) {
    KJUR.asn1.DERTeletexString.superclass.constructor.call(this, params);
    this.hT = "14";
};
JSX.extend(KJUR.asn1.DERTeletexString, KJUR.asn1.DERAbstractString);

// ********************************************************************
/**
 * class for ASN.1 DER IA5String
 * @name KJUR.asn1.DERIA5String
 * @class class for ASN.1 DER IA5String
 * @param {Array} params associative array of parameters (ex. {'str': 'aaa'})
 * @extends KJUR.asn1.DERAbstractString
 * @description
 * @see KJUR.asn1.DERAbstractString - superclass
 */
KJUR.asn1.DERIA5String = function(params) {
    KJUR.asn1.DERIA5String.superclass.constructor.call(this, params);
    this.hT = "16";
};
JSX.extend(KJUR.asn1.DERIA5String, KJUR.asn1.DERAbstractString);

// ********************************************************************
/**
 * class for ASN.1 DER UTCTime
 * @name KJUR.asn1.DERUTCTime
 * @class class for ASN.1 DER UTCTime
 * @param {Array} params associative array of parameters (ex. {'str': '130430235959Z'})
 * @extends KJUR.asn1.DERAbstractTime
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>str - specify initial ASN.1 value(V) by a string (ex.'130430235959Z')</li>
 * <li>hex - specify initial ASN.1 value(V) by a hexadecimal string</li>
 * <li>date - specify Date object.</li>
 * </ul>
 * NOTE: 'params' can be omitted.
 * <h4>EXAMPLES</h4>
 * @example
 * var d1 = new KJUR.asn1.DERUTCTime();
 * d1.setString('130430125959Z');
 *
 * var d2 = new KJUR.asn1.DERUTCTime({'str': '130430125959Z'});
 *
 * var d3 = new KJUR.asn1.DERUTCTime({'date': new Date(Date.UTC(2015, 0, 31, 0, 0, 0, 0))});
 */
KJUR.asn1.DERUTCTime = function(params) {
    KJUR.asn1.DERUTCTime.superclass.constructor.call(this, params);
    this.hT = "17";

    /**
     * set value by a Date object
     * @name setByDate
     * @memberOf KJUR.asn1.DERUTCTime
     * @function
     * @param {Date} dateObject Date object to set ASN.1 value(V)
     */
    this.setByDate = function(dateObject) {
	this.hTLV = null;
	this.isModified = true;
	this.date = dateObject;
	this.s = this.formatDate(this.date, 'utc');
	this.hV = stohex(this.s);
    };

    if (typeof params != "undefined") {
	if (typeof params['str'] != "undefined") {
	    this.setString(params['str']);
	} else if (typeof params['hex'] != "undefined") {
	    this.setStringHex(params['hex']);
	} else if (typeof params['date'] != "undefined") {
	    this.setByDate(params['date']);
	}
    }
};
JSX.extend(KJUR.asn1.DERUTCTime, KJUR.asn1.DERAbstractTime);

// ********************************************************************
/**
 * class for ASN.1 DER GeneralizedTime
 * @name KJUR.asn1.DERGeneralizedTime
 * @class class for ASN.1 DER GeneralizedTime
 * @param {Array} params associative array of parameters (ex. {'str': '20130430235959Z'})
 * @extends KJUR.asn1.DERAbstractTime
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>str - specify initial ASN.1 value(V) by a string (ex.'20130430235959Z')</li>
 * <li>hex - specify initial ASN.1 value(V) by a hexadecimal string</li>
 * <li>date - specify Date object.</li>
 * </ul>
 * NOTE: 'params' can be omitted.
 */
KJUR.asn1.DERGeneralizedTime = function(params) {
    KJUR.asn1.DERGeneralizedTime.superclass.constructor.call(this, params);
    this.hT = "18";

    /**
     * set value by a Date object
     * @name setByDate
     * @memberOf KJUR.asn1.DERGeneralizedTime
     * @function
     * @param {Date} dateObject Date object to set ASN.1 value(V)
     * @example
     * When you specify UTC time, use 'Date.UTC' method like this:<br/>
     * var o = new DERUTCTime();
     * var date = new Date(Date.UTC(2015, 0, 31, 23, 59, 59, 0)); #2015JAN31 23:59:59
     * o.setByDate(date);
     */
    this.setByDate = function(dateObject) {
	this.hTLV = null;
	this.isModified = true;
	this.date = dateObject;
	this.s = this.formatDate(this.date, 'gen');
	this.hV = stohex(this.s);
    };

    if (typeof params != "undefined") {
	if (typeof params['str'] != "undefined") {
	    this.setString(params['str']);
	} else if (typeof params['hex'] != "undefined") {
	    this.setStringHex(params['hex']);
	} else if (typeof params['date'] != "undefined") {
	    this.setByDate(params['date']);
	}
    }
};
JSX.extend(KJUR.asn1.DERGeneralizedTime, KJUR.asn1.DERAbstractTime);

// ********************************************************************
/**
 * class for ASN.1 DER Sequence
 * @name KJUR.asn1.DERSequence
 * @class class for ASN.1 DER Sequence
 * @extends KJUR.asn1.DERAbstractStructured
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>array - specify array of ASN1Object to set elements of content</li>
 * </ul>
 * NOTE: 'params' can be omitted.
 */
KJUR.asn1.DERSequence = function(params) {
    KJUR.asn1.DERSequence.superclass.constructor.call(this, params);
    this.hT = "30";
    this.getFreshValueHex = function() {
	var h = '';
	for (var i = 0; i < this.asn1Array.length; i++) {
	    var asn1Obj = this.asn1Array[i];
	    h += asn1Obj.getEncodedHex();
	}
	this.hV = h;
	return this.hV;
    };
};
JSX.extend(KJUR.asn1.DERSequence, KJUR.asn1.DERAbstractStructured);

// ********************************************************************
/**
 * class for ASN.1 DER Set
 * @name KJUR.asn1.DERSet
 * @class class for ASN.1 DER Set
 * @extends KJUR.asn1.DERAbstractStructured
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>array - specify array of ASN1Object to set elements of content</li>
 * </ul>
 * NOTE: 'params' can be omitted.
 */
KJUR.asn1.DERSet = function(params) {
    KJUR.asn1.DERSet.superclass.constructor.call(this, params);
    this.hT = "31";
    this.getFreshValueHex = function() {
	var a = new Array();
	for (var i = 0; i < this.asn1Array.length; i++) {
	    var asn1Obj = this.asn1Array[i];
	    a.push(asn1Obj.getEncodedHex());
	}
	a.sort();
	this.hV = a.join('');
	return this.hV;
    };
};
JSX.extend(KJUR.asn1.DERSet, KJUR.asn1.DERAbstractStructured);

// ********************************************************************
/**
 * class for ASN.1 DER TaggedObject
 * @name KJUR.asn1.DERTaggedObject
 * @class class for ASN.1 DER TaggedObject
 * @extends KJUR.asn1.ASN1Object
 * @description
 * <br/>
 * Parameter 'tagNoNex' is ASN.1 tag(T) value for this object.
 * For example, if you find '[1]' tag in a ASN.1 dump, 
 * 'tagNoHex' will be 'a1'.
 * <br/>
 * As for optional argument 'params' for constructor, you can specify *ANY* of
 * following properties:
 * <ul>
 * <li>explicit - specify true if this is explicit tag otherwise false 
 *     (default is 'true').</li>
 * <li>tag - specify tag (default is 'a0' which means [0])</li>
 * <li>obj - specify ASN1Object which is tagged</li>
 * </ul>
 * @example
 * d1 = new KJUR.asn1.DERUTF8String({'str':'a'});
 * d2 = new KJUR.asn1.DERTaggedObject({'obj': d1});
 * hex = d2.getEncodedHex();
 */
KJUR.asn1.DERTaggedObject = function(params) {
    KJUR.asn1.DERTaggedObject.superclass.constructor.call(this);
    this.hT = "a0";
    this.hV = '';
    this.isExplicit = true;
    this.asn1Object = null;

    /**
     * set value by an ASN1Object
     * @name setString
     * @memberOf KJUR.asn1.DERTaggedObject
     * @function
     * @param {Boolean} isExplicitFlag flag for explicit/implicit tag
     * @param {Integer} tagNoHex hexadecimal string of ASN.1 tag
     * @param {ASN1Object} asn1Object ASN.1 to encapsulate
     */
    this.setASN1Object = function(isExplicitFlag, tagNoHex, asn1Object) {
	this.hT = tagNoHex;
	this.isExplicit = isExplicitFlag;
	this.asn1Object = asn1Object;
	if (this.isExplicit) {
	    this.hV = this.asn1Object.getEncodedHex();
	    this.hTLV = null;
	    this.isModified = true;
	} else {
	    this.hV = null;
	    this.hTLV = asn1Object.getEncodedHex();
	    this.hTLV = this.hTLV.replace(/^../, tagNoHex);
	    this.isModified = false;
	}
    };

    this.getFreshValueHex = function() {
	return this.hV;
    };

    if (typeof params != "undefined") {
	if (typeof params['tag'] != "undefined") {
	    this.hT = params['tag'];
	}
	if (typeof params['explicit'] != "undefined") {
	    this.isExplicit = params['explicit'];
	}
	if (typeof params['obj'] != "undefined") {
	    this.asn1Object = params['obj'];
	    this.setASN1Object(this.isExplicit, this.hT, this.asn1Object);
	}
    }
};
JSX.extend(KJUR.asn1.DERTaggedObject, KJUR.asn1.ASN1Object);
// Hex JavaScript decoder
// Copyright (c) 2008-2013 Lapo Luchini <lapo@lapo.it>

// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
// 
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

/*jshint browser: true, strict: true, immed: true, latedef: true, undef: true, regexdash: false */
(function (undefined) {
"use strict";

var Hex = {},
    decoder;

Hex.decode = function(a) {
    var i;
    if (decoder === undefined) {
        var hex = "0123456789ABCDEF",
            ignore = " \f\n\r\t\u00A0\u2028\u2029";
        decoder = [];
        for (i = 0; i < 16; ++i)
            decoder[hex.charAt(i)] = i;
        hex = hex.toLowerCase();
        for (i = 10; i < 16; ++i)
            decoder[hex.charAt(i)] = i;
        for (i = 0; i < ignore.length; ++i)
            decoder[ignore.charAt(i)] = -1;
    }
    var out = [],
        bits = 0,
        char_count = 0;
    for (i = 0; i < a.length; ++i) {
        var c = a.charAt(i);
        if (c == '=')
            break;
        c = decoder[c];
        if (c == -1)
            continue;
        if (c === undefined)
            throw 'Illegal character at offset ' + i;
        bits |= c;
        if (++char_count >= 2) {
            out[out.length] = bits;
            bits = 0;
            char_count = 0;
        } else {
            bits <<= 4;
        }
    }
    if (char_count)
        throw "Hex encoding incomplete: 4 bits missing";
    return out;
};

// export globals
window.Hex = Hex;
})();
// Base64 JavaScript decoder
// Copyright (c) 2008-2013 Lapo Luchini <lapo@lapo.it>

// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
// 
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

/*jshint browser: true, strict: true, immed: true, latedef: true, undef: true, regexdash: false */
(function (undefined) {
"use strict";

var Base64 = {},
    decoder;

Base64.decode = function (a) {
    var i;
    if (decoder === undefined) {
        var b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            ignore = "= \f\n\r\t\u00A0\u2028\u2029";
        decoder = [];
        for (i = 0; i < 64; ++i)
            decoder[b64.charAt(i)] = i;
        for (i = 0; i < ignore.length; ++i)
            decoder[ignore.charAt(i)] = -1;
    }
    var out = [];
    var bits = 0, char_count = 0;
    for (i = 0; i < a.length; ++i) {
        var c = a.charAt(i);
        if (c == '=')
            break;
        c = decoder[c];
        if (c == -1)
            continue;
        if (c === undefined)
            throw 'Illegal character at offset ' + i;
        bits |= c;
        if (++char_count >= 4) {
            out[out.length] = (bits >> 16);
            out[out.length] = (bits >> 8) & 0xFF;
            out[out.length] = bits & 0xFF;
            bits = 0;
            char_count = 0;
        } else {
            bits <<= 6;
        }
    }
    switch (char_count) {
      case 1:
        throw "Base64 encoding incomplete: at least 2 bits missing";
      case 2:
        out[out.length] = (bits >> 10);
        break;
      case 3:
        out[out.length] = (bits >> 16);
        out[out.length] = (bits >> 8) & 0xFF;
        break;
    }
    return out;
};

Base64.re = /-----BEGIN [^-]+-----([A-Za-z0-9+\/=\s]+)-----END [^-]+-----|begin-base64[^\n]+\n([A-Za-z0-9+\/=\s]+)====/;
Base64.unarmor = function (a) {
    var m = Base64.re.exec(a);
    if (m) {
        if (m[1])
            a = m[1];
        else if (m[2])
            a = m[2];
        else
            throw "RegExp out of sync";
    }
    return Base64.decode(a);
};

// export globals
window.Base64 = Base64;
})();
// ASN.1 JavaScript decoder
// Copyright (c) 2008-2013 Lapo Luchini <lapo@lapo.it>

// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
// 
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

/*jshint browser: true, strict: true, immed: true, latedef: true, undef: true, regexdash: false */
/*global oids */
(function (undefined) {
"use strict";

var hardLimit = 100,
    ellipsis = "\u2026",
    DOM = {
        tag: function (tagName, className) {
            var t = document.createElement(tagName);
            t.className = className;
            return t;
        },
        text: function (str) {
            return document.createTextNode(str);
        }
    };

function Stream(enc, pos) {
    if (enc instanceof Stream) {
        this.enc = enc.enc;
        this.pos = enc.pos;
    } else {
        this.enc = enc;
        this.pos = pos;
    }
}
Stream.prototype.get = function (pos) {
    if (pos === undefined)
        pos = this.pos++;
    if (pos >= this.enc.length)
        throw 'Requesting byte offset ' + pos + ' on a stream of length ' + this.enc.length;
    return this.enc[pos];
};
Stream.prototype.hexDigits = "0123456789ABCDEF";
Stream.prototype.hexByte = function (b) {
    return this.hexDigits.charAt((b >> 4) & 0xF) + this.hexDigits.charAt(b & 0xF);
};
Stream.prototype.hexDump = function (start, end, raw) {
    var s = "";
    for (var i = start; i < end; ++i) {
        s += this.hexByte(this.get(i));
        if (raw !== true)
            switch (i & 0xF) {
            case 0x7: s += "  "; break;
            case 0xF: s += "\n"; break;
            default:  s += " ";
            }
    }
    return s;
};
Stream.prototype.parseStringISO = function (start, end) {
    var s = "";
    for (var i = start; i < end; ++i)
        s += String.fromCharCode(this.get(i));
    return s;
};
Stream.prototype.parseStringUTF = function (start, end) {
    var s = "";
    for (var i = start; i < end; ) {
        var c = this.get(i++);
        if (c < 128)
            s += String.fromCharCode(c);
        else if ((c > 191) && (c < 224))
            s += String.fromCharCode(((c & 0x1F) << 6) | (this.get(i++) & 0x3F));
        else
            s += String.fromCharCode(((c & 0x0F) << 12) | ((this.get(i++) & 0x3F) << 6) | (this.get(i++) & 0x3F));
    }
    return s;
};
Stream.prototype.parseStringBMP = function (start, end) {
    var str = ""
    for (var i = start; i < end; i += 2) {
        var high_byte = this.get(i);
        var low_byte = this.get(i + 1);
        str += String.fromCharCode( (high_byte << 8) + low_byte );
    }

    return str;
};
Stream.prototype.reTime = /^((?:1[89]|2\d)?\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([01]\d|2[0-3])(?:([0-5]\d)(?:([0-5]\d)(?:[.,](\d{1,3}))?)?)?(Z|[-+](?:[0]\d|1[0-2])([0-5]\d)?)?$/;
Stream.prototype.parseTime = function (start, end) {
    var s = this.parseStringISO(start, end),
        m = this.reTime.exec(s);
    if (!m)
        return "Unrecognized time: " + s;
    s = m[1] + "-" + m[2] + "-" + m[3] + " " + m[4];
    if (m[5]) {
        s += ":" + m[5];
        if (m[6]) {
            s += ":" + m[6];
            if (m[7])
                s += "." + m[7];
        }
    }
    if (m[8]) {
        s += " UTC";
        if (m[8] != 'Z') {
            s += m[8];
            if (m[9])
                s += ":" + m[9];
        }
    }
    return s;
};
Stream.prototype.parseInteger = function (start, end) {
    //TODO support negative numbers
    var len = end - start;
    if (len > 4) {
        len <<= 3;
        var s = this.get(start);
        if (s === 0)
            len -= 8;
        else
            while (s < 128) {
                s <<= 1;
                --len;
            }
        return "(" + len + " bit)";
    }
    var n = 0;
    for (var i = start; i < end; ++i)
        n = (n << 8) | this.get(i);
    return n;
};
Stream.prototype.parseBitString = function (start, end) {
    var unusedBit = this.get(start),
        lenBit = ((end - start - 1) << 3) - unusedBit,
        s = "(" + lenBit + " bit)";
    if (lenBit <= 20) {
        var skip = unusedBit;
        s += " ";
        for (var i = end - 1; i > start; --i) {
            var b = this.get(i);
            for (var j = skip; j < 8; ++j)
                s += (b >> j) & 1 ? "1" : "0";
            skip = 0;
        }
    }
    return s;
};
Stream.prototype.parseOctetString = function (start, end) {
    var len = end - start,
        s = "(" + len + " byte) ";
    if (len > hardLimit)
        end = start + hardLimit;
    for (var i = start; i < end; ++i)
        s += this.hexByte(this.get(i)); //TODO: also try Latin1?
    if (len > hardLimit)
        s += ellipsis;
    return s;
};
Stream.prototype.parseOID = function (start, end) {
    var s = '',
        n = 0,
        bits = 0;
    for (var i = start; i < end; ++i) {
        var v = this.get(i);
        n = (n << 7) | (v & 0x7F);
        bits += 7;
        if (!(v & 0x80)) { // finished
            if (s === '') {
                var m = n < 80 ? n < 40 ? 0 : 1 : 2;
                s = m + "." + (n - m * 40);
            } else
                s += "." + ((bits >= 31) ? "bigint" : n);
            n = bits = 0;
        }
    }
    return s;
};

function ASN1(stream, header, length, tag, sub) {
    this.stream = stream;
    this.header = header;
    this.length = length;
    this.tag = tag;
    this.sub = sub;
}
ASN1.prototype.typeName = function () {
    if (this.tag === undefined)
        return "unknown";
    var tagClass = this.tag >> 6,
        tagConstructed = (this.tag >> 5) & 1,
        tagNumber = this.tag & 0x1F;
    switch (tagClass) {
    case 0: // universal
        switch (tagNumber) {
        case 0x00: return "EOC";
        case 0x01: return "BOOLEAN";
        case 0x02: return "INTEGER";
        case 0x03: return "BIT_STRING";
        case 0x04: return "OCTET_STRING";
        case 0x05: return "NULL";
        case 0x06: return "OBJECT_IDENTIFIER";
        case 0x07: return "ObjectDescriptor";
        case 0x08: return "EXTERNAL";
        case 0x09: return "REAL";
        case 0x0A: return "ENUMERATED";
        case 0x0B: return "EMBEDDED_PDV";
        case 0x0C: return "UTF8String";
        case 0x10: return "SEQUENCE";
        case 0x11: return "SET";
        case 0x12: return "NumericString";
        case 0x13: return "PrintableString"; // ASCII subset
        case 0x14: return "TeletexString"; // aka T61String
        case 0x15: return "VideotexString";
        case 0x16: return "IA5String"; // ASCII
        case 0x17: return "UTCTime";
        case 0x18: return "GeneralizedTime";
        case 0x19: return "GraphicString";
        case 0x1A: return "VisibleString"; // ASCII subset
        case 0x1B: return "GeneralString";
        case 0x1C: return "UniversalString";
        case 0x1E: return "BMPString";
        default:   return "Universal_" + tagNumber.toString(16);
        }
    case 1: return "Application_" + tagNumber.toString(16);
    case 2: return "[" + tagNumber + "]"; // Context
    case 3: return "Private_" + tagNumber.toString(16);
    }
};
ASN1.prototype.reSeemsASCII = /^[ -~]+$/;
ASN1.prototype.content = function () {
    if (this.tag === undefined)
        return null;
    var tagClass = this.tag >> 6,
        tagNumber = this.tag & 0x1F,
        content = this.posContent(),
        len = Math.abs(this.length);
    if (tagClass !== 0) { // universal
        if (this.sub !== null)
            return "(" + this.sub.length + " elem)";
        //TODO: TRY TO PARSE ASCII STRING
        var s = this.stream.parseStringISO(content, content + Math.min(len, hardLimit));
        if (this.reSeemsASCII.test(s))
            return s.substring(0, 2 * hardLimit) + ((s.length > 2 * hardLimit) ? ellipsis : "");
        else
            return this.stream.parseOctetString(content, content + len);
    }
    switch (tagNumber) {
    case 0x01: // BOOLEAN
        return (this.stream.get(content) === 0) ? "false" : "true";
    case 0x02: // INTEGER
        return this.stream.parseInteger(content, content + len);
    case 0x03: // BIT_STRING
        return this.sub ? "(" + this.sub.length + " elem)" :
            this.stream.parseBitString(content, content + len);
    case 0x04: // OCTET_STRING
        return this.sub ? "(" + this.sub.length + " elem)" :
            this.stream.parseOctetString(content, content + len);
    //case 0x05: // NULL
    case 0x06: // OBJECT_IDENTIFIER
        return this.stream.parseOID(content, content + len);
    //case 0x07: // ObjectDescriptor
    //case 0x08: // EXTERNAL
    //case 0x09: // REAL
    //case 0x0A: // ENUMERATED
    //case 0x0B: // EMBEDDED_PDV
    case 0x10: // SEQUENCE
    case 0x11: // SET
        return "(" + this.sub.length + " elem)";
    case 0x0C: // UTF8String
        return this.stream.parseStringUTF(content, content + len);
    case 0x12: // NumericString
    case 0x13: // PrintableString
    case 0x14: // TeletexString
    case 0x15: // VideotexString
    case 0x16: // IA5String
    //case 0x19: // GraphicString
    case 0x1A: // VisibleString
    //case 0x1B: // GeneralString
    //case 0x1C: // UniversalString
        return this.stream.parseStringISO(content, content + len);
    case 0x1E: // BMPString
        return this.stream.parseStringBMP(content, content + len);
    case 0x17: // UTCTime
    case 0x18: // GeneralizedTime
        return this.stream.parseTime(content, content + len);
    }
    return null;
};
ASN1.prototype.toString = function () {
    return this.typeName() + "@" + this.stream.pos + "[header:" + this.header + ",length:" + this.length + ",sub:" + ((this.sub === null) ? 'null' : this.sub.length) + "]";
};
ASN1.prototype.print = function (indent) {
    if (indent === undefined) indent = '';
    document.writeln(indent + this);
    if (this.sub !== null) {
        indent += '  ';
        for (var i = 0, max = this.sub.length; i < max; ++i)
            this.sub[i].print(indent);
    }
};
ASN1.prototype.toPrettyString = function (indent) {
    if (indent === undefined) indent = '';
    var s = indent + this.typeName() + " @" + this.stream.pos;
    if (this.length >= 0)
        s += "+";
    s += this.length;
    if (this.tag & 0x20)
        s += " (constructed)";
    else if (((this.tag == 0x03) || (this.tag == 0x04)) && (this.sub !== null))
        s += " (encapsulates)";
    s += "\n";
    if (this.sub !== null) {
        indent += '  ';
        for (var i = 0, max = this.sub.length; i < max; ++i)
            s += this.sub[i].toPrettyString(indent);
    }
    return s;
};
ASN1.prototype.toDOM = function () {
    var node = DOM.tag("div", "node");
    node.asn1 = this;
    var head = DOM.tag("div", "head");
    var s = this.typeName().replace(/_/g, " ");
    head.innerHTML = s;
    var content = this.content();
    if (content !== null) {
        content = String(content).replace(/</g, "&lt;");
        var preview = DOM.tag("span", "preview");
        preview.appendChild(DOM.text(content));
        head.appendChild(preview);
    }
    node.appendChild(head);
    this.node = node;
    this.head = head;
    var value = DOM.tag("div", "value");
    s = "Offset: " + this.stream.pos + "<br/>";
    s += "Length: " + this.header + "+";
    if (this.length >= 0)
        s += this.length;
    else
        s += (-this.length) + " (undefined)";
    if (this.tag & 0x20)
        s += "<br/>(constructed)";
    else if (((this.tag == 0x03) || (this.tag == 0x04)) && (this.sub !== null))
        s += "<br/>(encapsulates)";
    //TODO if (this.tag == 0x03) s += "Unused bits: "
    if (content !== null) {
        s += "<br/>Value:<br/><b>" + content + "</b>";
        if ((typeof oids === 'object') && (this.tag == 0x06)) {
            var oid = oids[content];
            if (oid) {
                if (oid.d) s += "<br/>" + oid.d;
                if (oid.c) s += "<br/>" + oid.c;
                if (oid.w) s += "<br/>(warning!)";
            }
        }
    }
    value.innerHTML = s;
    node.appendChild(value);
    var sub = DOM.tag("div", "sub");
    if (this.sub !== null) {
        for (var i = 0, max = this.sub.length; i < max; ++i)
            sub.appendChild(this.sub[i].toDOM());
    }
    node.appendChild(sub);
    head.onclick = function () {
        node.className = (node.className == "node collapsed") ? "node" : "node collapsed";
    };
    return node;
};
ASN1.prototype.posStart = function () {
    return this.stream.pos;
};
ASN1.prototype.posContent = function () {
    return this.stream.pos + this.header;
};
ASN1.prototype.posEnd = function () {
    return this.stream.pos + this.header + Math.abs(this.length);
};
ASN1.prototype.fakeHover = function (current) {
    this.node.className += " hover";
    if (current)
        this.head.className += " hover";
};
ASN1.prototype.fakeOut = function (current) {
    var re = / ?hover/;
    this.node.className = this.node.className.replace(re, "");
    if (current)
        this.head.className = this.head.className.replace(re, "");
};
ASN1.prototype.toHexDOM_sub = function (node, className, stream, start, end) {
    if (start >= end)
        return;
    var sub = DOM.tag("span", className);
    sub.appendChild(DOM.text(
        stream.hexDump(start, end)));
    node.appendChild(sub);
};
ASN1.prototype.toHexDOM = function (root) {
    var node = DOM.tag("span", "hex");
    if (root === undefined) root = node;
    this.head.hexNode = node;
    this.head.onmouseover = function () { this.hexNode.className = "hexCurrent"; };
    this.head.onmouseout  = function () { this.hexNode.className = "hex"; };
    node.asn1 = this;
    node.onmouseover = function () {
        var current = !root.selected;
        if (current) {
            root.selected = this.asn1;
            this.className = "hexCurrent";
        }
        this.asn1.fakeHover(current);
    };
    node.onmouseout  = function () {
        var current = (root.selected == this.asn1);
        this.asn1.fakeOut(current);
        if (current) {
            root.selected = null;
            this.className = "hex";
        }
    };
    this.toHexDOM_sub(node, "tag", this.stream, this.posStart(), this.posStart() + 1);
    this.toHexDOM_sub(node, (this.length >= 0) ? "dlen" : "ulen", this.stream, this.posStart() + 1, this.posContent());
    if (this.sub === null)
        node.appendChild(DOM.text(
            this.stream.hexDump(this.posContent(), this.posEnd())));
    else if (this.sub.length > 0) {
        var first = this.sub[0];
        var last = this.sub[this.sub.length - 1];
        this.toHexDOM_sub(node, "intro", this.stream, this.posContent(), first.posStart());
        for (var i = 0, max = this.sub.length; i < max; ++i)
            node.appendChild(this.sub[i].toHexDOM(root));
        this.toHexDOM_sub(node, "outro", this.stream, last.posEnd(), this.posEnd());
    }
    return node;
};
ASN1.prototype.toHexString = function (root) {
    return this.stream.hexDump(this.posStart(), this.posEnd(), true);
};
ASN1.decodeLength = function (stream) {
    var buf = stream.get(),
        len = buf & 0x7F;
    if (len == buf)
        return len;
    if (len > 3)
        throw "Length over 24 bits not supported at position " + (stream.pos - 1);
    if (len === 0)
        return -1; // undefined
    buf = 0;
    for (var i = 0; i < len; ++i)
        buf = (buf << 8) | stream.get();
    return buf;
};
ASN1.hasContent = function (tag, len, stream) {
    if (tag & 0x20) // constructed
        return true;
    if ((tag < 0x03) || (tag > 0x04))
        return false;
    var p = new Stream(stream);
    if (tag == 0x03) p.get(); // BitString unused bits, must be in [0, 7]
    var subTag = p.get();
    if ((subTag >> 6) & 0x01) // not (universal or context)
        return false;
    try {
        var subLength = ASN1.decodeLength(p);
        return ((p.pos - stream.pos) + subLength == len);
    } catch (exception) {
        return false;
    }
};
ASN1.decode = function (stream) {
    if (!(stream instanceof Stream))
        stream = new Stream(stream, 0);
    var streamStart = new Stream(stream),
        tag = stream.get(),
        len = ASN1.decodeLength(stream),
        header = stream.pos - streamStart.pos,
        sub = null;
    if (ASN1.hasContent(tag, len, stream)) {
        // it has content, so we decode it
        var start = stream.pos;
        if (tag == 0x03) stream.get(); // skip BitString unused bits, must be in [0, 7]
        sub = [];
        if (len >= 0) {
            // definite length
            var end = start + len;
            while (stream.pos < end)
                sub[sub.length] = ASN1.decode(stream);
            if (stream.pos != end)
                throw "Content size is not correct for container starting at offset " + start;
        } else {
            // undefined length
            try {
                for (;;) {
                    var s = ASN1.decode(stream);
                    if (s.tag === 0)
                        break;
                    sub[sub.length] = s;
                }
                len = start - stream.pos;
            } catch (e) {
                throw "Exception while decoding undefined length content: " + e;
            }
        }
    } else
        stream.pos += len; // skip content
    return new ASN1(streamStart, header, len, tag, sub);
};
ASN1.test = function () {
    var test = [
        { value: [0x27],                   expected: 0x27     },
        { value: [0x81, 0xC9],             expected: 0xC9     },
        { value: [0x83, 0xFE, 0xDC, 0xBA], expected: 0xFEDCBA }
    ];
    for (var i = 0, max = test.length; i < max; ++i) {
        var pos = 0,
            stream = new Stream(test[i].value, 0),
            res = ASN1.decodeLength(stream);
        if (res != test[i].expected)
            document.write("In test[" + i + "] expected " + test[i].expected + " got " + res + "\n");
    }
};

// export globals
window.ASN1 = ASN1;
})();
/**
 * Retrieve the hexadecimal value (as a string) of the current ASN.1 element
 * @returns {string}
 * @public
 */
ASN1.prototype.getHexStringValue = function () {
  var hexString = this.toHexString();
  var offset = this.header * 2;
  var length = this.length * 2;
  return hexString.substr(offset, length);
};

/**
 * Method to parse a pem encoded string containing both a public or private key.
 * The method will translate the pem encoded string in a der encoded string and
 * will parse private key and public key parameters. This method accepts public key
 * in the rsaencryption pkcs #1 format (oid: 1.2.840.113549.1.1.1).
 *
 * @todo Check how many rsa formats use the same format of pkcs #1.
 *
 * The format is defined as:
 * PublicKeyInfo ::= SEQUENCE {
 *   algorithm       AlgorithmIdentifier,
 *   PublicKey       BIT STRING
 * }
 * Where AlgorithmIdentifier is:
 * AlgorithmIdentifier ::= SEQUENCE {
 *   algorithm       OBJECT IDENTIFIER,     the OID of the enc algorithm
 *   parameters      ANY DEFINED BY algorithm OPTIONAL (NULL for PKCS #1)
 * }
 * and PublicKey is a SEQUENCE encapsulated in a BIT STRING
 * RSAPublicKey ::= SEQUENCE {
 *   modulus           INTEGER,  -- n
 *   publicExponent    INTEGER   -- e
 * }
 * it's possible to examine the structure of the keys obtained from openssl using
 * an asn.1 dumper as the one used here to parse the components: http://lapo.it/asn1js/
 * @argument {string} pem the pem encoded string, can include the BEGIN/END header/footer
 * @private
 */
RSAKey.prototype.parseKey = function (pem) {
  try {
    var modulus = 0;
    var public_exponent = 0;
    var reHex = /^\s*(?:[0-9A-Fa-f][0-9A-Fa-f]\s*)+$/;
    var der = reHex.test(pem) ? Hex.decode(pem) : Base64.unarmor(pem);
    var asn1 = ASN1.decode(der);

    //Fixes a bug with OpenSSL 1.0+ private keys
    if(asn1.sub.length === 3){
        asn1 = asn1.sub[2].sub[0];
    }
    if (asn1.sub.length === 9) {

      // Parse the private key.
      modulus = asn1.sub[1].getHexStringValue(); //bigint
      this.n = parseBigInt(modulus, 16);

      public_exponent = asn1.sub[2].getHexStringValue(); //int
      this.e = parseInt(public_exponent, 16);

      var private_exponent = asn1.sub[3].getHexStringValue(); //bigint
      this.d = parseBigInt(private_exponent, 16);

      var prime1 = asn1.sub[4].getHexStringValue(); //bigint
      this.p = parseBigInt(prime1, 16);

      var prime2 = asn1.sub[5].getHexStringValue(); //bigint
      this.q = parseBigInt(prime2, 16);

      var exponent1 = asn1.sub[6].getHexStringValue(); //bigint
      this.dmp1 = parseBigInt(exponent1, 16);

      var exponent2 = asn1.sub[7].getHexStringValue(); //bigint
      this.dmq1 = parseBigInt(exponent2, 16);

      var coefficient = asn1.sub[8].getHexStringValue(); //bigint
      this.coeff = parseBigInt(coefficient, 16);

    }
    else if (asn1.sub.length === 2) {

      // Parse the public key.
      var bit_string = asn1.sub[1];
      var sequence = bit_string.sub[0];

      modulus = sequence.sub[0].getHexStringValue();
      this.n = parseBigInt(modulus, 16);
      public_exponent = sequence.sub[1].getHexStringValue();
      this.e = parseInt(public_exponent, 16);

    }
    else {
      return false;
    }
    return true;
  }
  catch (ex) {
    return false;
  }
};

/**
 * Translate rsa parameters in a hex encoded string representing the rsa key.
 *
 * The translation follow the ASN.1 notation :
 * RSAPrivateKey ::= SEQUENCE {
 *   version           Version,
 *   modulus           INTEGER,  -- n
 *   publicExponent    INTEGER,  -- e
 *   privateExponent   INTEGER,  -- d
 *   prime1            INTEGER,  -- p
 *   prime2            INTEGER,  -- q
 *   exponent1         INTEGER,  -- d mod (p1)
 *   exponent2         INTEGER,  -- d mod (q-1)
 *   coefficient       INTEGER,  -- (inverse of q) mod p
 * }
 * @returns {string}  DER Encoded String representing the rsa private key
 * @private
 */
RSAKey.prototype.getPrivateBaseKey = function () {
  var options = {
    'array': [
      new KJUR.asn1.DERInteger({'int': 0}),
      new KJUR.asn1.DERInteger({'bigint': this.n}),
      new KJUR.asn1.DERInteger({'int': this.e}),
      new KJUR.asn1.DERInteger({'bigint': this.d}),
      new KJUR.asn1.DERInteger({'bigint': this.p}),
      new KJUR.asn1.DERInteger({'bigint': this.q}),
      new KJUR.asn1.DERInteger({'bigint': this.dmp1}),
      new KJUR.asn1.DERInteger({'bigint': this.dmq1}),
      new KJUR.asn1.DERInteger({'bigint': this.coeff})
    ]
  };
  var seq = new KJUR.asn1.DERSequence(options);
  return seq.getEncodedHex();
};

/**
 * base64 (pem) encoded version of the DER encoded representation
 * @returns {string} pem encoded representation without header and footer
 * @public
 */
RSAKey.prototype.getPrivateBaseKeyB64 = function () {
  return hex2b64(this.getPrivateBaseKey());
};

/**
 * Translate rsa parameters in a hex encoded string representing the rsa public key.
 * The representation follow the ASN.1 notation :
 * PublicKeyInfo ::= SEQUENCE {
 *   algorithm       AlgorithmIdentifier,
 *   PublicKey       BIT STRING
 * }
 * Where AlgorithmIdentifier is:
 * AlgorithmIdentifier ::= SEQUENCE {
 *   algorithm       OBJECT IDENTIFIER,     the OID of the enc algorithm
 *   parameters      ANY DEFINED BY algorithm OPTIONAL (NULL for PKCS #1)
 * }
 * and PublicKey is a SEQUENCE encapsulated in a BIT STRING
 * RSAPublicKey ::= SEQUENCE {
 *   modulus           INTEGER,  -- n
 *   publicExponent    INTEGER   -- e
 * }
 * @returns {string} DER Encoded String representing the rsa public key
 * @private
 */
RSAKey.prototype.getPublicBaseKey = function () {
  var options = {
    'array': [
      new KJUR.asn1.DERObjectIdentifier({'oid': '1.2.840.113549.1.1.1'}), //RSA Encryption pkcs #1 oid
      new KJUR.asn1.DERNull()
    ]
  };
  var first_sequence = new KJUR.asn1.DERSequence(options);

  options = {
    'array': [
      new KJUR.asn1.DERInteger({'bigint': this.n}),
      new KJUR.asn1.DERInteger({'int': this.e})
    ]
  };
  var second_sequence = new KJUR.asn1.DERSequence(options);

  options = {
    'hex': '00' + second_sequence.getEncodedHex()
  };
  var bit_string = new KJUR.asn1.DERBitString(options);

  options = {
    'array': [
      first_sequence,
      bit_string
    ]
  };
  var seq = new KJUR.asn1.DERSequence(options);
  return seq.getEncodedHex();
};

/**
 * base64 (pem) encoded version of the DER encoded representation
 * @returns {string} pem encoded representation without header and footer
 * @public
 */
RSAKey.prototype.getPublicBaseKeyB64 = function () {
  return hex2b64(this.getPublicBaseKey());
};

/**
 * wrap the string in block of width chars. The default value for rsa keys is 64
 * characters.
 * @param {string} str the pem encoded string without header and footer
 * @param {Number} [width=64] - the length the string has to be wrapped at
 * @returns {string}
 * @private
 */
RSAKey.prototype.wordwrap = function (str, width) {
  width = width || 64;
  if (!str) {
    return str;
  }
  var regex = '(.{1,' + width + '})( +|$\n?)|(.{1,' + width + '})';
  return str.match(RegExp(regex, 'g')).join('\n');
};

/**
 * Retrieve the pem encoded private key
 * @returns {string} the pem encoded private key with header/footer
 * @public
 */
RSAKey.prototype.getPrivateKey = function () {
  var key = "-----BEGIN RSA PRIVATE KEY-----\n";
  key += this.wordwrap(this.getPrivateBaseKeyB64()) + "\n";
  key += "-----END RSA PRIVATE KEY-----";
  return key;
};

/**
 * Retrieve the pem encoded public key
 * @returns {string} the pem encoded public key with header/footer
 * @public
 */
RSAKey.prototype.getPublicKey = function () {
  var key = "-----BEGIN PUBLIC KEY-----\n";
  key += this.wordwrap(this.getPublicBaseKeyB64()) + "\n";
  key += "-----END PUBLIC KEY-----";
  return key;
};

/**
 * Check if the object contains the necessary parameters to populate the rsa modulus
 * and public exponent parameters.
 * @param {Object} [obj={}] - An object that may contain the two public key
 * parameters
 * @returns {boolean} true if the object contains both the modulus and the public exponent
 * properties (n and e)
 * @todo check for types of n and e. N should be a parseable bigInt object, E should
 * be a parseable integer number
 * @private
 */
RSAKey.prototype.hasPublicKeyProperty = function (obj) {
  obj = obj || {};
  return (
    obj.hasOwnProperty('n') &&
    obj.hasOwnProperty('e')
  );
};

/**
 * Check if the object contains ALL the parameters of an RSA key.
 * @param {Object} [obj={}] - An object that may contain nine rsa key
 * parameters
 * @returns {boolean} true if the object contains all the parameters needed
 * @todo check for types of the parameters all the parameters but the public exponent
 * should be parseable bigint objects, the public exponent should be a parseable integer number
 * @private
 */
RSAKey.prototype.hasPrivateKeyProperty = function (obj) {
  obj = obj || {};
  return (
    obj.hasOwnProperty('n') &&
    obj.hasOwnProperty('e') &&
    obj.hasOwnProperty('d') &&
    obj.hasOwnProperty('p') &&
    obj.hasOwnProperty('q') &&
    obj.hasOwnProperty('dmp1') &&
    obj.hasOwnProperty('dmq1') &&
    obj.hasOwnProperty('coeff')
  );
};

/**
 * Parse the properties of obj in the current rsa object. Obj should AT LEAST
 * include the modulus and public exponent (n, e) parameters.
 * @param {Object} obj - the object containing rsa parameters
 * @private
 */
RSAKey.prototype.parsePropertiesFrom = function (obj) {
  this.n = obj.n;
  this.e = obj.e;

  if (obj.hasOwnProperty('d')) {
    this.d = obj.d;
    this.p = obj.p;
    this.q = obj.q;
    this.dmp1 = obj.dmp1;
    this.dmq1 = obj.dmq1;
    this.coeff = obj.coeff;
  }
};

/**
 * Create a new JSEncryptRSAKey that extends Tom Wu's RSA key object.
 * This object is just a decorator for parsing the key parameter
 * @param {string|Object} key - The key in string format, or an object containing
 * the parameters needed to build a RSAKey object.
 * @constructor
 */
var JSEncryptRSAKey = function (key) {
  // Call the super constructor.
  RSAKey.call(this);
  // If a key key was provided.
  if (key) {
    // If this is a string...
    if (typeof key === 'string') {
      this.parseKey(key);
    }
    else if (
      this.hasPrivateKeyProperty(key) ||
      this.hasPublicKeyProperty(key)
    ) {
      // Set the values for the key.
      this.parsePropertiesFrom(key);
    }
  }
};

// Derive from RSAKey.
JSEncryptRSAKey.prototype = new RSAKey();

// Reset the contructor.
JSEncryptRSAKey.prototype.constructor = JSEncryptRSAKey;


/**
 *
 * @param {Object} [options = {}] - An object to customize JSEncrypt behaviour
 * possible parameters are:
 * - default_key_size        {number}  default: 1024 the key size in bit
 * - default_public_exponent {string}  default: '010001' the hexadecimal representation of the public exponent
 * - log                     {boolean} default: false whether log warn/error or not
 * @constructor
 */
var JSEncrypt = function (options) {
  options = options || {};
  this.default_key_size = parseInt(options.default_key_size) || 1024;
  this.default_public_exponent = options.default_public_exponent || '010001'; //65537 default openssl public exponent for rsa key type
  this.log = options.log || false;
  // The private and public key.
  this.key = null;
};

/**
 * Method to set the rsa key parameter (one method is enough to set both the public
 * and the private key, since the private key contains the public key paramenters)
 * Log a warning if logs are enabled
 * @param {Object|string} key the pem encoded string or an object (with or without header/footer)
 * @public
 */
JSEncrypt.prototype.setKey = function (key) {
  if (this.log && this.key) {
    console.warn('A key was already set, overriding existing.');
  }
  this.key = new JSEncryptRSAKey(key);
};

/**
 * Proxy method for setKey, for api compatibility
 * @see setKey
 * @public
 */
JSEncrypt.prototype.setPrivateKey = function (privkey) {
  // Create the key.
  this.setKey(privkey);
};

/**
 * Proxy method for setKey, for api compatibility
 * @see setKey
 * @public
 */
JSEncrypt.prototype.setPublicKey = function (pubkey) {
  // Sets the public key.
  this.setKey(pubkey);
};

/**
 * Proxy method for RSAKey object's decrypt, decrypt the string using the private
 * components of the rsa key object. Note that if the object was not set will be created
 * on the fly (by the getKey method) using the parameters passed in the JSEncrypt constructor
 * @param {string} string base64 encoded crypted string to decrypt
 * @return {string} the decrypted string
 * @public
 */
JSEncrypt.prototype.decrypt = function (string) {
  // Return the decrypted string.
  try {
    return this.getKey().decrypt(b64tohex(string));
  }
  catch (ex) {
    return false;
  }
};

/**
 * Proxy method for RSAKey object's encrypt, encrypt the string using the public
 * components of the rsa key object. Note that if the object was not set will be created
 * on the fly (by the getKey method) using the parameters passed in the JSEncrypt constructor
 * @param {string} string the string to encrypt
 * @return {string} the encrypted string encoded in base64
 * @public
 */
JSEncrypt.prototype.encrypt = function (string) {
  // Return the encrypted string.
  try {
    return hex2b64(this.getKey().encrypt(string));
  }
  catch (ex) {
    return false;
  }
};

/**
 * Getter for the current JSEncryptRSAKey object. If it doesn't exists a new object
 * will be created and returned
 * @param {callback} [cb] the callback to be called if we want the key to be generated
 * in an async fashion
 * @returns {JSEncryptRSAKey} the JSEncryptRSAKey object
 * @public
 */
JSEncrypt.prototype.getKey = function (cb) {
  // Only create new if it does not exist.
  if (!this.key) {
    // Get a new private key.
    this.key = new JSEncryptRSAKey();
    if (cb && {}.toString.call(cb) === '[object Function]') {
      this.key.generateAsync(this.default_key_size, this.default_public_exponent, cb);
      return;
    }
    // Generate the key.
    this.key.generate(this.default_key_size, this.default_public_exponent);
  }
  return this.key;
};

/**
 * Returns the pem encoded representation of the private key
 * If the key doesn't exists a new key will be created
 * @returns {string} pem encoded representation of the private key WITH header and footer
 * @public
 */
JSEncrypt.prototype.getPrivateKey = function () {
  // Return the private representation of this key.
  return this.getKey().getPrivateKey();
};

/**
 * Returns the pem encoded representation of the private key
 * If the key doesn't exists a new key will be created
 * @returns {string} pem encoded representation of the private key WITHOUT header and footer
 * @public
 */
JSEncrypt.prototype.getPrivateKeyB64 = function () {
  // Return the private representation of this key.
  return this.getKey().getPrivateBaseKeyB64();
};


/**
 * Returns the pem encoded representation of the public key
 * If the key doesn't exists a new key will be created
 * @returns {string} pem encoded representation of the public key WITH header and footer
 * @public
 */
JSEncrypt.prototype.getPublicKey = function () {
  // Return the private representation of this key.
  return this.getKey().getPublicKey();
};

/**
 * Returns the pem encoded representation of the public key
 * If the key doesn't exists a new key will be created
 * @returns {string} pem encoded representation of the public key WITHOUT header and footer
 * @public
 */
JSEncrypt.prototype.getPublicKeyB64 = function () {
  // Return the private representation of this key.
  return this.getKey().getPublicBaseKeyB64();
};


  JSEncrypt.version = '2.3.1';
  exports.JSEncrypt = JSEncrypt;
});
},{}]},{},[1])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJkZXYvanMvYXBwbGljYXRpb24uanMiLCJkZXYvanMvY29uc3RhbnRzLmpzIiwibm9kZV9tb2R1bGVzL2pzZW5jcnlwdC9iaW4vanNlbmNyeXB0LmpzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBO0FDQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDNURBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQzNCQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSIsImZpbGUiOiJnZW5lcmF0ZWQuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlc0NvbnRlbnQiOlsiKGZ1bmN0aW9uIGUodCxuLHIpe2Z1bmN0aW9uIHMobyx1KXtpZighbltvXSl7aWYoIXRbb10pe3ZhciBhPXR5cGVvZiByZXF1aXJlPT1cImZ1bmN0aW9uXCImJnJlcXVpcmU7aWYoIXUmJmEpcmV0dXJuIGEobywhMCk7aWYoaSlyZXR1cm4gaShvLCEwKTt2YXIgZj1uZXcgRXJyb3IoXCJDYW5ub3QgZmluZCBtb2R1bGUgJ1wiK28rXCInXCIpO3Rocm93IGYuY29kZT1cIk1PRFVMRV9OT1RfRk9VTkRcIixmfXZhciBsPW5bb109e2V4cG9ydHM6e319O3Rbb11bMF0uY2FsbChsLmV4cG9ydHMsZnVuY3Rpb24oZSl7dmFyIG49dFtvXVsxXVtlXTtyZXR1cm4gcyhuP246ZSl9LGwsbC5leHBvcnRzLGUsdCxuLHIpfXJldHVybiBuW29dLmV4cG9ydHN9dmFyIGk9dHlwZW9mIHJlcXVpcmU9PVwiZnVuY3Rpb25cIiYmcmVxdWlyZTtmb3IodmFyIG89MDtvPHIubGVuZ3RoO28rKylzKHJbb10pO3JldHVybiBzfSkiLCIvKmpzaGludCBtdWx0aXN0cjogdHJ1ZSAqL1xyXG5KU0VuY3J5cHQgPSByZXF1aXJlKCdqc2VuY3J5cHQnKS5KU0VuY3J5cHQ7XHJcbkNvbnN0YW50cyA9IHJlcXVpcmUoJy4vY29uc3RhbnRzJyk7XHJcblxyXG5mdW5jdGlvbiBlbmNyeXB0S2V5VmFsdWVQYWlyKHBhaXIpe1xyXG4gIHZhciBjcnlwdCA9IG5ldyBKU0VuY3J5cHQoKTtcclxuICBjcnlwdC5zZXRQdWJsaWNLZXkoQ29uc3RhbnRzLnB1YmxpY19rZXkpO1xyXG4gIGVuY3J5cHRlZF9wYWlyID0ge1xyXG4gICAga2V5OiBjcnlwdC5lbmNyeXB0KHBhaXIua2V5KSxcclxuICAgIHZhbHVlOiBjcnlwdC5lbmNyeXB0KHBhaXIudmFsdWUpXHJcbiAgfTtcclxuICByZXR1cm4gZW5jcnlwdGVkX3BhaXI7XHJcbn1cclxuXHJcbmZ1bmN0aW9uIHN1Ym1pdEtleVZhbHVlUGFpcihldmVudCkge1xyXG4gIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XHJcbiAga2V5X2VsZW1lbnQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcImtleVwiKTtcclxuICB2YWx1ZV9lbGVtZW50ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJ2YWx1ZVwiKTtcclxuXHJcbiAgaWYgKHZhbHVlX2VsZW1lbnQudmFsdWUgPT0gXCJcIil7XHJcbiAgICB2YWx1ZV9lbGVtZW50ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJ2YWx1ZV9zZWxlY3RcIik7XHJcbiAgfVxyXG5cclxuICB2YXIgcGFpciA9IHtcclxuICAgIGtleSA6IGtleV9lbGVtZW50LnZhbHVlLFxyXG4gICAgdmFsdWUgOiB2YWx1ZV9lbGVtZW50LnZhbHVlXHJcbiAgfTtcclxuXHJcbiAgdmFyIGVuY3J5cHRlZF9wYWlyID0gZW5jcnlwdEtleVZhbHVlUGFpcihwYWlyKTtcclxuXHJcbiAgc2VuZChlbmNyeXB0ZWRfcGFpcik7XHJcbn1cclxuXHJcbmZ1bmN0aW9uIHNlbmQoZW5jcnlwdGVkX3BhaXIpIHtcclxuICB2YXIgeGh0dHAgPSBuZXcgWE1MSHR0cFJlcXVlc3QoKTtcclxuICB4aHR0cC5vbnJlYWR5c3RhdGVjaGFuZ2UgPSBmdW5jdGlvbigpIHtcclxuICAgIGlmICh4aHR0cC5yZWFkeVN0YXRlID09IDQgJiYgeGh0dHAuc3RhdHVzID09IDIwMCkge1xyXG4gICAgIGFsZXJ0KCdTZW50IHN1Y2Nlc3NmdWxseScpO1xyXG4gICAgfVxyXG4gIH07XHJcbiAgeGh0dHAub3BlbihcIlBPU1RcIiwgXCJ3cml0ZVwiLCB0cnVlKTtcclxuICB4aHR0cC5zZXRSZXF1ZXN0SGVhZGVyKFwiQ29udGVudC1UeXBlXCIsIFwiYXBwbGljYXRpb24vanNvbjtjaGFyc2V0PVVURi04XCIpO1xyXG4gIHhodHRwLnNlbmQoSlNPTi5zdHJpbmdpZnkoZW5jcnlwdGVkX3BhaXIpKTtcclxufVxyXG5cclxud2luZG93Lm9ubG9hZCA9IGZ1bmN0aW9uKCl7XHJcbiAgdmFyIGZvcm0gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcImZvcm1cIik7XHJcbiAgZm9ybS5hZGRFdmVudExpc3RlbmVyKCdzdWJtaXQnLCBzdWJtaXRLZXlWYWx1ZVBhaXIpO1xyXG4gIHZhciBmb3JtID0gZm9ybS5hcHBlbmRDaGlsZChjcmVhdGVTZWxlY3QoKSk7XHJcbn07XHJcblxyXG5mdW5jdGlvbiBjcmVhdGVTZWxlY3QoKXtcclxuICB2YXIgc2VsZWN0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudChcInNlbGVjdFwiKTtcclxuICBzZWxlY3QuaWQgPSBcInZhbHVlX3NlbGVjdFwiO1xyXG4gIENvbnN0YW50cy52YWx1ZV9vcHRpb25zLmZvckVhY2goZnVuY3Rpb24oZWxlbWVudCl7XHJcbiAgICB2YXIgb3B0aW9uID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudChcIm9wdGlvblwiKTtcclxuICAgIG9wdGlvbi50ZXh0ID0gZWxlbWVudDtcclxuICAgIHNlbGVjdC5hZGQob3B0aW9uKTtcclxuICB9KVxyXG4gIHJldHVybiBzZWxlY3Q7XHJcbn0iLCIvKmpzaGludCBtdWx0aXN0cjogdHJ1ZSAqL1xyXG5cclxubW9kdWxlLmV4cG9ydHMgPSB7XHJcbiAgcHVibGljX2tleTogXCItLS0tLUJFR0lOIFBVQkxJQyBLRVktLS0tLVxcXHJcbiAgICAgICAgICAgICAgTUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FnOEFNSUlDQ2dLQ0FnRUE1bmlwM1g2REd2Um5UQ0Y3aFFrb1xcXHJcbiAgICAgICAgICAgICAgVGdnejNxMU1VTlhWYkRnYWNSOWRhZUlOSkoraUtVcUdNNE4yaXBKc2FLZGFYMk9ud0ZxT2NhL1doMDhEcXJmdVxcXHJcbiAgICAgICAgICAgICAgQTZ1V211c3JRbks0bWhNUno0ZUxUNE5kSVRVZS9GMHJFeVV3VkdqVEM0WVN6YWNCQ2VKSnM3MzFKR2lGTzdaa1xcXHJcbiAgICAgICAgICAgICAgYmJ4UEhVQWd1MHREazVLQm5EWVhKNjQ3Zm5pQlF4TktFOXZZRHQ4TGNZZnYrWGEvbnAzby92V2FhaEdRVDQxaFxcXHJcbiAgICAgICAgICAgICAgVGF1ZExERGJNY2UzdkhObk00YklIZWFqcko5Zmx6Y283c1o0V2hnbUdaMWRGdDRoMFQ0K3cxQUNmMytzMzlocFxcXHJcbiAgICAgICAgICAgICAgcEhlN2pHcjVXVDFHT3FGdnJySllKN2hEMVFQQ0tmU3B4WDE0YnRIeDZLeUhQYi9KdG5vYi8xaDFFWG1hVjRGOVxcXHJcbiAgICAgICAgICAgICAgZHRyOU9nZ1JmRVFkN0hScEJJUEhxVEUvTDRzZ2ZvWmxhZXl1SFRVK3RnK3ZYYS95MmIwdHVYbThjVFZFRVdaZlxcXHJcbiAgICAgICAgICAgICAgNHM2ZXNMS0RPZVo2WmpKRFowRzNJRzlWVjFGQWdlTXFia0V3aGN4RXQrV2VhZk1KQzBXZC9OaFZJSEZXWlN3M1xcXHJcbiAgICAgICAgICAgICAgTmdPdkxzUW1jUXkxTW5hZHZwbVB0akR2UVhDUVBuR0FkS1VFdW90SFdWYUYrcDA2WHhLZVo5azJCelE0UkxQQVxcXHJcbiAgICAgICAgICAgICAgeFpPVVErSFFOeEhKTjN2Z3FEeWI2bnJSV3JtUnBGVzZmRDlpbTh3ZmNKeE83N3lTZHVDRHEraGNIazdVcXZuTFxcXHJcbiAgICAgICAgICAgICAgSS82RWNNdWppSTBSeWcwdG5RdGVBVTlDRjYreFZ5SHBZQVNIbzB0NVNaRG0xYktkV3Jqa0pVc1B6cGRqemMxL1xcXHJcbiAgICAgICAgICAgICAgelk2K0ZTeEJodHZrSitlZ3lDS2RNaHNDQXdFQUFRPT1cXFxyXG4gICAgICAgICAgICAgIC0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLVwiLFxyXG4gIHZhbHVlX29wdGlvbnM6IFtcclxuICAgIDEwMSxcclxuICAgIDIwMSxcclxuICAgIDIwNSxcclxuICAgIDMwMSxcclxuICAgIDQwMSxcclxuICAgIDYwMSxcclxuICAgIDYwMlxyXG4gIF1cclxufTtcclxuIiwiLyohIEpTRW5jcnlwdCB2Mi4zLjEgfCBodHRwczovL25wbWNkbi5jb20vanNlbmNyeXB0QDIuMy4xL0xJQ0VOU0UudHh0ICovXG4oZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnkpIHtcbiAgaWYgKHR5cGVvZiBkZWZpbmUgPT09ICdmdW5jdGlvbicgJiYgZGVmaW5lLmFtZCkge1xuICAgIC8vIEFNRFxuICAgIGRlZmluZShbJ2V4cG9ydHMnXSwgZmFjdG9yeSk7XG4gIH0gZWxzZSBpZiAodHlwZW9mIGV4cG9ydHMgPT09ICdvYmplY3QnICYmIHR5cGVvZiBleHBvcnRzLm5vZGVOYW1lICE9PSAnc3RyaW5nJykge1xuICAgIC8vIE5vZGUsIENvbW1vbkpTLWxpa2VcbiAgICBmYWN0b3J5KG1vZHVsZS5leHBvcnRzKTtcbiAgfSBlbHNlIHtcbiAgICBmYWN0b3J5KHJvb3QpO1xuICB9XG59KSh0aGlzLCBmdW5jdGlvbiAoZXhwb3J0cykge1xuICAvLyBDb3B5cmlnaHQgKGMpIDIwMDUgIFRvbSBXdVxuLy8gQWxsIFJpZ2h0cyBSZXNlcnZlZC5cbi8vIFNlZSBcIkxJQ0VOU0VcIiBmb3IgZGV0YWlscy5cblxuLy8gQmFzaWMgSmF2YVNjcmlwdCBCTiBsaWJyYXJ5IC0gc3Vic2V0IHVzZWZ1bCBmb3IgUlNBIGVuY3J5cHRpb24uXG5cbi8vIEJpdHMgcGVyIGRpZ2l0XG52YXIgZGJpdHM7XG5cbi8vIEphdmFTY3JpcHQgZW5naW5lIGFuYWx5c2lzXG52YXIgY2FuYXJ5ID0gMHhkZWFkYmVlZmNhZmU7XG52YXIgal9sbSA9ICgoY2FuYXJ5JjB4ZmZmZmZmKT09MHhlZmNhZmUpO1xuXG4vLyAocHVibGljKSBDb25zdHJ1Y3RvclxuZnVuY3Rpb24gQmlnSW50ZWdlcihhLGIsYykge1xuICBpZihhICE9IG51bGwpXG4gICAgaWYoXCJudW1iZXJcIiA9PSB0eXBlb2YgYSkgdGhpcy5mcm9tTnVtYmVyKGEsYixjKTtcbiAgICBlbHNlIGlmKGIgPT0gbnVsbCAmJiBcInN0cmluZ1wiICE9IHR5cGVvZiBhKSB0aGlzLmZyb21TdHJpbmcoYSwyNTYpO1xuICAgIGVsc2UgdGhpcy5mcm9tU3RyaW5nKGEsYik7XG59XG5cbi8vIHJldHVybiBuZXcsIHVuc2V0IEJpZ0ludGVnZXJcbmZ1bmN0aW9uIG5iaSgpIHsgcmV0dXJuIG5ldyBCaWdJbnRlZ2VyKG51bGwpOyB9XG5cbi8vIGFtOiBDb21wdXRlIHdfaiArPSAoeCp0aGlzX2kpLCBwcm9wYWdhdGUgY2Fycmllcyxcbi8vIGMgaXMgaW5pdGlhbCBjYXJyeSwgcmV0dXJucyBmaW5hbCBjYXJyeS5cbi8vIGMgPCAzKmR2YWx1ZSwgeCA8IDIqZHZhbHVlLCB0aGlzX2kgPCBkdmFsdWVcbi8vIFdlIG5lZWQgdG8gc2VsZWN0IHRoZSBmYXN0ZXN0IG9uZSB0aGF0IHdvcmtzIGluIHRoaXMgZW52aXJvbm1lbnQuXG5cbi8vIGFtMTogdXNlIGEgc2luZ2xlIG11bHQgYW5kIGRpdmlkZSB0byBnZXQgdGhlIGhpZ2ggYml0cyxcbi8vIG1heCBkaWdpdCBiaXRzIHNob3VsZCBiZSAyNiBiZWNhdXNlXG4vLyBtYXggaW50ZXJuYWwgdmFsdWUgPSAyKmR2YWx1ZV4yLTIqZHZhbHVlICg8IDJeNTMpXG5mdW5jdGlvbiBhbTEoaSx4LHcsaixjLG4pIHtcbiAgd2hpbGUoLS1uID49IDApIHtcbiAgICB2YXIgdiA9IHgqdGhpc1tpKytdK3dbal0rYztcbiAgICBjID0gTWF0aC5mbG9vcih2LzB4NDAwMDAwMCk7XG4gICAgd1tqKytdID0gdiYweDNmZmZmZmY7XG4gIH1cbiAgcmV0dXJuIGM7XG59XG4vLyBhbTIgYXZvaWRzIGEgYmlnIG11bHQtYW5kLWV4dHJhY3QgY29tcGxldGVseS5cbi8vIE1heCBkaWdpdCBiaXRzIHNob3VsZCBiZSA8PSAzMCBiZWNhdXNlIHdlIGRvIGJpdHdpc2Ugb3BzXG4vLyBvbiB2YWx1ZXMgdXAgdG8gMipoZHZhbHVlXjItaGR2YWx1ZS0xICg8IDJeMzEpXG5mdW5jdGlvbiBhbTIoaSx4LHcsaixjLG4pIHtcbiAgdmFyIHhsID0geCYweDdmZmYsIHhoID0geD4+MTU7XG4gIHdoaWxlKC0tbiA+PSAwKSB7XG4gICAgdmFyIGwgPSB0aGlzW2ldJjB4N2ZmZjtcbiAgICB2YXIgaCA9IHRoaXNbaSsrXT4+MTU7XG4gICAgdmFyIG0gPSB4aCpsK2gqeGw7XG4gICAgbCA9IHhsKmwrKChtJjB4N2ZmZik8PDE1KSt3W2pdKyhjJjB4M2ZmZmZmZmYpO1xuICAgIGMgPSAobD4+PjMwKSsobT4+PjE1KSt4aCpoKyhjPj4+MzApO1xuICAgIHdbaisrXSA9IGwmMHgzZmZmZmZmZjtcbiAgfVxuICByZXR1cm4gYztcbn1cbi8vIEFsdGVybmF0ZWx5LCBzZXQgbWF4IGRpZ2l0IGJpdHMgdG8gMjggc2luY2Ugc29tZVxuLy8gYnJvd3NlcnMgc2xvdyBkb3duIHdoZW4gZGVhbGluZyB3aXRoIDMyLWJpdCBudW1iZXJzLlxuZnVuY3Rpb24gYW0zKGkseCx3LGosYyxuKSB7XG4gIHZhciB4bCA9IHgmMHgzZmZmLCB4aCA9IHg+PjE0O1xuICB3aGlsZSgtLW4gPj0gMCkge1xuICAgIHZhciBsID0gdGhpc1tpXSYweDNmZmY7XG4gICAgdmFyIGggPSB0aGlzW2krK10+PjE0O1xuICAgIHZhciBtID0geGgqbCtoKnhsO1xuICAgIGwgPSB4bCpsKygobSYweDNmZmYpPDwxNCkrd1tqXStjO1xuICAgIGMgPSAobD4+MjgpKyhtPj4xNCkreGgqaDtcbiAgICB3W2orK10gPSBsJjB4ZmZmZmZmZjtcbiAgfVxuICByZXR1cm4gYztcbn1cbmlmKGpfbG0gJiYgKG5hdmlnYXRvci5hcHBOYW1lID09IFwiTWljcm9zb2Z0IEludGVybmV0IEV4cGxvcmVyXCIpKSB7XG4gIEJpZ0ludGVnZXIucHJvdG90eXBlLmFtID0gYW0yO1xuICBkYml0cyA9IDMwO1xufVxuZWxzZSBpZihqX2xtICYmIChuYXZpZ2F0b3IuYXBwTmFtZSAhPSBcIk5ldHNjYXBlXCIpKSB7XG4gIEJpZ0ludGVnZXIucHJvdG90eXBlLmFtID0gYW0xO1xuICBkYml0cyA9IDI2O1xufVxuZWxzZSB7IC8vIE1vemlsbGEvTmV0c2NhcGUgc2VlbXMgdG8gcHJlZmVyIGFtM1xuICBCaWdJbnRlZ2VyLnByb3RvdHlwZS5hbSA9IGFtMztcbiAgZGJpdHMgPSAyODtcbn1cblxuQmlnSW50ZWdlci5wcm90b3R5cGUuREIgPSBkYml0cztcbkJpZ0ludGVnZXIucHJvdG90eXBlLkRNID0gKCgxPDxkYml0cyktMSk7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5EViA9ICgxPDxkYml0cyk7XG5cbnZhciBCSV9GUCA9IDUyO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuRlYgPSBNYXRoLnBvdygyLEJJX0ZQKTtcbkJpZ0ludGVnZXIucHJvdG90eXBlLkYxID0gQklfRlAtZGJpdHM7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5GMiA9IDIqZGJpdHMtQklfRlA7XG5cbi8vIERpZ2l0IGNvbnZlcnNpb25zXG52YXIgQklfUk0gPSBcIjAxMjM0NTY3ODlhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5elwiO1xudmFyIEJJX1JDID0gbmV3IEFycmF5KCk7XG52YXIgcnIsdnY7XG5yciA9IFwiMFwiLmNoYXJDb2RlQXQoMCk7XG5mb3IodnYgPSAwOyB2diA8PSA5OyArK3Z2KSBCSV9SQ1tycisrXSA9IHZ2O1xucnIgPSBcImFcIi5jaGFyQ29kZUF0KDApO1xuZm9yKHZ2ID0gMTA7IHZ2IDwgMzY7ICsrdnYpIEJJX1JDW3JyKytdID0gdnY7XG5yciA9IFwiQVwiLmNoYXJDb2RlQXQoMCk7XG5mb3IodnYgPSAxMDsgdnYgPCAzNjsgKyt2dikgQklfUkNbcnIrK10gPSB2djtcblxuZnVuY3Rpb24gaW50MmNoYXIobikgeyByZXR1cm4gQklfUk0uY2hhckF0KG4pOyB9XG5mdW5jdGlvbiBpbnRBdChzLGkpIHtcbiAgdmFyIGMgPSBCSV9SQ1tzLmNoYXJDb2RlQXQoaSldO1xuICByZXR1cm4gKGM9PW51bGwpPy0xOmM7XG59XG5cbi8vIChwcm90ZWN0ZWQpIGNvcHkgdGhpcyB0byByXG5mdW5jdGlvbiBibnBDb3B5VG8ocikge1xuICBmb3IodmFyIGkgPSB0aGlzLnQtMTsgaSA+PSAwOyAtLWkpIHJbaV0gPSB0aGlzW2ldO1xuICByLnQgPSB0aGlzLnQ7XG4gIHIucyA9IHRoaXMucztcbn1cblxuLy8gKHByb3RlY3RlZCkgc2V0IGZyb20gaW50ZWdlciB2YWx1ZSB4LCAtRFYgPD0geCA8IERWXG5mdW5jdGlvbiBibnBGcm9tSW50KHgpIHtcbiAgdGhpcy50ID0gMTtcbiAgdGhpcy5zID0gKHg8MCk/LTE6MDtcbiAgaWYoeCA+IDApIHRoaXNbMF0gPSB4O1xuICBlbHNlIGlmKHggPCAtMSkgdGhpc1swXSA9IHgrdGhpcy5EVjtcbiAgZWxzZSB0aGlzLnQgPSAwO1xufVxuXG4vLyByZXR1cm4gYmlnaW50IGluaXRpYWxpemVkIHRvIHZhbHVlXG5mdW5jdGlvbiBuYnYoaSkgeyB2YXIgciA9IG5iaSgpOyByLmZyb21JbnQoaSk7IHJldHVybiByOyB9XG5cbi8vIChwcm90ZWN0ZWQpIHNldCBmcm9tIHN0cmluZyBhbmQgcmFkaXhcbmZ1bmN0aW9uIGJucEZyb21TdHJpbmcocyxiKSB7XG4gIHZhciBrO1xuICBpZihiID09IDE2KSBrID0gNDtcbiAgZWxzZSBpZihiID09IDgpIGsgPSAzO1xuICBlbHNlIGlmKGIgPT0gMjU2KSBrID0gODsgLy8gYnl0ZSBhcnJheVxuICBlbHNlIGlmKGIgPT0gMikgayA9IDE7XG4gIGVsc2UgaWYoYiA9PSAzMikgayA9IDU7XG4gIGVsc2UgaWYoYiA9PSA0KSBrID0gMjtcbiAgZWxzZSB7IHRoaXMuZnJvbVJhZGl4KHMsYik7IHJldHVybjsgfVxuICB0aGlzLnQgPSAwO1xuICB0aGlzLnMgPSAwO1xuICB2YXIgaSA9IHMubGVuZ3RoLCBtaSA9IGZhbHNlLCBzaCA9IDA7XG4gIHdoaWxlKC0taSA+PSAwKSB7XG4gICAgdmFyIHggPSAoaz09OCk/c1tpXSYweGZmOmludEF0KHMsaSk7XG4gICAgaWYoeCA8IDApIHtcbiAgICAgIGlmKHMuY2hhckF0KGkpID09IFwiLVwiKSBtaSA9IHRydWU7XG4gICAgICBjb250aW51ZTtcbiAgICB9XG4gICAgbWkgPSBmYWxzZTtcbiAgICBpZihzaCA9PSAwKVxuICAgICAgdGhpc1t0aGlzLnQrK10gPSB4O1xuICAgIGVsc2UgaWYoc2grayA+IHRoaXMuREIpIHtcbiAgICAgIHRoaXNbdGhpcy50LTFdIHw9ICh4JigoMTw8KHRoaXMuREItc2gpKS0xKSk8PHNoO1xuICAgICAgdGhpc1t0aGlzLnQrK10gPSAoeD4+KHRoaXMuREItc2gpKTtcbiAgICB9XG4gICAgZWxzZVxuICAgICAgdGhpc1t0aGlzLnQtMV0gfD0geDw8c2g7XG4gICAgc2ggKz0gaztcbiAgICBpZihzaCA+PSB0aGlzLkRCKSBzaCAtPSB0aGlzLkRCO1xuICB9XG4gIGlmKGsgPT0gOCAmJiAoc1swXSYweDgwKSAhPSAwKSB7XG4gICAgdGhpcy5zID0gLTE7XG4gICAgaWYoc2ggPiAwKSB0aGlzW3RoaXMudC0xXSB8PSAoKDE8PCh0aGlzLkRCLXNoKSktMSk8PHNoO1xuICB9XG4gIHRoaXMuY2xhbXAoKTtcbiAgaWYobWkpIEJpZ0ludGVnZXIuWkVSTy5zdWJUbyh0aGlzLHRoaXMpO1xufVxuXG4vLyAocHJvdGVjdGVkKSBjbGFtcCBvZmYgZXhjZXNzIGhpZ2ggd29yZHNcbmZ1bmN0aW9uIGJucENsYW1wKCkge1xuICB2YXIgYyA9IHRoaXMucyZ0aGlzLkRNO1xuICB3aGlsZSh0aGlzLnQgPiAwICYmIHRoaXNbdGhpcy50LTFdID09IGMpIC0tdGhpcy50O1xufVxuXG4vLyAocHVibGljKSByZXR1cm4gc3RyaW5nIHJlcHJlc2VudGF0aW9uIGluIGdpdmVuIHJhZGl4XG5mdW5jdGlvbiBiblRvU3RyaW5nKGIpIHtcbiAgaWYodGhpcy5zIDwgMCkgcmV0dXJuIFwiLVwiK3RoaXMubmVnYXRlKCkudG9TdHJpbmcoYik7XG4gIHZhciBrO1xuICBpZihiID09IDE2KSBrID0gNDtcbiAgZWxzZSBpZihiID09IDgpIGsgPSAzO1xuICBlbHNlIGlmKGIgPT0gMikgayA9IDE7XG4gIGVsc2UgaWYoYiA9PSAzMikgayA9IDU7XG4gIGVsc2UgaWYoYiA9PSA0KSBrID0gMjtcbiAgZWxzZSByZXR1cm4gdGhpcy50b1JhZGl4KGIpO1xuICB2YXIga20gPSAoMTw8ayktMSwgZCwgbSA9IGZhbHNlLCByID0gXCJcIiwgaSA9IHRoaXMudDtcbiAgdmFyIHAgPSB0aGlzLkRCLShpKnRoaXMuREIpJWs7XG4gIGlmKGktLSA+IDApIHtcbiAgICBpZihwIDwgdGhpcy5EQiAmJiAoZCA9IHRoaXNbaV0+PnApID4gMCkgeyBtID0gdHJ1ZTsgciA9IGludDJjaGFyKGQpOyB9XG4gICAgd2hpbGUoaSA+PSAwKSB7XG4gICAgICBpZihwIDwgaykge1xuICAgICAgICBkID0gKHRoaXNbaV0mKCgxPDxwKS0xKSk8PChrLXApO1xuICAgICAgICBkIHw9IHRoaXNbLS1pXT4+KHArPXRoaXMuREItayk7XG4gICAgICB9XG4gICAgICBlbHNlIHtcbiAgICAgICAgZCA9ICh0aGlzW2ldPj4ocC09aykpJmttO1xuICAgICAgICBpZihwIDw9IDApIHsgcCArPSB0aGlzLkRCOyAtLWk7IH1cbiAgICAgIH1cbiAgICAgIGlmKGQgPiAwKSBtID0gdHJ1ZTtcbiAgICAgIGlmKG0pIHIgKz0gaW50MmNoYXIoZCk7XG4gICAgfVxuICB9XG4gIHJldHVybiBtP3I6XCIwXCI7XG59XG5cbi8vIChwdWJsaWMpIC10aGlzXG5mdW5jdGlvbiBibk5lZ2F0ZSgpIHsgdmFyIHIgPSBuYmkoKTsgQmlnSW50ZWdlci5aRVJPLnN1YlRvKHRoaXMscik7IHJldHVybiByOyB9XG5cbi8vIChwdWJsaWMpIHx0aGlzfFxuZnVuY3Rpb24gYm5BYnMoKSB7IHJldHVybiAodGhpcy5zPDApP3RoaXMubmVnYXRlKCk6dGhpczsgfVxuXG4vLyAocHVibGljKSByZXR1cm4gKyBpZiB0aGlzID4gYSwgLSBpZiB0aGlzIDwgYSwgMCBpZiBlcXVhbFxuZnVuY3Rpb24gYm5Db21wYXJlVG8oYSkge1xuICB2YXIgciA9IHRoaXMucy1hLnM7XG4gIGlmKHIgIT0gMCkgcmV0dXJuIHI7XG4gIHZhciBpID0gdGhpcy50O1xuICByID0gaS1hLnQ7XG4gIGlmKHIgIT0gMCkgcmV0dXJuICh0aGlzLnM8MCk/LXI6cjtcbiAgd2hpbGUoLS1pID49IDApIGlmKChyPXRoaXNbaV0tYVtpXSkgIT0gMCkgcmV0dXJuIHI7XG4gIHJldHVybiAwO1xufVxuXG4vLyByZXR1cm5zIGJpdCBsZW5ndGggb2YgdGhlIGludGVnZXIgeFxuZnVuY3Rpb24gbmJpdHMoeCkge1xuICB2YXIgciA9IDEsIHQ7XG4gIGlmKCh0PXg+Pj4xNikgIT0gMCkgeyB4ID0gdDsgciArPSAxNjsgfVxuICBpZigodD14Pj44KSAhPSAwKSB7IHggPSB0OyByICs9IDg7IH1cbiAgaWYoKHQ9eD4+NCkgIT0gMCkgeyB4ID0gdDsgciArPSA0OyB9XG4gIGlmKCh0PXg+PjIpICE9IDApIHsgeCA9IHQ7IHIgKz0gMjsgfVxuICBpZigodD14Pj4xKSAhPSAwKSB7IHggPSB0OyByICs9IDE7IH1cbiAgcmV0dXJuIHI7XG59XG5cbi8vIChwdWJsaWMpIHJldHVybiB0aGUgbnVtYmVyIG9mIGJpdHMgaW4gXCJ0aGlzXCJcbmZ1bmN0aW9uIGJuQml0TGVuZ3RoKCkge1xuICBpZih0aGlzLnQgPD0gMCkgcmV0dXJuIDA7XG4gIHJldHVybiB0aGlzLkRCKih0aGlzLnQtMSkrbmJpdHModGhpc1t0aGlzLnQtMV1eKHRoaXMucyZ0aGlzLkRNKSk7XG59XG5cbi8vIChwcm90ZWN0ZWQpIHIgPSB0aGlzIDw8IG4qREJcbmZ1bmN0aW9uIGJucERMU2hpZnRUbyhuLHIpIHtcbiAgdmFyIGk7XG4gIGZvcihpID0gdGhpcy50LTE7IGkgPj0gMDsgLS1pKSByW2krbl0gPSB0aGlzW2ldO1xuICBmb3IoaSA9IG4tMTsgaSA+PSAwOyAtLWkpIHJbaV0gPSAwO1xuICByLnQgPSB0aGlzLnQrbjtcbiAgci5zID0gdGhpcy5zO1xufVxuXG4vLyAocHJvdGVjdGVkKSByID0gdGhpcyA+PiBuKkRCXG5mdW5jdGlvbiBibnBEUlNoaWZ0VG8obixyKSB7XG4gIGZvcih2YXIgaSA9IG47IGkgPCB0aGlzLnQ7ICsraSkgcltpLW5dID0gdGhpc1tpXTtcbiAgci50ID0gTWF0aC5tYXgodGhpcy50LW4sMCk7XG4gIHIucyA9IHRoaXMucztcbn1cblxuLy8gKHByb3RlY3RlZCkgciA9IHRoaXMgPDwgblxuZnVuY3Rpb24gYm5wTFNoaWZ0VG8obixyKSB7XG4gIHZhciBicyA9IG4ldGhpcy5EQjtcbiAgdmFyIGNicyA9IHRoaXMuREItYnM7XG4gIHZhciBibSA9ICgxPDxjYnMpLTE7XG4gIHZhciBkcyA9IE1hdGguZmxvb3Iobi90aGlzLkRCKSwgYyA9ICh0aGlzLnM8PGJzKSZ0aGlzLkRNLCBpO1xuICBmb3IoaSA9IHRoaXMudC0xOyBpID49IDA7IC0taSkge1xuICAgIHJbaStkcysxXSA9ICh0aGlzW2ldPj5jYnMpfGM7XG4gICAgYyA9ICh0aGlzW2ldJmJtKTw8YnM7XG4gIH1cbiAgZm9yKGkgPSBkcy0xOyBpID49IDA7IC0taSkgcltpXSA9IDA7XG4gIHJbZHNdID0gYztcbiAgci50ID0gdGhpcy50K2RzKzE7XG4gIHIucyA9IHRoaXMucztcbiAgci5jbGFtcCgpO1xufVxuXG4vLyAocHJvdGVjdGVkKSByID0gdGhpcyA+PiBuXG5mdW5jdGlvbiBibnBSU2hpZnRUbyhuLHIpIHtcbiAgci5zID0gdGhpcy5zO1xuICB2YXIgZHMgPSBNYXRoLmZsb29yKG4vdGhpcy5EQik7XG4gIGlmKGRzID49IHRoaXMudCkgeyByLnQgPSAwOyByZXR1cm47IH1cbiAgdmFyIGJzID0gbiV0aGlzLkRCO1xuICB2YXIgY2JzID0gdGhpcy5EQi1icztcbiAgdmFyIGJtID0gKDE8PGJzKS0xO1xuICByWzBdID0gdGhpc1tkc10+PmJzO1xuICBmb3IodmFyIGkgPSBkcysxOyBpIDwgdGhpcy50OyArK2kpIHtcbiAgICByW2ktZHMtMV0gfD0gKHRoaXNbaV0mYm0pPDxjYnM7XG4gICAgcltpLWRzXSA9IHRoaXNbaV0+PmJzO1xuICB9XG4gIGlmKGJzID4gMCkgclt0aGlzLnQtZHMtMV0gfD0gKHRoaXMucyZibSk8PGNicztcbiAgci50ID0gdGhpcy50LWRzO1xuICByLmNsYW1wKCk7XG59XG5cbi8vIChwcm90ZWN0ZWQpIHIgPSB0aGlzIC0gYVxuZnVuY3Rpb24gYm5wU3ViVG8oYSxyKSB7XG4gIHZhciBpID0gMCwgYyA9IDAsIG0gPSBNYXRoLm1pbihhLnQsdGhpcy50KTtcbiAgd2hpbGUoaSA8IG0pIHtcbiAgICBjICs9IHRoaXNbaV0tYVtpXTtcbiAgICByW2krK10gPSBjJnRoaXMuRE07XG4gICAgYyA+Pj0gdGhpcy5EQjtcbiAgfVxuICBpZihhLnQgPCB0aGlzLnQpIHtcbiAgICBjIC09IGEucztcbiAgICB3aGlsZShpIDwgdGhpcy50KSB7XG4gICAgICBjICs9IHRoaXNbaV07XG4gICAgICByW2krK10gPSBjJnRoaXMuRE07XG4gICAgICBjID4+PSB0aGlzLkRCO1xuICAgIH1cbiAgICBjICs9IHRoaXMucztcbiAgfVxuICBlbHNlIHtcbiAgICBjICs9IHRoaXMucztcbiAgICB3aGlsZShpIDwgYS50KSB7XG4gICAgICBjIC09IGFbaV07XG4gICAgICByW2krK10gPSBjJnRoaXMuRE07XG4gICAgICBjID4+PSB0aGlzLkRCO1xuICAgIH1cbiAgICBjIC09IGEucztcbiAgfVxuICByLnMgPSAoYzwwKT8tMTowO1xuICBpZihjIDwgLTEpIHJbaSsrXSA9IHRoaXMuRFYrYztcbiAgZWxzZSBpZihjID4gMCkgcltpKytdID0gYztcbiAgci50ID0gaTtcbiAgci5jbGFtcCgpO1xufVxuXG4vLyAocHJvdGVjdGVkKSByID0gdGhpcyAqIGEsIHIgIT0gdGhpcyxhIChIQUMgMTQuMTIpXG4vLyBcInRoaXNcIiBzaG91bGQgYmUgdGhlIGxhcmdlciBvbmUgaWYgYXBwcm9wcmlhdGUuXG5mdW5jdGlvbiBibnBNdWx0aXBseVRvKGEscikge1xuICB2YXIgeCA9IHRoaXMuYWJzKCksIHkgPSBhLmFicygpO1xuICB2YXIgaSA9IHgudDtcbiAgci50ID0gaSt5LnQ7XG4gIHdoaWxlKC0taSA+PSAwKSByW2ldID0gMDtcbiAgZm9yKGkgPSAwOyBpIDwgeS50OyArK2kpIHJbaSt4LnRdID0geC5hbSgwLHlbaV0scixpLDAseC50KTtcbiAgci5zID0gMDtcbiAgci5jbGFtcCgpO1xuICBpZih0aGlzLnMgIT0gYS5zKSBCaWdJbnRlZ2VyLlpFUk8uc3ViVG8ocixyKTtcbn1cblxuLy8gKHByb3RlY3RlZCkgciA9IHRoaXNeMiwgciAhPSB0aGlzIChIQUMgMTQuMTYpXG5mdW5jdGlvbiBibnBTcXVhcmVUbyhyKSB7XG4gIHZhciB4ID0gdGhpcy5hYnMoKTtcbiAgdmFyIGkgPSByLnQgPSAyKngudDtcbiAgd2hpbGUoLS1pID49IDApIHJbaV0gPSAwO1xuICBmb3IoaSA9IDA7IGkgPCB4LnQtMTsgKytpKSB7XG4gICAgdmFyIGMgPSB4LmFtKGkseFtpXSxyLDIqaSwwLDEpO1xuICAgIGlmKChyW2kreC50XSs9eC5hbShpKzEsMip4W2ldLHIsMippKzEsYyx4LnQtaS0xKSkgPj0geC5EVikge1xuICAgICAgcltpK3gudF0gLT0geC5EVjtcbiAgICAgIHJbaSt4LnQrMV0gPSAxO1xuICAgIH1cbiAgfVxuICBpZihyLnQgPiAwKSByW3IudC0xXSArPSB4LmFtKGkseFtpXSxyLDIqaSwwLDEpO1xuICByLnMgPSAwO1xuICByLmNsYW1wKCk7XG59XG5cbi8vIChwcm90ZWN0ZWQpIGRpdmlkZSB0aGlzIGJ5IG0sIHF1b3RpZW50IGFuZCByZW1haW5kZXIgdG8gcSwgciAoSEFDIDE0LjIwKVxuLy8gciAhPSBxLCB0aGlzICE9IG0uICBxIG9yIHIgbWF5IGJlIG51bGwuXG5mdW5jdGlvbiBibnBEaXZSZW1UbyhtLHEscikge1xuICB2YXIgcG0gPSBtLmFicygpO1xuICBpZihwbS50IDw9IDApIHJldHVybjtcbiAgdmFyIHB0ID0gdGhpcy5hYnMoKTtcbiAgaWYocHQudCA8IHBtLnQpIHtcbiAgICBpZihxICE9IG51bGwpIHEuZnJvbUludCgwKTtcbiAgICBpZihyICE9IG51bGwpIHRoaXMuY29weVRvKHIpO1xuICAgIHJldHVybjtcbiAgfVxuICBpZihyID09IG51bGwpIHIgPSBuYmkoKTtcbiAgdmFyIHkgPSBuYmkoKSwgdHMgPSB0aGlzLnMsIG1zID0gbS5zO1xuICB2YXIgbnNoID0gdGhpcy5EQi1uYml0cyhwbVtwbS50LTFdKTtcdC8vIG5vcm1hbGl6ZSBtb2R1bHVzXG4gIGlmKG5zaCA+IDApIHsgcG0ubFNoaWZ0VG8obnNoLHkpOyBwdC5sU2hpZnRUbyhuc2gscik7IH1cbiAgZWxzZSB7IHBtLmNvcHlUbyh5KTsgcHQuY29weVRvKHIpOyB9XG4gIHZhciB5cyA9IHkudDtcbiAgdmFyIHkwID0geVt5cy0xXTtcbiAgaWYoeTAgPT0gMCkgcmV0dXJuO1xuICB2YXIgeXQgPSB5MCooMTw8dGhpcy5GMSkrKCh5cz4xKT95W3lzLTJdPj50aGlzLkYyOjApO1xuICB2YXIgZDEgPSB0aGlzLkZWL3l0LCBkMiA9ICgxPDx0aGlzLkYxKS95dCwgZSA9IDE8PHRoaXMuRjI7XG4gIHZhciBpID0gci50LCBqID0gaS15cywgdCA9IChxPT1udWxsKT9uYmkoKTpxO1xuICB5LmRsU2hpZnRUbyhqLHQpO1xuICBpZihyLmNvbXBhcmVUbyh0KSA+PSAwKSB7XG4gICAgcltyLnQrK10gPSAxO1xuICAgIHIuc3ViVG8odCxyKTtcbiAgfVxuICBCaWdJbnRlZ2VyLk9ORS5kbFNoaWZ0VG8oeXMsdCk7XG4gIHQuc3ViVG8oeSx5KTtcdC8vIFwibmVnYXRpdmVcIiB5IHNvIHdlIGNhbiByZXBsYWNlIHN1YiB3aXRoIGFtIGxhdGVyXG4gIHdoaWxlKHkudCA8IHlzKSB5W3kudCsrXSA9IDA7XG4gIHdoaWxlKC0taiA+PSAwKSB7XG4gICAgLy8gRXN0aW1hdGUgcXVvdGllbnQgZGlnaXRcbiAgICB2YXIgcWQgPSAoclstLWldPT15MCk/dGhpcy5ETTpNYXRoLmZsb29yKHJbaV0qZDErKHJbaS0xXStlKSpkMik7XG4gICAgaWYoKHJbaV0rPXkuYW0oMCxxZCxyLGosMCx5cykpIDwgcWQpIHtcdC8vIFRyeSBpdCBvdXRcbiAgICAgIHkuZGxTaGlmdFRvKGosdCk7XG4gICAgICByLnN1YlRvKHQscik7XG4gICAgICB3aGlsZShyW2ldIDwgLS1xZCkgci5zdWJUbyh0LHIpO1xuICAgIH1cbiAgfVxuICBpZihxICE9IG51bGwpIHtcbiAgICByLmRyU2hpZnRUbyh5cyxxKTtcbiAgICBpZih0cyAhPSBtcykgQmlnSW50ZWdlci5aRVJPLnN1YlRvKHEscSk7XG4gIH1cbiAgci50ID0geXM7XG4gIHIuY2xhbXAoKTtcbiAgaWYobnNoID4gMCkgci5yU2hpZnRUbyhuc2gscik7XHQvLyBEZW5vcm1hbGl6ZSByZW1haW5kZXJcbiAgaWYodHMgPCAwKSBCaWdJbnRlZ2VyLlpFUk8uc3ViVG8ocixyKTtcbn1cblxuLy8gKHB1YmxpYykgdGhpcyBtb2QgYVxuZnVuY3Rpb24gYm5Nb2QoYSkge1xuICB2YXIgciA9IG5iaSgpO1xuICB0aGlzLmFicygpLmRpdlJlbVRvKGEsbnVsbCxyKTtcbiAgaWYodGhpcy5zIDwgMCAmJiByLmNvbXBhcmVUbyhCaWdJbnRlZ2VyLlpFUk8pID4gMCkgYS5zdWJUbyhyLHIpO1xuICByZXR1cm4gcjtcbn1cblxuLy8gTW9kdWxhciByZWR1Y3Rpb24gdXNpbmcgXCJjbGFzc2ljXCIgYWxnb3JpdGhtXG5mdW5jdGlvbiBDbGFzc2ljKG0pIHsgdGhpcy5tID0gbTsgfVxuZnVuY3Rpb24gY0NvbnZlcnQoeCkge1xuICBpZih4LnMgPCAwIHx8IHguY29tcGFyZVRvKHRoaXMubSkgPj0gMCkgcmV0dXJuIHgubW9kKHRoaXMubSk7XG4gIGVsc2UgcmV0dXJuIHg7XG59XG5mdW5jdGlvbiBjUmV2ZXJ0KHgpIHsgcmV0dXJuIHg7IH1cbmZ1bmN0aW9uIGNSZWR1Y2UoeCkgeyB4LmRpdlJlbVRvKHRoaXMubSxudWxsLHgpOyB9XG5mdW5jdGlvbiBjTXVsVG8oeCx5LHIpIHsgeC5tdWx0aXBseVRvKHkscik7IHRoaXMucmVkdWNlKHIpOyB9XG5mdW5jdGlvbiBjU3FyVG8oeCxyKSB7IHguc3F1YXJlVG8ocik7IHRoaXMucmVkdWNlKHIpOyB9XG5cbkNsYXNzaWMucHJvdG90eXBlLmNvbnZlcnQgPSBjQ29udmVydDtcbkNsYXNzaWMucHJvdG90eXBlLnJldmVydCA9IGNSZXZlcnQ7XG5DbGFzc2ljLnByb3RvdHlwZS5yZWR1Y2UgPSBjUmVkdWNlO1xuQ2xhc3NpYy5wcm90b3R5cGUubXVsVG8gPSBjTXVsVG87XG5DbGFzc2ljLnByb3RvdHlwZS5zcXJUbyA9IGNTcXJUbztcblxuLy8gKHByb3RlY3RlZCkgcmV0dXJuIFwiLTEvdGhpcyAlIDJeREJcIjsgdXNlZnVsIGZvciBNb250LiByZWR1Y3Rpb25cbi8vIGp1c3RpZmljYXRpb246XG4vLyAgICAgICAgIHh5ID09IDEgKG1vZCBtKVxuLy8gICAgICAgICB4eSA9ICAxK2ttXG4vLyAgIHh5KDIteHkpID0gKDEra20pKDEta20pXG4vLyB4W3koMi14eSldID0gMS1rXjJtXjJcbi8vIHhbeSgyLXh5KV0gPT0gMSAobW9kIG1eMilcbi8vIGlmIHkgaXMgMS94IG1vZCBtLCB0aGVuIHkoMi14eSkgaXMgMS94IG1vZCBtXjJcbi8vIHNob3VsZCByZWR1Y2UgeCBhbmQgeSgyLXh5KSBieSBtXjIgYXQgZWFjaCBzdGVwIHRvIGtlZXAgc2l6ZSBib3VuZGVkLlxuLy8gSlMgbXVsdGlwbHkgXCJvdmVyZmxvd3NcIiBkaWZmZXJlbnRseSBmcm9tIEMvQysrLCBzbyBjYXJlIGlzIG5lZWRlZCBoZXJlLlxuZnVuY3Rpb24gYm5wSW52RGlnaXQoKSB7XG4gIGlmKHRoaXMudCA8IDEpIHJldHVybiAwO1xuICB2YXIgeCA9IHRoaXNbMF07XG4gIGlmKCh4JjEpID09IDApIHJldHVybiAwO1xuICB2YXIgeSA9IHgmMztcdFx0Ly8geSA9PSAxL3ggbW9kIDJeMlxuICB5ID0gKHkqKDItKHgmMHhmKSp5KSkmMHhmO1x0Ly8geSA9PSAxL3ggbW9kIDJeNFxuICB5ID0gKHkqKDItKHgmMHhmZikqeSkpJjB4ZmY7XHQvLyB5ID09IDEveCBtb2QgMl44XG4gIHkgPSAoeSooMi0oKCh4JjB4ZmZmZikqeSkmMHhmZmZmKSkpJjB4ZmZmZjtcdC8vIHkgPT0gMS94IG1vZCAyXjE2XG4gIC8vIGxhc3Qgc3RlcCAtIGNhbGN1bGF0ZSBpbnZlcnNlIG1vZCBEViBkaXJlY3RseTtcbiAgLy8gYXNzdW1lcyAxNiA8IERCIDw9IDMyIGFuZCBhc3N1bWVzIGFiaWxpdHkgdG8gaGFuZGxlIDQ4LWJpdCBpbnRzXG4gIHkgPSAoeSooMi14KnkldGhpcy5EVikpJXRoaXMuRFY7XHRcdC8vIHkgPT0gMS94IG1vZCAyXmRiaXRzXG4gIC8vIHdlIHJlYWxseSB3YW50IHRoZSBuZWdhdGl2ZSBpbnZlcnNlLCBhbmQgLURWIDwgeSA8IERWXG4gIHJldHVybiAoeT4wKT90aGlzLkRWLXk6LXk7XG59XG5cbi8vIE1vbnRnb21lcnkgcmVkdWN0aW9uXG5mdW5jdGlvbiBNb250Z29tZXJ5KG0pIHtcbiAgdGhpcy5tID0gbTtcbiAgdGhpcy5tcCA9IG0uaW52RGlnaXQoKTtcbiAgdGhpcy5tcGwgPSB0aGlzLm1wJjB4N2ZmZjtcbiAgdGhpcy5tcGggPSB0aGlzLm1wPj4xNTtcbiAgdGhpcy51bSA9ICgxPDwobS5EQi0xNSkpLTE7XG4gIHRoaXMubXQyID0gMiptLnQ7XG59XG5cbi8vIHhSIG1vZCBtXG5mdW5jdGlvbiBtb250Q29udmVydCh4KSB7XG4gIHZhciByID0gbmJpKCk7XG4gIHguYWJzKCkuZGxTaGlmdFRvKHRoaXMubS50LHIpO1xuICByLmRpdlJlbVRvKHRoaXMubSxudWxsLHIpO1xuICBpZih4LnMgPCAwICYmIHIuY29tcGFyZVRvKEJpZ0ludGVnZXIuWkVSTykgPiAwKSB0aGlzLm0uc3ViVG8ocixyKTtcbiAgcmV0dXJuIHI7XG59XG5cbi8vIHgvUiBtb2QgbVxuZnVuY3Rpb24gbW9udFJldmVydCh4KSB7XG4gIHZhciByID0gbmJpKCk7XG4gIHguY29weVRvKHIpO1xuICB0aGlzLnJlZHVjZShyKTtcbiAgcmV0dXJuIHI7XG59XG5cbi8vIHggPSB4L1IgbW9kIG0gKEhBQyAxNC4zMilcbmZ1bmN0aW9uIG1vbnRSZWR1Y2UoeCkge1xuICB3aGlsZSh4LnQgPD0gdGhpcy5tdDIpXHQvLyBwYWQgeCBzbyBhbSBoYXMgZW5vdWdoIHJvb20gbGF0ZXJcbiAgICB4W3gudCsrXSA9IDA7XG4gIGZvcih2YXIgaSA9IDA7IGkgPCB0aGlzLm0udDsgKytpKSB7XG4gICAgLy8gZmFzdGVyIHdheSBvZiBjYWxjdWxhdGluZyB1MCA9IHhbaV0qbXAgbW9kIERWXG4gICAgdmFyIGogPSB4W2ldJjB4N2ZmZjtcbiAgICB2YXIgdTAgPSAoaip0aGlzLm1wbCsoKChqKnRoaXMubXBoKyh4W2ldPj4xNSkqdGhpcy5tcGwpJnRoaXMudW0pPDwxNSkpJnguRE07XG4gICAgLy8gdXNlIGFtIHRvIGNvbWJpbmUgdGhlIG11bHRpcGx5LXNoaWZ0LWFkZCBpbnRvIG9uZSBjYWxsXG4gICAgaiA9IGkrdGhpcy5tLnQ7XG4gICAgeFtqXSArPSB0aGlzLm0uYW0oMCx1MCx4LGksMCx0aGlzLm0udCk7XG4gICAgLy8gcHJvcGFnYXRlIGNhcnJ5XG4gICAgd2hpbGUoeFtqXSA+PSB4LkRWKSB7IHhbal0gLT0geC5EVjsgeFsrK2pdKys7IH1cbiAgfVxuICB4LmNsYW1wKCk7XG4gIHguZHJTaGlmdFRvKHRoaXMubS50LHgpO1xuICBpZih4LmNvbXBhcmVUbyh0aGlzLm0pID49IDApIHguc3ViVG8odGhpcy5tLHgpO1xufVxuXG4vLyByID0gXCJ4XjIvUiBtb2QgbVwiOyB4ICE9IHJcbmZ1bmN0aW9uIG1vbnRTcXJUbyh4LHIpIHsgeC5zcXVhcmVUbyhyKTsgdGhpcy5yZWR1Y2Uocik7IH1cblxuLy8gciA9IFwieHkvUiBtb2QgbVwiOyB4LHkgIT0gclxuZnVuY3Rpb24gbW9udE11bFRvKHgseSxyKSB7IHgubXVsdGlwbHlUbyh5LHIpOyB0aGlzLnJlZHVjZShyKTsgfVxuXG5Nb250Z29tZXJ5LnByb3RvdHlwZS5jb252ZXJ0ID0gbW9udENvbnZlcnQ7XG5Nb250Z29tZXJ5LnByb3RvdHlwZS5yZXZlcnQgPSBtb250UmV2ZXJ0O1xuTW9udGdvbWVyeS5wcm90b3R5cGUucmVkdWNlID0gbW9udFJlZHVjZTtcbk1vbnRnb21lcnkucHJvdG90eXBlLm11bFRvID0gbW9udE11bFRvO1xuTW9udGdvbWVyeS5wcm90b3R5cGUuc3FyVG8gPSBtb250U3FyVG87XG5cbi8vIChwcm90ZWN0ZWQpIHRydWUgaWZmIHRoaXMgaXMgZXZlblxuZnVuY3Rpb24gYm5wSXNFdmVuKCkgeyByZXR1cm4gKCh0aGlzLnQ+MCk/KHRoaXNbMF0mMSk6dGhpcy5zKSA9PSAwOyB9XG5cbi8vIChwcm90ZWN0ZWQpIHRoaXNeZSwgZSA8IDJeMzIsIGRvaW5nIHNxciBhbmQgbXVsIHdpdGggXCJyXCIgKEhBQyAxNC43OSlcbmZ1bmN0aW9uIGJucEV4cChlLHopIHtcbiAgaWYoZSA+IDB4ZmZmZmZmZmYgfHwgZSA8IDEpIHJldHVybiBCaWdJbnRlZ2VyLk9ORTtcbiAgdmFyIHIgPSBuYmkoKSwgcjIgPSBuYmkoKSwgZyA9IHouY29udmVydCh0aGlzKSwgaSA9IG5iaXRzKGUpLTE7XG4gIGcuY29weVRvKHIpO1xuICB3aGlsZSgtLWkgPj0gMCkge1xuICAgIHouc3FyVG8ocixyMik7XG4gICAgaWYoKGUmKDE8PGkpKSA+IDApIHoubXVsVG8ocjIsZyxyKTtcbiAgICBlbHNlIHsgdmFyIHQgPSByOyByID0gcjI7IHIyID0gdDsgfVxuICB9XG4gIHJldHVybiB6LnJldmVydChyKTtcbn1cblxuLy8gKHB1YmxpYykgdGhpc15lICUgbSwgMCA8PSBlIDwgMl4zMlxuZnVuY3Rpb24gYm5Nb2RQb3dJbnQoZSxtKSB7XG4gIHZhciB6O1xuICBpZihlIDwgMjU2IHx8IG0uaXNFdmVuKCkpIHogPSBuZXcgQ2xhc3NpYyhtKTsgZWxzZSB6ID0gbmV3IE1vbnRnb21lcnkobSk7XG4gIHJldHVybiB0aGlzLmV4cChlLHopO1xufVxuXG4vLyBwcm90ZWN0ZWRcbkJpZ0ludGVnZXIucHJvdG90eXBlLmNvcHlUbyA9IGJucENvcHlUbztcbkJpZ0ludGVnZXIucHJvdG90eXBlLmZyb21JbnQgPSBibnBGcm9tSW50O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZnJvbVN0cmluZyA9IGJucEZyb21TdHJpbmc7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5jbGFtcCA9IGJucENsYW1wO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZGxTaGlmdFRvID0gYm5wRExTaGlmdFRvO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZHJTaGlmdFRvID0gYm5wRFJTaGlmdFRvO1xuQmlnSW50ZWdlci5wcm90b3R5cGUubFNoaWZ0VG8gPSBibnBMU2hpZnRUbztcbkJpZ0ludGVnZXIucHJvdG90eXBlLnJTaGlmdFRvID0gYm5wUlNoaWZ0VG87XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5zdWJUbyA9IGJucFN1YlRvO1xuQmlnSW50ZWdlci5wcm90b3R5cGUubXVsdGlwbHlUbyA9IGJucE11bHRpcGx5VG87XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5zcXVhcmVUbyA9IGJucFNxdWFyZVRvO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZGl2UmVtVG8gPSBibnBEaXZSZW1UbztcbkJpZ0ludGVnZXIucHJvdG90eXBlLmludkRpZ2l0ID0gYm5wSW52RGlnaXQ7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5pc0V2ZW4gPSBibnBJc0V2ZW47XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5leHAgPSBibnBFeHA7XG5cbi8vIHB1YmxpY1xuQmlnSW50ZWdlci5wcm90b3R5cGUudG9TdHJpbmcgPSBiblRvU3RyaW5nO1xuQmlnSW50ZWdlci5wcm90b3R5cGUubmVnYXRlID0gYm5OZWdhdGU7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5hYnMgPSBibkFicztcbkJpZ0ludGVnZXIucHJvdG90eXBlLmNvbXBhcmVUbyA9IGJuQ29tcGFyZVRvO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuYml0TGVuZ3RoID0gYm5CaXRMZW5ndGg7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5tb2QgPSBibk1vZDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLm1vZFBvd0ludCA9IGJuTW9kUG93SW50O1xuXG4vLyBcImNvbnN0YW50c1wiXG5CaWdJbnRlZ2VyLlpFUk8gPSBuYnYoMCk7XG5CaWdJbnRlZ2VyLk9ORSA9IG5idigxKTtcblxuLy8gQ29weXJpZ2h0IChjKSAyMDA1LTIwMDkgIFRvbSBXdVxuLy8gQWxsIFJpZ2h0cyBSZXNlcnZlZC5cbi8vIFNlZSBcIkxJQ0VOU0VcIiBmb3IgZGV0YWlscy5cblxuLy8gRXh0ZW5kZWQgSmF2YVNjcmlwdCBCTiBmdW5jdGlvbnMsIHJlcXVpcmVkIGZvciBSU0EgcHJpdmF0ZSBvcHMuXG5cbi8vIFZlcnNpb24gMS4xOiBuZXcgQmlnSW50ZWdlcihcIjBcIiwgMTApIHJldHVybnMgXCJwcm9wZXJcIiB6ZXJvXG4vLyBWZXJzaW9uIDEuMjogc3F1YXJlKCkgQVBJLCBpc1Byb2JhYmxlUHJpbWUgZml4XG5cbi8vIChwdWJsaWMpXG5mdW5jdGlvbiBibkNsb25lKCkgeyB2YXIgciA9IG5iaSgpOyB0aGlzLmNvcHlUbyhyKTsgcmV0dXJuIHI7IH1cblxuLy8gKHB1YmxpYykgcmV0dXJuIHZhbHVlIGFzIGludGVnZXJcbmZ1bmN0aW9uIGJuSW50VmFsdWUoKSB7XG4gIGlmKHRoaXMucyA8IDApIHtcbiAgICBpZih0aGlzLnQgPT0gMSkgcmV0dXJuIHRoaXNbMF0tdGhpcy5EVjtcbiAgICBlbHNlIGlmKHRoaXMudCA9PSAwKSByZXR1cm4gLTE7XG4gIH1cbiAgZWxzZSBpZih0aGlzLnQgPT0gMSkgcmV0dXJuIHRoaXNbMF07XG4gIGVsc2UgaWYodGhpcy50ID09IDApIHJldHVybiAwO1xuICAvLyBhc3N1bWVzIDE2IDwgREIgPCAzMlxuICByZXR1cm4gKCh0aGlzWzFdJigoMTw8KDMyLXRoaXMuREIpKS0xKSk8PHRoaXMuREIpfHRoaXNbMF07XG59XG5cbi8vIChwdWJsaWMpIHJldHVybiB2YWx1ZSBhcyBieXRlXG5mdW5jdGlvbiBibkJ5dGVWYWx1ZSgpIHsgcmV0dXJuICh0aGlzLnQ9PTApP3RoaXMuczoodGhpc1swXTw8MjQpPj4yNDsgfVxuXG4vLyAocHVibGljKSByZXR1cm4gdmFsdWUgYXMgc2hvcnQgKGFzc3VtZXMgREI+PTE2KVxuZnVuY3Rpb24gYm5TaG9ydFZhbHVlKCkgeyByZXR1cm4gKHRoaXMudD09MCk/dGhpcy5zOih0aGlzWzBdPDwxNik+PjE2OyB9XG5cbi8vIChwcm90ZWN0ZWQpIHJldHVybiB4IHMudC4gcl54IDwgRFZcbmZ1bmN0aW9uIGJucENodW5rU2l6ZShyKSB7IHJldHVybiBNYXRoLmZsb29yKE1hdGguTE4yKnRoaXMuREIvTWF0aC5sb2cocikpOyB9XG5cbi8vIChwdWJsaWMpIDAgaWYgdGhpcyA9PSAwLCAxIGlmIHRoaXMgPiAwXG5mdW5jdGlvbiBiblNpZ051bSgpIHtcbiAgaWYodGhpcy5zIDwgMCkgcmV0dXJuIC0xO1xuICBlbHNlIGlmKHRoaXMudCA8PSAwIHx8ICh0aGlzLnQgPT0gMSAmJiB0aGlzWzBdIDw9IDApKSByZXR1cm4gMDtcbiAgZWxzZSByZXR1cm4gMTtcbn1cblxuLy8gKHByb3RlY3RlZCkgY29udmVydCB0byByYWRpeCBzdHJpbmdcbmZ1bmN0aW9uIGJucFRvUmFkaXgoYikge1xuICBpZihiID09IG51bGwpIGIgPSAxMDtcbiAgaWYodGhpcy5zaWdudW0oKSA9PSAwIHx8IGIgPCAyIHx8IGIgPiAzNikgcmV0dXJuIFwiMFwiO1xuICB2YXIgY3MgPSB0aGlzLmNodW5rU2l6ZShiKTtcbiAgdmFyIGEgPSBNYXRoLnBvdyhiLGNzKTtcbiAgdmFyIGQgPSBuYnYoYSksIHkgPSBuYmkoKSwgeiA9IG5iaSgpLCByID0gXCJcIjtcbiAgdGhpcy5kaXZSZW1UbyhkLHkseik7XG4gIHdoaWxlKHkuc2lnbnVtKCkgPiAwKSB7XG4gICAgciA9IChhK3ouaW50VmFsdWUoKSkudG9TdHJpbmcoYikuc3Vic3RyKDEpICsgcjtcbiAgICB5LmRpdlJlbVRvKGQseSx6KTtcbiAgfVxuICByZXR1cm4gei5pbnRWYWx1ZSgpLnRvU3RyaW5nKGIpICsgcjtcbn1cblxuLy8gKHByb3RlY3RlZCkgY29udmVydCBmcm9tIHJhZGl4IHN0cmluZ1xuZnVuY3Rpb24gYm5wRnJvbVJhZGl4KHMsYikge1xuICB0aGlzLmZyb21JbnQoMCk7XG4gIGlmKGIgPT0gbnVsbCkgYiA9IDEwO1xuICB2YXIgY3MgPSB0aGlzLmNodW5rU2l6ZShiKTtcbiAgdmFyIGQgPSBNYXRoLnBvdyhiLGNzKSwgbWkgPSBmYWxzZSwgaiA9IDAsIHcgPSAwO1xuICBmb3IodmFyIGkgPSAwOyBpIDwgcy5sZW5ndGg7ICsraSkge1xuICAgIHZhciB4ID0gaW50QXQocyxpKTtcbiAgICBpZih4IDwgMCkge1xuICAgICAgaWYocy5jaGFyQXQoaSkgPT0gXCItXCIgJiYgdGhpcy5zaWdudW0oKSA9PSAwKSBtaSA9IHRydWU7XG4gICAgICBjb250aW51ZTtcbiAgICB9XG4gICAgdyA9IGIqdyt4O1xuICAgIGlmKCsraiA+PSBjcykge1xuICAgICAgdGhpcy5kTXVsdGlwbHkoZCk7XG4gICAgICB0aGlzLmRBZGRPZmZzZXQodywwKTtcbiAgICAgIGogPSAwO1xuICAgICAgdyA9IDA7XG4gICAgfVxuICB9XG4gIGlmKGogPiAwKSB7XG4gICAgdGhpcy5kTXVsdGlwbHkoTWF0aC5wb3coYixqKSk7XG4gICAgdGhpcy5kQWRkT2Zmc2V0KHcsMCk7XG4gIH1cbiAgaWYobWkpIEJpZ0ludGVnZXIuWkVSTy5zdWJUbyh0aGlzLHRoaXMpO1xufVxuXG4vLyAocHJvdGVjdGVkKSBhbHRlcm5hdGUgY29uc3RydWN0b3JcbmZ1bmN0aW9uIGJucEZyb21OdW1iZXIoYSxiLGMpIHtcbiAgaWYoXCJudW1iZXJcIiA9PSB0eXBlb2YgYikge1xuICAgIC8vIG5ldyBCaWdJbnRlZ2VyKGludCxpbnQsUk5HKVxuICAgIGlmKGEgPCAyKSB0aGlzLmZyb21JbnQoMSk7XG4gICAgZWxzZSB7XG4gICAgICB0aGlzLmZyb21OdW1iZXIoYSxjKTtcbiAgICAgIGlmKCF0aGlzLnRlc3RCaXQoYS0xKSlcdC8vIGZvcmNlIE1TQiBzZXRcbiAgICAgICAgdGhpcy5iaXR3aXNlVG8oQmlnSW50ZWdlci5PTkUuc2hpZnRMZWZ0KGEtMSksb3Bfb3IsdGhpcyk7XG4gICAgICBpZih0aGlzLmlzRXZlbigpKSB0aGlzLmRBZGRPZmZzZXQoMSwwKTsgLy8gZm9yY2Ugb2RkXG4gICAgICB3aGlsZSghdGhpcy5pc1Byb2JhYmxlUHJpbWUoYikpIHtcbiAgICAgICAgdGhpcy5kQWRkT2Zmc2V0KDIsMCk7XG4gICAgICAgIGlmKHRoaXMuYml0TGVuZ3RoKCkgPiBhKSB0aGlzLnN1YlRvKEJpZ0ludGVnZXIuT05FLnNoaWZ0TGVmdChhLTEpLHRoaXMpO1xuICAgICAgfVxuICAgIH1cbiAgfVxuICBlbHNlIHtcbiAgICAvLyBuZXcgQmlnSW50ZWdlcihpbnQsUk5HKVxuICAgIHZhciB4ID0gbmV3IEFycmF5KCksIHQgPSBhJjc7XG4gICAgeC5sZW5ndGggPSAoYT4+MykrMTtcbiAgICBiLm5leHRCeXRlcyh4KTtcbiAgICBpZih0ID4gMCkgeFswXSAmPSAoKDE8PHQpLTEpOyBlbHNlIHhbMF0gPSAwO1xuICAgIHRoaXMuZnJvbVN0cmluZyh4LDI1Nik7XG4gIH1cbn1cblxuLy8gKHB1YmxpYykgY29udmVydCB0byBiaWdlbmRpYW4gYnl0ZSBhcnJheVxuZnVuY3Rpb24gYm5Ub0J5dGVBcnJheSgpIHtcbiAgdmFyIGkgPSB0aGlzLnQsIHIgPSBuZXcgQXJyYXkoKTtcbiAgclswXSA9IHRoaXMucztcbiAgdmFyIHAgPSB0aGlzLkRCLShpKnRoaXMuREIpJTgsIGQsIGsgPSAwO1xuICBpZihpLS0gPiAwKSB7XG4gICAgaWYocCA8IHRoaXMuREIgJiYgKGQgPSB0aGlzW2ldPj5wKSAhPSAodGhpcy5zJnRoaXMuRE0pPj5wKVxuICAgICAgcltrKytdID0gZHwodGhpcy5zPDwodGhpcy5EQi1wKSk7XG4gICAgd2hpbGUoaSA+PSAwKSB7XG4gICAgICBpZihwIDwgOCkge1xuICAgICAgICBkID0gKHRoaXNbaV0mKCgxPDxwKS0xKSk8PCg4LXApO1xuICAgICAgICBkIHw9IHRoaXNbLS1pXT4+KHArPXRoaXMuREItOCk7XG4gICAgICB9XG4gICAgICBlbHNlIHtcbiAgICAgICAgZCA9ICh0aGlzW2ldPj4ocC09OCkpJjB4ZmY7XG4gICAgICAgIGlmKHAgPD0gMCkgeyBwICs9IHRoaXMuREI7IC0taTsgfVxuICAgICAgfVxuICAgICAgaWYoKGQmMHg4MCkgIT0gMCkgZCB8PSAtMjU2O1xuICAgICAgaWYoayA9PSAwICYmICh0aGlzLnMmMHg4MCkgIT0gKGQmMHg4MCkpICsraztcbiAgICAgIGlmKGsgPiAwIHx8IGQgIT0gdGhpcy5zKSByW2srK10gPSBkO1xuICAgIH1cbiAgfVxuICByZXR1cm4gcjtcbn1cblxuZnVuY3Rpb24gYm5FcXVhbHMoYSkgeyByZXR1cm4odGhpcy5jb21wYXJlVG8oYSk9PTApOyB9XG5mdW5jdGlvbiBibk1pbihhKSB7IHJldHVybih0aGlzLmNvbXBhcmVUbyhhKTwwKT90aGlzOmE7IH1cbmZ1bmN0aW9uIGJuTWF4KGEpIHsgcmV0dXJuKHRoaXMuY29tcGFyZVRvKGEpPjApP3RoaXM6YTsgfVxuXG4vLyAocHJvdGVjdGVkKSByID0gdGhpcyBvcCBhIChiaXR3aXNlKVxuZnVuY3Rpb24gYm5wQml0d2lzZVRvKGEsb3Ascikge1xuICB2YXIgaSwgZiwgbSA9IE1hdGgubWluKGEudCx0aGlzLnQpO1xuICBmb3IoaSA9IDA7IGkgPCBtOyArK2kpIHJbaV0gPSBvcCh0aGlzW2ldLGFbaV0pO1xuICBpZihhLnQgPCB0aGlzLnQpIHtcbiAgICBmID0gYS5zJnRoaXMuRE07XG4gICAgZm9yKGkgPSBtOyBpIDwgdGhpcy50OyArK2kpIHJbaV0gPSBvcCh0aGlzW2ldLGYpO1xuICAgIHIudCA9IHRoaXMudDtcbiAgfVxuICBlbHNlIHtcbiAgICBmID0gdGhpcy5zJnRoaXMuRE07XG4gICAgZm9yKGkgPSBtOyBpIDwgYS50OyArK2kpIHJbaV0gPSBvcChmLGFbaV0pO1xuICAgIHIudCA9IGEudDtcbiAgfVxuICByLnMgPSBvcCh0aGlzLnMsYS5zKTtcbiAgci5jbGFtcCgpO1xufVxuXG4vLyAocHVibGljKSB0aGlzICYgYVxuZnVuY3Rpb24gb3BfYW5kKHgseSkgeyByZXR1cm4geCZ5OyB9XG5mdW5jdGlvbiBibkFuZChhKSB7IHZhciByID0gbmJpKCk7IHRoaXMuYml0d2lzZVRvKGEsb3BfYW5kLHIpOyByZXR1cm4gcjsgfVxuXG4vLyAocHVibGljKSB0aGlzIHwgYVxuZnVuY3Rpb24gb3Bfb3IoeCx5KSB7IHJldHVybiB4fHk7IH1cbmZ1bmN0aW9uIGJuT3IoYSkgeyB2YXIgciA9IG5iaSgpOyB0aGlzLmJpdHdpc2VUbyhhLG9wX29yLHIpOyByZXR1cm4gcjsgfVxuXG4vLyAocHVibGljKSB0aGlzIF4gYVxuZnVuY3Rpb24gb3BfeG9yKHgseSkgeyByZXR1cm4geF55OyB9XG5mdW5jdGlvbiBiblhvcihhKSB7IHZhciByID0gbmJpKCk7IHRoaXMuYml0d2lzZVRvKGEsb3BfeG9yLHIpOyByZXR1cm4gcjsgfVxuXG4vLyAocHVibGljKSB0aGlzICYgfmFcbmZ1bmN0aW9uIG9wX2FuZG5vdCh4LHkpIHsgcmV0dXJuIHgmfnk7IH1cbmZ1bmN0aW9uIGJuQW5kTm90KGEpIHsgdmFyIHIgPSBuYmkoKTsgdGhpcy5iaXR3aXNlVG8oYSxvcF9hbmRub3Qscik7IHJldHVybiByOyB9XG5cbi8vIChwdWJsaWMpIH50aGlzXG5mdW5jdGlvbiBibk5vdCgpIHtcbiAgdmFyIHIgPSBuYmkoKTtcbiAgZm9yKHZhciBpID0gMDsgaSA8IHRoaXMudDsgKytpKSByW2ldID0gdGhpcy5ETSZ+dGhpc1tpXTtcbiAgci50ID0gdGhpcy50O1xuICByLnMgPSB+dGhpcy5zO1xuICByZXR1cm4gcjtcbn1cblxuLy8gKHB1YmxpYykgdGhpcyA8PCBuXG5mdW5jdGlvbiBiblNoaWZ0TGVmdChuKSB7XG4gIHZhciByID0gbmJpKCk7XG4gIGlmKG4gPCAwKSB0aGlzLnJTaGlmdFRvKC1uLHIpOyBlbHNlIHRoaXMubFNoaWZ0VG8obixyKTtcbiAgcmV0dXJuIHI7XG59XG5cbi8vIChwdWJsaWMpIHRoaXMgPj4gblxuZnVuY3Rpb24gYm5TaGlmdFJpZ2h0KG4pIHtcbiAgdmFyIHIgPSBuYmkoKTtcbiAgaWYobiA8IDApIHRoaXMubFNoaWZ0VG8oLW4scik7IGVsc2UgdGhpcy5yU2hpZnRUbyhuLHIpO1xuICByZXR1cm4gcjtcbn1cblxuLy8gcmV0dXJuIGluZGV4IG9mIGxvd2VzdCAxLWJpdCBpbiB4LCB4IDwgMl4zMVxuZnVuY3Rpb24gbGJpdCh4KSB7XG4gIGlmKHggPT0gMCkgcmV0dXJuIC0xO1xuICB2YXIgciA9IDA7XG4gIGlmKCh4JjB4ZmZmZikgPT0gMCkgeyB4ID4+PSAxNjsgciArPSAxNjsgfVxuICBpZigoeCYweGZmKSA9PSAwKSB7IHggPj49IDg7IHIgKz0gODsgfVxuICBpZigoeCYweGYpID09IDApIHsgeCA+Pj0gNDsgciArPSA0OyB9XG4gIGlmKCh4JjMpID09IDApIHsgeCA+Pj0gMjsgciArPSAyOyB9XG4gIGlmKCh4JjEpID09IDApICsrcjtcbiAgcmV0dXJuIHI7XG59XG5cbi8vIChwdWJsaWMpIHJldHVybnMgaW5kZXggb2YgbG93ZXN0IDEtYml0IChvciAtMSBpZiBub25lKVxuZnVuY3Rpb24gYm5HZXRMb3dlc3RTZXRCaXQoKSB7XG4gIGZvcih2YXIgaSA9IDA7IGkgPCB0aGlzLnQ7ICsraSlcbiAgICBpZih0aGlzW2ldICE9IDApIHJldHVybiBpKnRoaXMuREIrbGJpdCh0aGlzW2ldKTtcbiAgaWYodGhpcy5zIDwgMCkgcmV0dXJuIHRoaXMudCp0aGlzLkRCO1xuICByZXR1cm4gLTE7XG59XG5cbi8vIHJldHVybiBudW1iZXIgb2YgMSBiaXRzIGluIHhcbmZ1bmN0aW9uIGNiaXQoeCkge1xuICB2YXIgciA9IDA7XG4gIHdoaWxlKHggIT0gMCkgeyB4ICY9IHgtMTsgKytyOyB9XG4gIHJldHVybiByO1xufVxuXG4vLyAocHVibGljKSByZXR1cm4gbnVtYmVyIG9mIHNldCBiaXRzXG5mdW5jdGlvbiBibkJpdENvdW50KCkge1xuICB2YXIgciA9IDAsIHggPSB0aGlzLnMmdGhpcy5ETTtcbiAgZm9yKHZhciBpID0gMDsgaSA8IHRoaXMudDsgKytpKSByICs9IGNiaXQodGhpc1tpXV54KTtcbiAgcmV0dXJuIHI7XG59XG5cbi8vIChwdWJsaWMpIHRydWUgaWZmIG50aCBiaXQgaXMgc2V0XG5mdW5jdGlvbiBiblRlc3RCaXQobikge1xuICB2YXIgaiA9IE1hdGguZmxvb3Iobi90aGlzLkRCKTtcbiAgaWYoaiA+PSB0aGlzLnQpIHJldHVybih0aGlzLnMhPTApO1xuICByZXR1cm4oKHRoaXNbal0mKDE8PChuJXRoaXMuREIpKSkhPTApO1xufVxuXG4vLyAocHJvdGVjdGVkKSB0aGlzIG9wICgxPDxuKVxuZnVuY3Rpb24gYm5wQ2hhbmdlQml0KG4sb3ApIHtcbiAgdmFyIHIgPSBCaWdJbnRlZ2VyLk9ORS5zaGlmdExlZnQobik7XG4gIHRoaXMuYml0d2lzZVRvKHIsb3Ascik7XG4gIHJldHVybiByO1xufVxuXG4vLyAocHVibGljKSB0aGlzIHwgKDE8PG4pXG5mdW5jdGlvbiBiblNldEJpdChuKSB7IHJldHVybiB0aGlzLmNoYW5nZUJpdChuLG9wX29yKTsgfVxuXG4vLyAocHVibGljKSB0aGlzICYgfigxPDxuKVxuZnVuY3Rpb24gYm5DbGVhckJpdChuKSB7IHJldHVybiB0aGlzLmNoYW5nZUJpdChuLG9wX2FuZG5vdCk7IH1cblxuLy8gKHB1YmxpYykgdGhpcyBeICgxPDxuKVxuZnVuY3Rpb24gYm5GbGlwQml0KG4pIHsgcmV0dXJuIHRoaXMuY2hhbmdlQml0KG4sb3BfeG9yKTsgfVxuXG4vLyAocHJvdGVjdGVkKSByID0gdGhpcyArIGFcbmZ1bmN0aW9uIGJucEFkZFRvKGEscikge1xuICB2YXIgaSA9IDAsIGMgPSAwLCBtID0gTWF0aC5taW4oYS50LHRoaXMudCk7XG4gIHdoaWxlKGkgPCBtKSB7XG4gICAgYyArPSB0aGlzW2ldK2FbaV07XG4gICAgcltpKytdID0gYyZ0aGlzLkRNO1xuICAgIGMgPj49IHRoaXMuREI7XG4gIH1cbiAgaWYoYS50IDwgdGhpcy50KSB7XG4gICAgYyArPSBhLnM7XG4gICAgd2hpbGUoaSA8IHRoaXMudCkge1xuICAgICAgYyArPSB0aGlzW2ldO1xuICAgICAgcltpKytdID0gYyZ0aGlzLkRNO1xuICAgICAgYyA+Pj0gdGhpcy5EQjtcbiAgICB9XG4gICAgYyArPSB0aGlzLnM7XG4gIH1cbiAgZWxzZSB7XG4gICAgYyArPSB0aGlzLnM7XG4gICAgd2hpbGUoaSA8IGEudCkge1xuICAgICAgYyArPSBhW2ldO1xuICAgICAgcltpKytdID0gYyZ0aGlzLkRNO1xuICAgICAgYyA+Pj0gdGhpcy5EQjtcbiAgICB9XG4gICAgYyArPSBhLnM7XG4gIH1cbiAgci5zID0gKGM8MCk/LTE6MDtcbiAgaWYoYyA+IDApIHJbaSsrXSA9IGM7XG4gIGVsc2UgaWYoYyA8IC0xKSByW2krK10gPSB0aGlzLkRWK2M7XG4gIHIudCA9IGk7XG4gIHIuY2xhbXAoKTtcbn1cblxuLy8gKHB1YmxpYykgdGhpcyArIGFcbmZ1bmN0aW9uIGJuQWRkKGEpIHsgdmFyIHIgPSBuYmkoKTsgdGhpcy5hZGRUbyhhLHIpOyByZXR1cm4gcjsgfVxuXG4vLyAocHVibGljKSB0aGlzIC0gYVxuZnVuY3Rpb24gYm5TdWJ0cmFjdChhKSB7IHZhciByID0gbmJpKCk7IHRoaXMuc3ViVG8oYSxyKTsgcmV0dXJuIHI7IH1cblxuLy8gKHB1YmxpYykgdGhpcyAqIGFcbmZ1bmN0aW9uIGJuTXVsdGlwbHkoYSkgeyB2YXIgciA9IG5iaSgpOyB0aGlzLm11bHRpcGx5VG8oYSxyKTsgcmV0dXJuIHI7IH1cblxuLy8gKHB1YmxpYykgdGhpc14yXG5mdW5jdGlvbiBiblNxdWFyZSgpIHsgdmFyIHIgPSBuYmkoKTsgdGhpcy5zcXVhcmVUbyhyKTsgcmV0dXJuIHI7IH1cblxuLy8gKHB1YmxpYykgdGhpcyAvIGFcbmZ1bmN0aW9uIGJuRGl2aWRlKGEpIHsgdmFyIHIgPSBuYmkoKTsgdGhpcy5kaXZSZW1UbyhhLHIsbnVsbCk7IHJldHVybiByOyB9XG5cbi8vIChwdWJsaWMpIHRoaXMgJSBhXG5mdW5jdGlvbiBiblJlbWFpbmRlcihhKSB7IHZhciByID0gbmJpKCk7IHRoaXMuZGl2UmVtVG8oYSxudWxsLHIpOyByZXR1cm4gcjsgfVxuXG4vLyAocHVibGljKSBbdGhpcy9hLHRoaXMlYV1cbmZ1bmN0aW9uIGJuRGl2aWRlQW5kUmVtYWluZGVyKGEpIHtcbiAgdmFyIHEgPSBuYmkoKSwgciA9IG5iaSgpO1xuICB0aGlzLmRpdlJlbVRvKGEscSxyKTtcbiAgcmV0dXJuIG5ldyBBcnJheShxLHIpO1xufVxuXG4vLyAocHJvdGVjdGVkKSB0aGlzICo9IG4sIHRoaXMgPj0gMCwgMSA8IG4gPCBEVlxuZnVuY3Rpb24gYm5wRE11bHRpcGx5KG4pIHtcbiAgdGhpc1t0aGlzLnRdID0gdGhpcy5hbSgwLG4tMSx0aGlzLDAsMCx0aGlzLnQpO1xuICArK3RoaXMudDtcbiAgdGhpcy5jbGFtcCgpO1xufVxuXG4vLyAocHJvdGVjdGVkKSB0aGlzICs9IG4gPDwgdyB3b3JkcywgdGhpcyA+PSAwXG5mdW5jdGlvbiBibnBEQWRkT2Zmc2V0KG4sdykge1xuICBpZihuID09IDApIHJldHVybjtcbiAgd2hpbGUodGhpcy50IDw9IHcpIHRoaXNbdGhpcy50KytdID0gMDtcbiAgdGhpc1t3XSArPSBuO1xuICB3aGlsZSh0aGlzW3ddID49IHRoaXMuRFYpIHtcbiAgICB0aGlzW3ddIC09IHRoaXMuRFY7XG4gICAgaWYoKyt3ID49IHRoaXMudCkgdGhpc1t0aGlzLnQrK10gPSAwO1xuICAgICsrdGhpc1t3XTtcbiAgfVxufVxuXG4vLyBBIFwibnVsbFwiIHJlZHVjZXJcbmZ1bmN0aW9uIE51bGxFeHAoKSB7fVxuZnVuY3Rpb24gbk5vcCh4KSB7IHJldHVybiB4OyB9XG5mdW5jdGlvbiBuTXVsVG8oeCx5LHIpIHsgeC5tdWx0aXBseVRvKHkscik7IH1cbmZ1bmN0aW9uIG5TcXJUbyh4LHIpIHsgeC5zcXVhcmVUbyhyKTsgfVxuXG5OdWxsRXhwLnByb3RvdHlwZS5jb252ZXJ0ID0gbk5vcDtcbk51bGxFeHAucHJvdG90eXBlLnJldmVydCA9IG5Ob3A7XG5OdWxsRXhwLnByb3RvdHlwZS5tdWxUbyA9IG5NdWxUbztcbk51bGxFeHAucHJvdG90eXBlLnNxclRvID0gblNxclRvO1xuXG4vLyAocHVibGljKSB0aGlzXmVcbmZ1bmN0aW9uIGJuUG93KGUpIHsgcmV0dXJuIHRoaXMuZXhwKGUsbmV3IE51bGxFeHAoKSk7IH1cblxuLy8gKHByb3RlY3RlZCkgciA9IGxvd2VyIG4gd29yZHMgb2YgXCJ0aGlzICogYVwiLCBhLnQgPD0gblxuLy8gXCJ0aGlzXCIgc2hvdWxkIGJlIHRoZSBsYXJnZXIgb25lIGlmIGFwcHJvcHJpYXRlLlxuZnVuY3Rpb24gYm5wTXVsdGlwbHlMb3dlclRvKGEsbixyKSB7XG4gIHZhciBpID0gTWF0aC5taW4odGhpcy50K2EudCxuKTtcbiAgci5zID0gMDsgLy8gYXNzdW1lcyBhLHRoaXMgPj0gMFxuICByLnQgPSBpO1xuICB3aGlsZShpID4gMCkgclstLWldID0gMDtcbiAgdmFyIGo7XG4gIGZvcihqID0gci50LXRoaXMudDsgaSA8IGo7ICsraSkgcltpK3RoaXMudF0gPSB0aGlzLmFtKDAsYVtpXSxyLGksMCx0aGlzLnQpO1xuICBmb3IoaiA9IE1hdGgubWluKGEudCxuKTsgaSA8IGo7ICsraSkgdGhpcy5hbSgwLGFbaV0scixpLDAsbi1pKTtcbiAgci5jbGFtcCgpO1xufVxuXG4vLyAocHJvdGVjdGVkKSByID0gXCJ0aGlzICogYVwiIHdpdGhvdXQgbG93ZXIgbiB3b3JkcywgbiA+IDBcbi8vIFwidGhpc1wiIHNob3VsZCBiZSB0aGUgbGFyZ2VyIG9uZSBpZiBhcHByb3ByaWF0ZS5cbmZ1bmN0aW9uIGJucE11bHRpcGx5VXBwZXJUbyhhLG4scikge1xuICAtLW47XG4gIHZhciBpID0gci50ID0gdGhpcy50K2EudC1uO1xuICByLnMgPSAwOyAvLyBhc3N1bWVzIGEsdGhpcyA+PSAwXG4gIHdoaWxlKC0taSA+PSAwKSByW2ldID0gMDtcbiAgZm9yKGkgPSBNYXRoLm1heChuLXRoaXMudCwwKTsgaSA8IGEudDsgKytpKVxuICAgIHJbdGhpcy50K2ktbl0gPSB0aGlzLmFtKG4taSxhW2ldLHIsMCwwLHRoaXMudCtpLW4pO1xuICByLmNsYW1wKCk7XG4gIHIuZHJTaGlmdFRvKDEscik7XG59XG5cbi8vIEJhcnJldHQgbW9kdWxhciByZWR1Y3Rpb25cbmZ1bmN0aW9uIEJhcnJldHQobSkge1xuICAvLyBzZXR1cCBCYXJyZXR0XG4gIHRoaXMucjIgPSBuYmkoKTtcbiAgdGhpcy5xMyA9IG5iaSgpO1xuICBCaWdJbnRlZ2VyLk9ORS5kbFNoaWZ0VG8oMiptLnQsdGhpcy5yMik7XG4gIHRoaXMubXUgPSB0aGlzLnIyLmRpdmlkZShtKTtcbiAgdGhpcy5tID0gbTtcbn1cblxuZnVuY3Rpb24gYmFycmV0dENvbnZlcnQoeCkge1xuICBpZih4LnMgPCAwIHx8IHgudCA+IDIqdGhpcy5tLnQpIHJldHVybiB4Lm1vZCh0aGlzLm0pO1xuICBlbHNlIGlmKHguY29tcGFyZVRvKHRoaXMubSkgPCAwKSByZXR1cm4geDtcbiAgZWxzZSB7IHZhciByID0gbmJpKCk7IHguY29weVRvKHIpOyB0aGlzLnJlZHVjZShyKTsgcmV0dXJuIHI7IH1cbn1cblxuZnVuY3Rpb24gYmFycmV0dFJldmVydCh4KSB7IHJldHVybiB4OyB9XG5cbi8vIHggPSB4IG1vZCBtIChIQUMgMTQuNDIpXG5mdW5jdGlvbiBiYXJyZXR0UmVkdWNlKHgpIHtcbiAgeC5kclNoaWZ0VG8odGhpcy5tLnQtMSx0aGlzLnIyKTtcbiAgaWYoeC50ID4gdGhpcy5tLnQrMSkgeyB4LnQgPSB0aGlzLm0udCsxOyB4LmNsYW1wKCk7IH1cbiAgdGhpcy5tdS5tdWx0aXBseVVwcGVyVG8odGhpcy5yMix0aGlzLm0udCsxLHRoaXMucTMpO1xuICB0aGlzLm0ubXVsdGlwbHlMb3dlclRvKHRoaXMucTMsdGhpcy5tLnQrMSx0aGlzLnIyKTtcbiAgd2hpbGUoeC5jb21wYXJlVG8odGhpcy5yMikgPCAwKSB4LmRBZGRPZmZzZXQoMSx0aGlzLm0udCsxKTtcbiAgeC5zdWJUbyh0aGlzLnIyLHgpO1xuICB3aGlsZSh4LmNvbXBhcmVUbyh0aGlzLm0pID49IDApIHguc3ViVG8odGhpcy5tLHgpO1xufVxuXG4vLyByID0geF4yIG1vZCBtOyB4ICE9IHJcbmZ1bmN0aW9uIGJhcnJldHRTcXJUbyh4LHIpIHsgeC5zcXVhcmVUbyhyKTsgdGhpcy5yZWR1Y2Uocik7IH1cblxuLy8gciA9IHgqeSBtb2QgbTsgeCx5ICE9IHJcbmZ1bmN0aW9uIGJhcnJldHRNdWxUbyh4LHkscikgeyB4Lm11bHRpcGx5VG8oeSxyKTsgdGhpcy5yZWR1Y2Uocik7IH1cblxuQmFycmV0dC5wcm90b3R5cGUuY29udmVydCA9IGJhcnJldHRDb252ZXJ0O1xuQmFycmV0dC5wcm90b3R5cGUucmV2ZXJ0ID0gYmFycmV0dFJldmVydDtcbkJhcnJldHQucHJvdG90eXBlLnJlZHVjZSA9IGJhcnJldHRSZWR1Y2U7XG5CYXJyZXR0LnByb3RvdHlwZS5tdWxUbyA9IGJhcnJldHRNdWxUbztcbkJhcnJldHQucHJvdG90eXBlLnNxclRvID0gYmFycmV0dFNxclRvO1xuXG4vLyAocHVibGljKSB0aGlzXmUgJSBtIChIQUMgMTQuODUpXG5mdW5jdGlvbiBibk1vZFBvdyhlLG0pIHtcbiAgdmFyIGkgPSBlLmJpdExlbmd0aCgpLCBrLCByID0gbmJ2KDEpLCB6O1xuICBpZihpIDw9IDApIHJldHVybiByO1xuICBlbHNlIGlmKGkgPCAxOCkgayA9IDE7XG4gIGVsc2UgaWYoaSA8IDQ4KSBrID0gMztcbiAgZWxzZSBpZihpIDwgMTQ0KSBrID0gNDtcbiAgZWxzZSBpZihpIDwgNzY4KSBrID0gNTtcbiAgZWxzZSBrID0gNjtcbiAgaWYoaSA8IDgpXG4gICAgeiA9IG5ldyBDbGFzc2ljKG0pO1xuICBlbHNlIGlmKG0uaXNFdmVuKCkpXG4gICAgeiA9IG5ldyBCYXJyZXR0KG0pO1xuICBlbHNlXG4gICAgeiA9IG5ldyBNb250Z29tZXJ5KG0pO1xuXG4gIC8vIHByZWNvbXB1dGF0aW9uXG4gIHZhciBnID0gbmV3IEFycmF5KCksIG4gPSAzLCBrMSA9IGstMSwga20gPSAoMTw8ayktMTtcbiAgZ1sxXSA9IHouY29udmVydCh0aGlzKTtcbiAgaWYoayA+IDEpIHtcbiAgICB2YXIgZzIgPSBuYmkoKTtcbiAgICB6LnNxclRvKGdbMV0sZzIpO1xuICAgIHdoaWxlKG4gPD0ga20pIHtcbiAgICAgIGdbbl0gPSBuYmkoKTtcbiAgICAgIHoubXVsVG8oZzIsZ1tuLTJdLGdbbl0pO1xuICAgICAgbiArPSAyO1xuICAgIH1cbiAgfVxuXG4gIHZhciBqID0gZS50LTEsIHcsIGlzMSA9IHRydWUsIHIyID0gbmJpKCksIHQ7XG4gIGkgPSBuYml0cyhlW2pdKS0xO1xuICB3aGlsZShqID49IDApIHtcbiAgICBpZihpID49IGsxKSB3ID0gKGVbal0+PihpLWsxKSkma207XG4gICAgZWxzZSB7XG4gICAgICB3ID0gKGVbal0mKCgxPDwoaSsxKSktMSkpPDwoazEtaSk7XG4gICAgICBpZihqID4gMCkgdyB8PSBlW2otMV0+Pih0aGlzLkRCK2ktazEpO1xuICAgIH1cblxuICAgIG4gPSBrO1xuICAgIHdoaWxlKCh3JjEpID09IDApIHsgdyA+Pj0gMTsgLS1uOyB9XG4gICAgaWYoKGkgLT0gbikgPCAwKSB7IGkgKz0gdGhpcy5EQjsgLS1qOyB9XG4gICAgaWYoaXMxKSB7XHQvLyByZXQgPT0gMSwgZG9uJ3QgYm90aGVyIHNxdWFyaW5nIG9yIG11bHRpcGx5aW5nIGl0XG4gICAgICBnW3ddLmNvcHlUbyhyKTtcbiAgICAgIGlzMSA9IGZhbHNlO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgIHdoaWxlKG4gPiAxKSB7IHouc3FyVG8ocixyMik7IHouc3FyVG8ocjIscik7IG4gLT0gMjsgfVxuICAgICAgaWYobiA+IDApIHouc3FyVG8ocixyMik7IGVsc2UgeyB0ID0gcjsgciA9IHIyOyByMiA9IHQ7IH1cbiAgICAgIHoubXVsVG8ocjIsZ1t3XSxyKTtcbiAgICB9XG5cbiAgICB3aGlsZShqID49IDAgJiYgKGVbal0mKDE8PGkpKSA9PSAwKSB7XG4gICAgICB6LnNxclRvKHIscjIpOyB0ID0gcjsgciA9IHIyOyByMiA9IHQ7XG4gICAgICBpZigtLWkgPCAwKSB7IGkgPSB0aGlzLkRCLTE7IC0tajsgfVxuICAgIH1cbiAgfVxuICByZXR1cm4gei5yZXZlcnQocik7XG59XG5cbi8vIChwdWJsaWMpIGdjZCh0aGlzLGEpIChIQUMgMTQuNTQpXG5mdW5jdGlvbiBibkdDRChhKSB7XG4gIHZhciB4ID0gKHRoaXMuczwwKT90aGlzLm5lZ2F0ZSgpOnRoaXMuY2xvbmUoKTtcbiAgdmFyIHkgPSAoYS5zPDApP2EubmVnYXRlKCk6YS5jbG9uZSgpO1xuICBpZih4LmNvbXBhcmVUbyh5KSA8IDApIHsgdmFyIHQgPSB4OyB4ID0geTsgeSA9IHQ7IH1cbiAgdmFyIGkgPSB4LmdldExvd2VzdFNldEJpdCgpLCBnID0geS5nZXRMb3dlc3RTZXRCaXQoKTtcbiAgaWYoZyA8IDApIHJldHVybiB4O1xuICBpZihpIDwgZykgZyA9IGk7XG4gIGlmKGcgPiAwKSB7XG4gICAgeC5yU2hpZnRUbyhnLHgpO1xuICAgIHkuclNoaWZ0VG8oZyx5KTtcbiAgfVxuICB3aGlsZSh4LnNpZ251bSgpID4gMCkge1xuICAgIGlmKChpID0geC5nZXRMb3dlc3RTZXRCaXQoKSkgPiAwKSB4LnJTaGlmdFRvKGkseCk7XG4gICAgaWYoKGkgPSB5LmdldExvd2VzdFNldEJpdCgpKSA+IDApIHkuclNoaWZ0VG8oaSx5KTtcbiAgICBpZih4LmNvbXBhcmVUbyh5KSA+PSAwKSB7XG4gICAgICB4LnN1YlRvKHkseCk7XG4gICAgICB4LnJTaGlmdFRvKDEseCk7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgeS5zdWJUbyh4LHkpO1xuICAgICAgeS5yU2hpZnRUbygxLHkpO1xuICAgIH1cbiAgfVxuICBpZihnID4gMCkgeS5sU2hpZnRUbyhnLHkpO1xuICByZXR1cm4geTtcbn1cblxuLy8gKHByb3RlY3RlZCkgdGhpcyAlIG4sIG4gPCAyXjI2XG5mdW5jdGlvbiBibnBNb2RJbnQobikge1xuICBpZihuIDw9IDApIHJldHVybiAwO1xuICB2YXIgZCA9IHRoaXMuRFYlbiwgciA9ICh0aGlzLnM8MCk/bi0xOjA7XG4gIGlmKHRoaXMudCA+IDApXG4gICAgaWYoZCA9PSAwKSByID0gdGhpc1swXSVuO1xuICAgIGVsc2UgZm9yKHZhciBpID0gdGhpcy50LTE7IGkgPj0gMDsgLS1pKSByID0gKGQqcit0aGlzW2ldKSVuO1xuICByZXR1cm4gcjtcbn1cblxuLy8gKHB1YmxpYykgMS90aGlzICUgbSAoSEFDIDE0LjYxKVxuZnVuY3Rpb24gYm5Nb2RJbnZlcnNlKG0pIHtcbiAgdmFyIGFjID0gbS5pc0V2ZW4oKTtcbiAgaWYoKHRoaXMuaXNFdmVuKCkgJiYgYWMpIHx8IG0uc2lnbnVtKCkgPT0gMCkgcmV0dXJuIEJpZ0ludGVnZXIuWkVSTztcbiAgdmFyIHUgPSBtLmNsb25lKCksIHYgPSB0aGlzLmNsb25lKCk7XG4gIHZhciBhID0gbmJ2KDEpLCBiID0gbmJ2KDApLCBjID0gbmJ2KDApLCBkID0gbmJ2KDEpO1xuICB3aGlsZSh1LnNpZ251bSgpICE9IDApIHtcbiAgICB3aGlsZSh1LmlzRXZlbigpKSB7XG4gICAgICB1LnJTaGlmdFRvKDEsdSk7XG4gICAgICBpZihhYykge1xuICAgICAgICBpZighYS5pc0V2ZW4oKSB8fCAhYi5pc0V2ZW4oKSkgeyBhLmFkZFRvKHRoaXMsYSk7IGIuc3ViVG8obSxiKTsgfVxuICAgICAgICBhLnJTaGlmdFRvKDEsYSk7XG4gICAgICB9XG4gICAgICBlbHNlIGlmKCFiLmlzRXZlbigpKSBiLnN1YlRvKG0sYik7XG4gICAgICBiLnJTaGlmdFRvKDEsYik7XG4gICAgfVxuICAgIHdoaWxlKHYuaXNFdmVuKCkpIHtcbiAgICAgIHYuclNoaWZ0VG8oMSx2KTtcbiAgICAgIGlmKGFjKSB7XG4gICAgICAgIGlmKCFjLmlzRXZlbigpIHx8ICFkLmlzRXZlbigpKSB7IGMuYWRkVG8odGhpcyxjKTsgZC5zdWJUbyhtLGQpOyB9XG4gICAgICAgIGMuclNoaWZ0VG8oMSxjKTtcbiAgICAgIH1cbiAgICAgIGVsc2UgaWYoIWQuaXNFdmVuKCkpIGQuc3ViVG8obSxkKTtcbiAgICAgIGQuclNoaWZ0VG8oMSxkKTtcbiAgICB9XG4gICAgaWYodS5jb21wYXJlVG8odikgPj0gMCkge1xuICAgICAgdS5zdWJUbyh2LHUpO1xuICAgICAgaWYoYWMpIGEuc3ViVG8oYyxhKTtcbiAgICAgIGIuc3ViVG8oZCxiKTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICB2LnN1YlRvKHUsdik7XG4gICAgICBpZihhYykgYy5zdWJUbyhhLGMpO1xuICAgICAgZC5zdWJUbyhiLGQpO1xuICAgIH1cbiAgfVxuICBpZih2LmNvbXBhcmVUbyhCaWdJbnRlZ2VyLk9ORSkgIT0gMCkgcmV0dXJuIEJpZ0ludGVnZXIuWkVSTztcbiAgaWYoZC5jb21wYXJlVG8obSkgPj0gMCkgcmV0dXJuIGQuc3VidHJhY3QobSk7XG4gIGlmKGQuc2lnbnVtKCkgPCAwKSBkLmFkZFRvKG0sZCk7IGVsc2UgcmV0dXJuIGQ7XG4gIGlmKGQuc2lnbnVtKCkgPCAwKSByZXR1cm4gZC5hZGQobSk7IGVsc2UgcmV0dXJuIGQ7XG59XG5cbnZhciBsb3dwcmltZXMgPSBbMiwzLDUsNywxMSwxMywxNywxOSwyMywyOSwzMSwzNyw0MSw0Myw0Nyw1Myw1OSw2MSw2Nyw3MSw3Myw3OSw4Myw4OSw5NywxMDEsMTAzLDEwNywxMDksMTEzLDEyNywxMzEsMTM3LDEzOSwxNDksMTUxLDE1NywxNjMsMTY3LDE3MywxNzksMTgxLDE5MSwxOTMsMTk3LDE5OSwyMTEsMjIzLDIyNywyMjksMjMzLDIzOSwyNDEsMjUxLDI1NywyNjMsMjY5LDI3MSwyNzcsMjgxLDI4MywyOTMsMzA3LDMxMSwzMTMsMzE3LDMzMSwzMzcsMzQ3LDM0OSwzNTMsMzU5LDM2NywzNzMsMzc5LDM4MywzODksMzk3LDQwMSw0MDksNDE5LDQyMSw0MzEsNDMzLDQzOSw0NDMsNDQ5LDQ1Nyw0NjEsNDYzLDQ2Nyw0NzksNDg3LDQ5MSw0OTksNTAzLDUwOSw1MjEsNTIzLDU0MSw1NDcsNTU3LDU2Myw1NjksNTcxLDU3Nyw1ODcsNTkzLDU5OSw2MDEsNjA3LDYxMyw2MTcsNjE5LDYzMSw2NDEsNjQzLDY0Nyw2NTMsNjU5LDY2MSw2NzMsNjc3LDY4Myw2OTEsNzAxLDcwOSw3MTksNzI3LDczMyw3MzksNzQzLDc1MSw3NTcsNzYxLDc2OSw3NzMsNzg3LDc5Nyw4MDksODExLDgyMSw4MjMsODI3LDgyOSw4MzksODUzLDg1Nyw4NTksODYzLDg3Nyw4ODEsODgzLDg4Nyw5MDcsOTExLDkxOSw5MjksOTM3LDk0MSw5NDcsOTUzLDk2Nyw5NzEsOTc3LDk4Myw5OTEsOTk3XTtcbnZhciBscGxpbSA9ICgxPDwyNikvbG93cHJpbWVzW2xvd3ByaW1lcy5sZW5ndGgtMV07XG5cbi8vIChwdWJsaWMpIHRlc3QgcHJpbWFsaXR5IHdpdGggY2VydGFpbnR5ID49IDEtLjVedFxuZnVuY3Rpb24gYm5Jc1Byb2JhYmxlUHJpbWUodCkge1xuICB2YXIgaSwgeCA9IHRoaXMuYWJzKCk7XG4gIGlmKHgudCA9PSAxICYmIHhbMF0gPD0gbG93cHJpbWVzW2xvd3ByaW1lcy5sZW5ndGgtMV0pIHtcbiAgICBmb3IoaSA9IDA7IGkgPCBsb3dwcmltZXMubGVuZ3RoOyArK2kpXG4gICAgICBpZih4WzBdID09IGxvd3ByaW1lc1tpXSkgcmV0dXJuIHRydWU7XG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG4gIGlmKHguaXNFdmVuKCkpIHJldHVybiBmYWxzZTtcbiAgaSA9IDE7XG4gIHdoaWxlKGkgPCBsb3dwcmltZXMubGVuZ3RoKSB7XG4gICAgdmFyIG0gPSBsb3dwcmltZXNbaV0sIGogPSBpKzE7XG4gICAgd2hpbGUoaiA8IGxvd3ByaW1lcy5sZW5ndGggJiYgbSA8IGxwbGltKSBtICo9IGxvd3ByaW1lc1tqKytdO1xuICAgIG0gPSB4Lm1vZEludChtKTtcbiAgICB3aGlsZShpIDwgaikgaWYobSVsb3dwcmltZXNbaSsrXSA9PSAwKSByZXR1cm4gZmFsc2U7XG4gIH1cbiAgcmV0dXJuIHgubWlsbGVyUmFiaW4odCk7XG59XG5cbi8vIChwcm90ZWN0ZWQpIHRydWUgaWYgcHJvYmFibHkgcHJpbWUgKEhBQyA0LjI0LCBNaWxsZXItUmFiaW4pXG5mdW5jdGlvbiBibnBNaWxsZXJSYWJpbih0KSB7XG4gIHZhciBuMSA9IHRoaXMuc3VidHJhY3QoQmlnSW50ZWdlci5PTkUpO1xuICB2YXIgayA9IG4xLmdldExvd2VzdFNldEJpdCgpO1xuICBpZihrIDw9IDApIHJldHVybiBmYWxzZTtcbiAgdmFyIHIgPSBuMS5zaGlmdFJpZ2h0KGspO1xuICB0ID0gKHQrMSk+PjE7XG4gIGlmKHQgPiBsb3dwcmltZXMubGVuZ3RoKSB0ID0gbG93cHJpbWVzLmxlbmd0aDtcbiAgdmFyIGEgPSBuYmkoKTtcbiAgZm9yKHZhciBpID0gMDsgaSA8IHQ7ICsraSkge1xuICAgIC8vUGljayBiYXNlcyBhdCByYW5kb20sIGluc3RlYWQgb2Ygc3RhcnRpbmcgYXQgMlxuICAgIGEuZnJvbUludChsb3dwcmltZXNbTWF0aC5mbG9vcihNYXRoLnJhbmRvbSgpKmxvd3ByaW1lcy5sZW5ndGgpXSk7XG4gICAgdmFyIHkgPSBhLm1vZFBvdyhyLHRoaXMpO1xuICAgIGlmKHkuY29tcGFyZVRvKEJpZ0ludGVnZXIuT05FKSAhPSAwICYmIHkuY29tcGFyZVRvKG4xKSAhPSAwKSB7XG4gICAgICB2YXIgaiA9IDE7XG4gICAgICB3aGlsZShqKysgPCBrICYmIHkuY29tcGFyZVRvKG4xKSAhPSAwKSB7XG4gICAgICAgIHkgPSB5Lm1vZFBvd0ludCgyLHRoaXMpO1xuICAgICAgICBpZih5LmNvbXBhcmVUbyhCaWdJbnRlZ2VyLk9ORSkgPT0gMCkgcmV0dXJuIGZhbHNlO1xuICAgICAgfVxuICAgICAgaWYoeS5jb21wYXJlVG8objEpICE9IDApIHJldHVybiBmYWxzZTtcbiAgICB9XG4gIH1cbiAgcmV0dXJuIHRydWU7XG59XG5cbi8vIHByb3RlY3RlZFxuQmlnSW50ZWdlci5wcm90b3R5cGUuY2h1bmtTaXplID0gYm5wQ2h1bmtTaXplO1xuQmlnSW50ZWdlci5wcm90b3R5cGUudG9SYWRpeCA9IGJucFRvUmFkaXg7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5mcm9tUmFkaXggPSBibnBGcm9tUmFkaXg7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5mcm9tTnVtYmVyID0gYm5wRnJvbU51bWJlcjtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmJpdHdpc2VUbyA9IGJucEJpdHdpc2VUbztcbkJpZ0ludGVnZXIucHJvdG90eXBlLmNoYW5nZUJpdCA9IGJucENoYW5nZUJpdDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmFkZFRvID0gYm5wQWRkVG87XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5kTXVsdGlwbHkgPSBibnBETXVsdGlwbHk7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5kQWRkT2Zmc2V0ID0gYm5wREFkZE9mZnNldDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLm11bHRpcGx5TG93ZXJUbyA9IGJucE11bHRpcGx5TG93ZXJUbztcbkJpZ0ludGVnZXIucHJvdG90eXBlLm11bHRpcGx5VXBwZXJUbyA9IGJucE11bHRpcGx5VXBwZXJUbztcbkJpZ0ludGVnZXIucHJvdG90eXBlLm1vZEludCA9IGJucE1vZEludDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLm1pbGxlclJhYmluID0gYm5wTWlsbGVyUmFiaW47XG5cbi8vIHB1YmxpY1xuQmlnSW50ZWdlci5wcm90b3R5cGUuY2xvbmUgPSBibkNsb25lO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuaW50VmFsdWUgPSBibkludFZhbHVlO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuYnl0ZVZhbHVlID0gYm5CeXRlVmFsdWU7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5zaG9ydFZhbHVlID0gYm5TaG9ydFZhbHVlO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuc2lnbnVtID0gYm5TaWdOdW07XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS50b0J5dGVBcnJheSA9IGJuVG9CeXRlQXJyYXk7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5lcXVhbHMgPSBibkVxdWFscztcbkJpZ0ludGVnZXIucHJvdG90eXBlLm1pbiA9IGJuTWluO1xuQmlnSW50ZWdlci5wcm90b3R5cGUubWF4ID0gYm5NYXg7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5hbmQgPSBibkFuZDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLm9yID0gYm5PcjtcbkJpZ0ludGVnZXIucHJvdG90eXBlLnhvciA9IGJuWG9yO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuYW5kTm90ID0gYm5BbmROb3Q7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5ub3QgPSBibk5vdDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLnNoaWZ0TGVmdCA9IGJuU2hpZnRMZWZ0O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuc2hpZnRSaWdodCA9IGJuU2hpZnRSaWdodDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmdldExvd2VzdFNldEJpdCA9IGJuR2V0TG93ZXN0U2V0Qml0O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuYml0Q291bnQgPSBibkJpdENvdW50O1xuQmlnSW50ZWdlci5wcm90b3R5cGUudGVzdEJpdCA9IGJuVGVzdEJpdDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLnNldEJpdCA9IGJuU2V0Qml0O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuY2xlYXJCaXQgPSBibkNsZWFyQml0O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZmxpcEJpdCA9IGJuRmxpcEJpdDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmFkZCA9IGJuQWRkO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuc3VidHJhY3QgPSBiblN1YnRyYWN0O1xuQmlnSW50ZWdlci5wcm90b3R5cGUubXVsdGlwbHkgPSBibk11bHRpcGx5O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZGl2aWRlID0gYm5EaXZpZGU7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5yZW1haW5kZXIgPSBiblJlbWFpbmRlcjtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmRpdmlkZUFuZFJlbWFpbmRlciA9IGJuRGl2aWRlQW5kUmVtYWluZGVyO1xuQmlnSW50ZWdlci5wcm90b3R5cGUubW9kUG93ID0gYm5Nb2RQb3c7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5tb2RJbnZlcnNlID0gYm5Nb2RJbnZlcnNlO1xuQmlnSW50ZWdlci5wcm90b3R5cGUucG93ID0gYm5Qb3c7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5nY2QgPSBibkdDRDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmlzUHJvYmFibGVQcmltZSA9IGJuSXNQcm9iYWJsZVByaW1lO1xuXG4vLyBKU0JOLXNwZWNpZmljIGV4dGVuc2lvblxuQmlnSW50ZWdlci5wcm90b3R5cGUuc3F1YXJlID0gYm5TcXVhcmU7XG5cbi8vIEJpZ0ludGVnZXIgaW50ZXJmYWNlcyBub3QgaW1wbGVtZW50ZWQgaW4ganNibjpcblxuLy8gQmlnSW50ZWdlcihpbnQgc2lnbnVtLCBieXRlW10gbWFnbml0dWRlKVxuLy8gZG91YmxlIGRvdWJsZVZhbHVlKClcbi8vIGZsb2F0IGZsb2F0VmFsdWUoKVxuLy8gaW50IGhhc2hDb2RlKClcbi8vIGxvbmcgbG9uZ1ZhbHVlKClcbi8vIHN0YXRpYyBCaWdJbnRlZ2VyIHZhbHVlT2YobG9uZyB2YWwpXG5cbi8vIHBybmc0LmpzIC0gdXNlcyBBcmNmb3VyIGFzIGEgUFJOR1xuXG5mdW5jdGlvbiBBcmNmb3VyKCkge1xuICB0aGlzLmkgPSAwO1xuICB0aGlzLmogPSAwO1xuICB0aGlzLlMgPSBuZXcgQXJyYXkoKTtcbn1cblxuLy8gSW5pdGlhbGl6ZSBhcmNmb3VyIGNvbnRleHQgZnJvbSBrZXksIGFuIGFycmF5IG9mIGludHMsIGVhY2ggZnJvbSBbMC4uMjU1XVxuZnVuY3Rpb24gQVJDNGluaXQoa2V5KSB7XG4gIHZhciBpLCBqLCB0O1xuICBmb3IoaSA9IDA7IGkgPCAyNTY7ICsraSlcbiAgICB0aGlzLlNbaV0gPSBpO1xuICBqID0gMDtcbiAgZm9yKGkgPSAwOyBpIDwgMjU2OyArK2kpIHtcbiAgICBqID0gKGogKyB0aGlzLlNbaV0gKyBrZXlbaSAlIGtleS5sZW5ndGhdKSAmIDI1NTtcbiAgICB0ID0gdGhpcy5TW2ldO1xuICAgIHRoaXMuU1tpXSA9IHRoaXMuU1tqXTtcbiAgICB0aGlzLlNbal0gPSB0O1xuICB9XG4gIHRoaXMuaSA9IDA7XG4gIHRoaXMuaiA9IDA7XG59XG5cbmZ1bmN0aW9uIEFSQzRuZXh0KCkge1xuICB2YXIgdDtcbiAgdGhpcy5pID0gKHRoaXMuaSArIDEpICYgMjU1O1xuICB0aGlzLmogPSAodGhpcy5qICsgdGhpcy5TW3RoaXMuaV0pICYgMjU1O1xuICB0ID0gdGhpcy5TW3RoaXMuaV07XG4gIHRoaXMuU1t0aGlzLmldID0gdGhpcy5TW3RoaXMual07XG4gIHRoaXMuU1t0aGlzLmpdID0gdDtcbiAgcmV0dXJuIHRoaXMuU1sodCArIHRoaXMuU1t0aGlzLmldKSAmIDI1NV07XG59XG5cbkFyY2ZvdXIucHJvdG90eXBlLmluaXQgPSBBUkM0aW5pdDtcbkFyY2ZvdXIucHJvdG90eXBlLm5leHQgPSBBUkM0bmV4dDtcblxuLy8gUGx1ZyBpbiB5b3VyIFJORyBjb25zdHJ1Y3RvciBoZXJlXG5mdW5jdGlvbiBwcm5nX25ld3N0YXRlKCkge1xuICByZXR1cm4gbmV3IEFyY2ZvdXIoKTtcbn1cblxuLy8gUG9vbCBzaXplIG11c3QgYmUgYSBtdWx0aXBsZSBvZiA0IGFuZCBncmVhdGVyIHRoYW4gMzIuXG4vLyBBbiBhcnJheSBvZiBieXRlcyB0aGUgc2l6ZSBvZiB0aGUgcG9vbCB3aWxsIGJlIHBhc3NlZCB0byBpbml0KClcbnZhciBybmdfcHNpemUgPSAyNTY7XG5cbi8vIFJhbmRvbSBudW1iZXIgZ2VuZXJhdG9yIC0gcmVxdWlyZXMgYSBQUk5HIGJhY2tlbmQsIGUuZy4gcHJuZzQuanNcbnZhciBybmdfc3RhdGU7XG52YXIgcm5nX3Bvb2w7XG52YXIgcm5nX3BwdHI7XG5cbi8vIEluaXRpYWxpemUgdGhlIHBvb2wgd2l0aCBqdW5rIGlmIG5lZWRlZC5cbmlmKHJuZ19wb29sID09IG51bGwpIHtcbiAgcm5nX3Bvb2wgPSBuZXcgQXJyYXkoKTtcbiAgcm5nX3BwdHIgPSAwO1xuICB2YXIgdDtcbiAgaWYod2luZG93LmNyeXB0byAmJiB3aW5kb3cuY3J5cHRvLmdldFJhbmRvbVZhbHVlcykge1xuICAgIC8vIEV4dHJhY3QgZW50cm9weSAoMjA0OCBiaXRzKSBmcm9tIFJORyBpZiBhdmFpbGFibGVcbiAgICB2YXIgeiA9IG5ldyBVaW50MzJBcnJheSgyNTYpO1xuICAgIHdpbmRvdy5jcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKHopO1xuICAgIGZvciAodCA9IDA7IHQgPCB6Lmxlbmd0aDsgKyt0KVxuICAgICAgcm5nX3Bvb2xbcm5nX3BwdHIrK10gPSB6W3RdICYgMjU1O1xuICB9XG5cbiAgLy8gVXNlIG1vdXNlIGV2ZW50cyBmb3IgZW50cm9weSwgaWYgd2UgZG8gbm90IGhhdmUgZW5vdWdoIGVudHJvcHkgYnkgdGhlIHRpbWVcbiAgLy8gd2UgbmVlZCBpdCwgZW50cm9weSB3aWxsIGJlIGdlbmVyYXRlZCBieSBNYXRoLnJhbmRvbS5cbiAgdmFyIG9uTW91c2VNb3ZlTGlzdGVuZXIgPSBmdW5jdGlvbihldikge1xuICAgIHRoaXMuY291bnQgPSB0aGlzLmNvdW50IHx8IDA7XG4gICAgaWYgKHRoaXMuY291bnQgPj0gMjU2IHx8IHJuZ19wcHRyID49IHJuZ19wc2l6ZSkge1xuICAgICAgaWYgKHdpbmRvdy5yZW1vdmVFdmVudExpc3RlbmVyKVxuICAgICAgICB3aW5kb3cucmVtb3ZlRXZlbnRMaXN0ZW5lcihcIm1vdXNlbW92ZVwiLCBvbk1vdXNlTW92ZUxpc3RlbmVyLCBmYWxzZSk7XG4gICAgICBlbHNlIGlmICh3aW5kb3cuZGV0YWNoRXZlbnQpXG4gICAgICAgIHdpbmRvdy5kZXRhY2hFdmVudChcIm9ubW91c2Vtb3ZlXCIsIG9uTW91c2VNb3ZlTGlzdGVuZXIpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICB0cnkge1xuICAgICAgdmFyIG1vdXNlQ29vcmRpbmF0ZXMgPSBldi54ICsgZXYueTtcbiAgICAgIHJuZ19wb29sW3JuZ19wcHRyKytdID0gbW91c2VDb29yZGluYXRlcyAmIDI1NTtcbiAgICAgIHRoaXMuY291bnQgKz0gMTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAvLyBTb21ldGltZXMgRmlyZWZveCB3aWxsIGRlbnkgcGVybWlzc2lvbiB0byBhY2Nlc3MgZXZlbnQgcHJvcGVydGllcyBmb3Igc29tZSByZWFzb24uIElnbm9yZS5cbiAgICB9XG4gIH07XG4gIGlmICh3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcilcbiAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcihcIm1vdXNlbW92ZVwiLCBvbk1vdXNlTW92ZUxpc3RlbmVyLCBmYWxzZSk7XG4gIGVsc2UgaWYgKHdpbmRvdy5hdHRhY2hFdmVudClcbiAgICB3aW5kb3cuYXR0YWNoRXZlbnQoXCJvbm1vdXNlbW92ZVwiLCBvbk1vdXNlTW92ZUxpc3RlbmVyKTtcblxufVxuXG5mdW5jdGlvbiBybmdfZ2V0X2J5dGUoKSB7XG4gIGlmKHJuZ19zdGF0ZSA9PSBudWxsKSB7XG4gICAgcm5nX3N0YXRlID0gcHJuZ19uZXdzdGF0ZSgpO1xuICAgIC8vIEF0IHRoaXMgcG9pbnQsIHdlIG1heSBub3QgaGF2ZSBjb2xsZWN0ZWQgZW5vdWdoIGVudHJvcHkuICBJZiBub3QsIGZhbGwgYmFjayB0byBNYXRoLnJhbmRvbVxuICAgIHdoaWxlIChybmdfcHB0ciA8IHJuZ19wc2l6ZSkge1xuICAgICAgdmFyIHJhbmRvbSA9IE1hdGguZmxvb3IoNjU1MzYgKiBNYXRoLnJhbmRvbSgpKTtcbiAgICAgIHJuZ19wb29sW3JuZ19wcHRyKytdID0gcmFuZG9tICYgMjU1O1xuICAgIH1cbiAgICBybmdfc3RhdGUuaW5pdChybmdfcG9vbCk7XG4gICAgZm9yKHJuZ19wcHRyID0gMDsgcm5nX3BwdHIgPCBybmdfcG9vbC5sZW5ndGg7ICsrcm5nX3BwdHIpXG4gICAgICBybmdfcG9vbFtybmdfcHB0cl0gPSAwO1xuICAgIHJuZ19wcHRyID0gMDtcbiAgfVxuICAvLyBUT0RPOiBhbGxvdyByZXNlZWRpbmcgYWZ0ZXIgZmlyc3QgcmVxdWVzdFxuICByZXR1cm4gcm5nX3N0YXRlLm5leHQoKTtcbn1cblxuZnVuY3Rpb24gcm5nX2dldF9ieXRlcyhiYSkge1xuICB2YXIgaTtcbiAgZm9yKGkgPSAwOyBpIDwgYmEubGVuZ3RoOyArK2kpIGJhW2ldID0gcm5nX2dldF9ieXRlKCk7XG59XG5cbmZ1bmN0aW9uIFNlY3VyZVJhbmRvbSgpIHt9XG5cblNlY3VyZVJhbmRvbS5wcm90b3R5cGUubmV4dEJ5dGVzID0gcm5nX2dldF9ieXRlcztcblxuLy8gRGVwZW5kcyBvbiBqc2JuLmpzIGFuZCBybmcuanNcblxuLy8gVmVyc2lvbiAxLjE6IHN1cHBvcnQgdXRmLTggZW5jb2RpbmcgaW4gcGtjczFwYWQyXG5cbi8vIGNvbnZlcnQgYSAoaGV4KSBzdHJpbmcgdG8gYSBiaWdudW0gb2JqZWN0XG5mdW5jdGlvbiBwYXJzZUJpZ0ludChzdHIscikge1xuICByZXR1cm4gbmV3IEJpZ0ludGVnZXIoc3RyLHIpO1xufVxuXG5mdW5jdGlvbiBsaW5lYnJrKHMsbikge1xuICB2YXIgcmV0ID0gXCJcIjtcbiAgdmFyIGkgPSAwO1xuICB3aGlsZShpICsgbiA8IHMubGVuZ3RoKSB7XG4gICAgcmV0ICs9IHMuc3Vic3RyaW5nKGksaStuKSArIFwiXFxuXCI7XG4gICAgaSArPSBuO1xuICB9XG4gIHJldHVybiByZXQgKyBzLnN1YnN0cmluZyhpLHMubGVuZ3RoKTtcbn1cblxuZnVuY3Rpb24gYnl0ZTJIZXgoYikge1xuICBpZihiIDwgMHgxMClcbiAgICByZXR1cm4gXCIwXCIgKyBiLnRvU3RyaW5nKDE2KTtcbiAgZWxzZVxuICAgIHJldHVybiBiLnRvU3RyaW5nKDE2KTtcbn1cblxuLy8gUEtDUyMxICh0eXBlIDIsIHJhbmRvbSkgcGFkIGlucHV0IHN0cmluZyBzIHRvIG4gYnl0ZXMsIGFuZCByZXR1cm4gYSBiaWdpbnRcbmZ1bmN0aW9uIHBrY3MxcGFkMihzLG4pIHtcbiAgaWYobiA8IHMubGVuZ3RoICsgMTEpIHsgLy8gVE9ETzogZml4IGZvciB1dGYtOFxuICAgIGNvbnNvbGUuZXJyb3IoXCJNZXNzYWdlIHRvbyBsb25nIGZvciBSU0FcIik7XG4gICAgcmV0dXJuIG51bGw7XG4gIH1cbiAgdmFyIGJhID0gbmV3IEFycmF5KCk7XG4gIHZhciBpID0gcy5sZW5ndGggLSAxO1xuICB3aGlsZShpID49IDAgJiYgbiA+IDApIHtcbiAgICB2YXIgYyA9IHMuY2hhckNvZGVBdChpLS0pO1xuICAgIGlmKGMgPCAxMjgpIHsgLy8gZW5jb2RlIHVzaW5nIHV0Zi04XG4gICAgICBiYVstLW5dID0gYztcbiAgICB9XG4gICAgZWxzZSBpZigoYyA+IDEyNykgJiYgKGMgPCAyMDQ4KSkge1xuICAgICAgYmFbLS1uXSA9IChjICYgNjMpIHwgMTI4O1xuICAgICAgYmFbLS1uXSA9IChjID4+IDYpIHwgMTkyO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgIGJhWy0tbl0gPSAoYyAmIDYzKSB8IDEyODtcbiAgICAgIGJhWy0tbl0gPSAoKGMgPj4gNikgJiA2MykgfCAxMjg7XG4gICAgICBiYVstLW5dID0gKGMgPj4gMTIpIHwgMjI0O1xuICAgIH1cbiAgfVxuICBiYVstLW5dID0gMDtcbiAgdmFyIHJuZyA9IG5ldyBTZWN1cmVSYW5kb20oKTtcbiAgdmFyIHggPSBuZXcgQXJyYXkoKTtcbiAgd2hpbGUobiA+IDIpIHsgLy8gcmFuZG9tIG5vbi16ZXJvIHBhZFxuICAgIHhbMF0gPSAwO1xuICAgIHdoaWxlKHhbMF0gPT0gMCkgcm5nLm5leHRCeXRlcyh4KTtcbiAgICBiYVstLW5dID0geFswXTtcbiAgfVxuICBiYVstLW5dID0gMjtcbiAgYmFbLS1uXSA9IDA7XG4gIHJldHVybiBuZXcgQmlnSW50ZWdlcihiYSk7XG59XG5cbi8vIFwiZW1wdHlcIiBSU0Ega2V5IGNvbnN0cnVjdG9yXG5mdW5jdGlvbiBSU0FLZXkoKSB7XG4gIHRoaXMubiA9IG51bGw7XG4gIHRoaXMuZSA9IDA7XG4gIHRoaXMuZCA9IG51bGw7XG4gIHRoaXMucCA9IG51bGw7XG4gIHRoaXMucSA9IG51bGw7XG4gIHRoaXMuZG1wMSA9IG51bGw7XG4gIHRoaXMuZG1xMSA9IG51bGw7XG4gIHRoaXMuY29lZmYgPSBudWxsO1xufVxuXG4vLyBTZXQgdGhlIHB1YmxpYyBrZXkgZmllbGRzIE4gYW5kIGUgZnJvbSBoZXggc3RyaW5nc1xuZnVuY3Rpb24gUlNBU2V0UHVibGljKE4sRSkge1xuICBpZihOICE9IG51bGwgJiYgRSAhPSBudWxsICYmIE4ubGVuZ3RoID4gMCAmJiBFLmxlbmd0aCA+IDApIHtcbiAgICB0aGlzLm4gPSBwYXJzZUJpZ0ludChOLDE2KTtcbiAgICB0aGlzLmUgPSBwYXJzZUludChFLDE2KTtcbiAgfVxuICBlbHNlXG4gICAgY29uc29sZS5lcnJvcihcIkludmFsaWQgUlNBIHB1YmxpYyBrZXlcIik7XG59XG5cbi8vIFBlcmZvcm0gcmF3IHB1YmxpYyBvcGVyYXRpb24gb24gXCJ4XCI6IHJldHVybiB4XmUgKG1vZCBuKVxuZnVuY3Rpb24gUlNBRG9QdWJsaWMoeCkge1xuICByZXR1cm4geC5tb2RQb3dJbnQodGhpcy5lLCB0aGlzLm4pO1xufVxuXG4vLyBSZXR1cm4gdGhlIFBLQ1MjMSBSU0EgZW5jcnlwdGlvbiBvZiBcInRleHRcIiBhcyBhbiBldmVuLWxlbmd0aCBoZXggc3RyaW5nXG5mdW5jdGlvbiBSU0FFbmNyeXB0KHRleHQpIHtcbiAgdmFyIG0gPSBwa2NzMXBhZDIodGV4dCwodGhpcy5uLmJpdExlbmd0aCgpKzcpPj4zKTtcbiAgaWYobSA9PSBudWxsKSByZXR1cm4gbnVsbDtcbiAgdmFyIGMgPSB0aGlzLmRvUHVibGljKG0pO1xuICBpZihjID09IG51bGwpIHJldHVybiBudWxsO1xuICB2YXIgaCA9IGMudG9TdHJpbmcoMTYpO1xuICBpZigoaC5sZW5ndGggJiAxKSA9PSAwKSByZXR1cm4gaDsgZWxzZSByZXR1cm4gXCIwXCIgKyBoO1xufVxuXG4vLyBSZXR1cm4gdGhlIFBLQ1MjMSBSU0EgZW5jcnlwdGlvbiBvZiBcInRleHRcIiBhcyBhIEJhc2U2NC1lbmNvZGVkIHN0cmluZ1xuLy9mdW5jdGlvbiBSU0FFbmNyeXB0QjY0KHRleHQpIHtcbi8vICB2YXIgaCA9IHRoaXMuZW5jcnlwdCh0ZXh0KTtcbi8vICBpZihoKSByZXR1cm4gaGV4MmI2NChoKTsgZWxzZSByZXR1cm4gbnVsbDtcbi8vfVxuXG4vLyBwcm90ZWN0ZWRcblJTQUtleS5wcm90b3R5cGUuZG9QdWJsaWMgPSBSU0FEb1B1YmxpYztcblxuLy8gcHVibGljXG5SU0FLZXkucHJvdG90eXBlLnNldFB1YmxpYyA9IFJTQVNldFB1YmxpYztcblJTQUtleS5wcm90b3R5cGUuZW5jcnlwdCA9IFJTQUVuY3J5cHQ7XG4vL1JTQUtleS5wcm90b3R5cGUuZW5jcnlwdF9iNjQgPSBSU0FFbmNyeXB0QjY0O1xuXG4vLyBEZXBlbmRzIG9uIHJzYS5qcyBhbmQganNibjIuanNcblxuLy8gVmVyc2lvbiAxLjE6IHN1cHBvcnQgdXRmLTggZGVjb2RpbmcgaW4gcGtjczF1bnBhZDJcblxuLy8gVW5kbyBQS0NTIzEgKHR5cGUgMiwgcmFuZG9tKSBwYWRkaW5nIGFuZCwgaWYgdmFsaWQsIHJldHVybiB0aGUgcGxhaW50ZXh0XG5mdW5jdGlvbiBwa2NzMXVucGFkMihkLG4pIHtcbiAgdmFyIGIgPSBkLnRvQnl0ZUFycmF5KCk7XG4gIHZhciBpID0gMDtcbiAgd2hpbGUoaSA8IGIubGVuZ3RoICYmIGJbaV0gPT0gMCkgKytpO1xuICBpZihiLmxlbmd0aC1pICE9IG4tMSB8fCBiW2ldICE9IDIpXG4gICAgcmV0dXJuIG51bGw7XG4gICsraTtcbiAgd2hpbGUoYltpXSAhPSAwKVxuICAgIGlmKCsraSA+PSBiLmxlbmd0aCkgcmV0dXJuIG51bGw7XG4gIHZhciByZXQgPSBcIlwiO1xuICB3aGlsZSgrK2kgPCBiLmxlbmd0aCkge1xuICAgIHZhciBjID0gYltpXSAmIDI1NTtcbiAgICBpZihjIDwgMTI4KSB7IC8vIHV0Zi04IGRlY29kZVxuICAgICAgcmV0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoYyk7XG4gICAgfVxuICAgIGVsc2UgaWYoKGMgPiAxOTEpICYmIChjIDwgMjI0KSkge1xuICAgICAgcmV0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoKChjICYgMzEpIDw8IDYpIHwgKGJbaSsxXSAmIDYzKSk7XG4gICAgICArK2k7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgcmV0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoKChjICYgMTUpIDw8IDEyKSB8ICgoYltpKzFdICYgNjMpIDw8IDYpIHwgKGJbaSsyXSAmIDYzKSk7XG4gICAgICBpICs9IDI7XG4gICAgfVxuICB9XG4gIHJldHVybiByZXQ7XG59XG5cbi8vIFNldCB0aGUgcHJpdmF0ZSBrZXkgZmllbGRzIE4sIGUsIGFuZCBkIGZyb20gaGV4IHN0cmluZ3NcbmZ1bmN0aW9uIFJTQVNldFByaXZhdGUoTixFLEQpIHtcbiAgaWYoTiAhPSBudWxsICYmIEUgIT0gbnVsbCAmJiBOLmxlbmd0aCA+IDAgJiYgRS5sZW5ndGggPiAwKSB7XG4gICAgdGhpcy5uID0gcGFyc2VCaWdJbnQoTiwxNik7XG4gICAgdGhpcy5lID0gcGFyc2VJbnQoRSwxNik7XG4gICAgdGhpcy5kID0gcGFyc2VCaWdJbnQoRCwxNik7XG4gIH1cbiAgZWxzZVxuICAgIGNvbnNvbGUuZXJyb3IoXCJJbnZhbGlkIFJTQSBwcml2YXRlIGtleVwiKTtcbn1cblxuLy8gU2V0IHRoZSBwcml2YXRlIGtleSBmaWVsZHMgTiwgZSwgZCBhbmQgQ1JUIHBhcmFtcyBmcm9tIGhleCBzdHJpbmdzXG5mdW5jdGlvbiBSU0FTZXRQcml2YXRlRXgoTixFLEQsUCxRLERQLERRLEMpIHtcbiAgaWYoTiAhPSBudWxsICYmIEUgIT0gbnVsbCAmJiBOLmxlbmd0aCA+IDAgJiYgRS5sZW5ndGggPiAwKSB7XG4gICAgdGhpcy5uID0gcGFyc2VCaWdJbnQoTiwxNik7XG4gICAgdGhpcy5lID0gcGFyc2VJbnQoRSwxNik7XG4gICAgdGhpcy5kID0gcGFyc2VCaWdJbnQoRCwxNik7XG4gICAgdGhpcy5wID0gcGFyc2VCaWdJbnQoUCwxNik7XG4gICAgdGhpcy5xID0gcGFyc2VCaWdJbnQoUSwxNik7XG4gICAgdGhpcy5kbXAxID0gcGFyc2VCaWdJbnQoRFAsMTYpO1xuICAgIHRoaXMuZG1xMSA9IHBhcnNlQmlnSW50KERRLDE2KTtcbiAgICB0aGlzLmNvZWZmID0gcGFyc2VCaWdJbnQoQywxNik7XG4gIH1cbiAgZWxzZVxuICAgIGNvbnNvbGUuZXJyb3IoXCJJbnZhbGlkIFJTQSBwcml2YXRlIGtleVwiKTtcbn1cblxuLy8gR2VuZXJhdGUgYSBuZXcgcmFuZG9tIHByaXZhdGUga2V5IEIgYml0cyBsb25nLCB1c2luZyBwdWJsaWMgZXhwdCBFXG5mdW5jdGlvbiBSU0FHZW5lcmF0ZShCLEUpIHtcbiAgdmFyIHJuZyA9IG5ldyBTZWN1cmVSYW5kb20oKTtcbiAgdmFyIHFzID0gQj4+MTtcbiAgdGhpcy5lID0gcGFyc2VJbnQoRSwxNik7XG4gIHZhciBlZSA9IG5ldyBCaWdJbnRlZ2VyKEUsMTYpO1xuICBmb3IoOzspIHtcbiAgICBmb3IoOzspIHtcbiAgICAgIHRoaXMucCA9IG5ldyBCaWdJbnRlZ2VyKEItcXMsMSxybmcpO1xuICAgICAgaWYodGhpcy5wLnN1YnRyYWN0KEJpZ0ludGVnZXIuT05FKS5nY2QoZWUpLmNvbXBhcmVUbyhCaWdJbnRlZ2VyLk9ORSkgPT0gMCAmJiB0aGlzLnAuaXNQcm9iYWJsZVByaW1lKDEwKSkgYnJlYWs7XG4gICAgfVxuICAgIGZvcig7Oykge1xuICAgICAgdGhpcy5xID0gbmV3IEJpZ0ludGVnZXIocXMsMSxybmcpO1xuICAgICAgaWYodGhpcy5xLnN1YnRyYWN0KEJpZ0ludGVnZXIuT05FKS5nY2QoZWUpLmNvbXBhcmVUbyhCaWdJbnRlZ2VyLk9ORSkgPT0gMCAmJiB0aGlzLnEuaXNQcm9iYWJsZVByaW1lKDEwKSkgYnJlYWs7XG4gICAgfVxuICAgIGlmKHRoaXMucC5jb21wYXJlVG8odGhpcy5xKSA8PSAwKSB7XG4gICAgICB2YXIgdCA9IHRoaXMucDtcbiAgICAgIHRoaXMucCA9IHRoaXMucTtcbiAgICAgIHRoaXMucSA9IHQ7XG4gICAgfVxuICAgIHZhciBwMSA9IHRoaXMucC5zdWJ0cmFjdChCaWdJbnRlZ2VyLk9ORSk7XG4gICAgdmFyIHExID0gdGhpcy5xLnN1YnRyYWN0KEJpZ0ludGVnZXIuT05FKTtcbiAgICB2YXIgcGhpID0gcDEubXVsdGlwbHkocTEpO1xuICAgIGlmKHBoaS5nY2QoZWUpLmNvbXBhcmVUbyhCaWdJbnRlZ2VyLk9ORSkgPT0gMCkge1xuICAgICAgdGhpcy5uID0gdGhpcy5wLm11bHRpcGx5KHRoaXMucSk7XG4gICAgICB0aGlzLmQgPSBlZS5tb2RJbnZlcnNlKHBoaSk7XG4gICAgICB0aGlzLmRtcDEgPSB0aGlzLmQubW9kKHAxKTtcbiAgICAgIHRoaXMuZG1xMSA9IHRoaXMuZC5tb2QocTEpO1xuICAgICAgdGhpcy5jb2VmZiA9IHRoaXMucS5tb2RJbnZlcnNlKHRoaXMucCk7XG4gICAgICBicmVhaztcbiAgICB9XG4gIH1cbn1cblxuLy8gUGVyZm9ybSByYXcgcHJpdmF0ZSBvcGVyYXRpb24gb24gXCJ4XCI6IHJldHVybiB4XmQgKG1vZCBuKVxuZnVuY3Rpb24gUlNBRG9Qcml2YXRlKHgpIHtcbiAgaWYodGhpcy5wID09IG51bGwgfHwgdGhpcy5xID09IG51bGwpXG4gICAgcmV0dXJuIHgubW9kUG93KHRoaXMuZCwgdGhpcy5uKTtcblxuICAvLyBUT0RPOiByZS1jYWxjdWxhdGUgYW55IG1pc3NpbmcgQ1JUIHBhcmFtc1xuICB2YXIgeHAgPSB4Lm1vZCh0aGlzLnApLm1vZFBvdyh0aGlzLmRtcDEsIHRoaXMucCk7XG4gIHZhciB4cSA9IHgubW9kKHRoaXMucSkubW9kUG93KHRoaXMuZG1xMSwgdGhpcy5xKTtcblxuICB3aGlsZSh4cC5jb21wYXJlVG8oeHEpIDwgMClcbiAgICB4cCA9IHhwLmFkZCh0aGlzLnApO1xuICByZXR1cm4geHAuc3VidHJhY3QoeHEpLm11bHRpcGx5KHRoaXMuY29lZmYpLm1vZCh0aGlzLnApLm11bHRpcGx5KHRoaXMucSkuYWRkKHhxKTtcbn1cblxuLy8gUmV0dXJuIHRoZSBQS0NTIzEgUlNBIGRlY3J5cHRpb24gb2YgXCJjdGV4dFwiLlxuLy8gXCJjdGV4dFwiIGlzIGFuIGV2ZW4tbGVuZ3RoIGhleCBzdHJpbmcgYW5kIHRoZSBvdXRwdXQgaXMgYSBwbGFpbiBzdHJpbmcuXG5mdW5jdGlvbiBSU0FEZWNyeXB0KGN0ZXh0KSB7XG4gIHZhciBjID0gcGFyc2VCaWdJbnQoY3RleHQsIDE2KTtcbiAgdmFyIG0gPSB0aGlzLmRvUHJpdmF0ZShjKTtcbiAgaWYobSA9PSBudWxsKSByZXR1cm4gbnVsbDtcbiAgcmV0dXJuIHBrY3MxdW5wYWQyKG0sICh0aGlzLm4uYml0TGVuZ3RoKCkrNyk+PjMpO1xufVxuXG4vLyBSZXR1cm4gdGhlIFBLQ1MjMSBSU0EgZGVjcnlwdGlvbiBvZiBcImN0ZXh0XCIuXG4vLyBcImN0ZXh0XCIgaXMgYSBCYXNlNjQtZW5jb2RlZCBzdHJpbmcgYW5kIHRoZSBvdXRwdXQgaXMgYSBwbGFpbiBzdHJpbmcuXG4vL2Z1bmN0aW9uIFJTQUI2NERlY3J5cHQoY3RleHQpIHtcbi8vICB2YXIgaCA9IGI2NHRvaGV4KGN0ZXh0KTtcbi8vICBpZihoKSByZXR1cm4gdGhpcy5kZWNyeXB0KGgpOyBlbHNlIHJldHVybiBudWxsO1xuLy99XG5cbi8vIHByb3RlY3RlZFxuUlNBS2V5LnByb3RvdHlwZS5kb1ByaXZhdGUgPSBSU0FEb1ByaXZhdGU7XG5cbi8vIHB1YmxpY1xuUlNBS2V5LnByb3RvdHlwZS5zZXRQcml2YXRlID0gUlNBU2V0UHJpdmF0ZTtcblJTQUtleS5wcm90b3R5cGUuc2V0UHJpdmF0ZUV4ID0gUlNBU2V0UHJpdmF0ZUV4O1xuUlNBS2V5LnByb3RvdHlwZS5nZW5lcmF0ZSA9IFJTQUdlbmVyYXRlO1xuUlNBS2V5LnByb3RvdHlwZS5kZWNyeXB0ID0gUlNBRGVjcnlwdDtcbi8vUlNBS2V5LnByb3RvdHlwZS5iNjRfZGVjcnlwdCA9IFJTQUI2NERlY3J5cHQ7XG5cbi8vIENvcHlyaWdodCAoYykgMjAxMSAgS2V2aW4gTSBCdXJucyBKci5cbi8vIEFsbCBSaWdodHMgUmVzZXJ2ZWQuXG4vLyBTZWUgXCJMSUNFTlNFXCIgZm9yIGRldGFpbHMuXG4vL1xuLy8gRXh0ZW5zaW9uIHRvIGpzYm4gd2hpY2ggYWRkcyBmYWNpbGl0aWVzIGZvciBhc3luY2hyb25vdXMgUlNBIGtleSBnZW5lcmF0aW9uXG4vLyBQcmltYXJpbHkgY3JlYXRlZCB0byBhdm9pZCBleGVjdXRpb24gdGltZW91dCBvbiBtb2JpbGUgZGV2aWNlc1xuLy9cbi8vIGh0dHA6Ly93d3ctY3Mtc3R1ZGVudHMuc3RhbmZvcmQuZWR1L350ancvanNibi9cbi8vXG4vLyAtLS1cblxuKGZ1bmN0aW9uKCl7XG5cbi8vIEdlbmVyYXRlIGEgbmV3IHJhbmRvbSBwcml2YXRlIGtleSBCIGJpdHMgbG9uZywgdXNpbmcgcHVibGljIGV4cHQgRVxudmFyIFJTQUdlbmVyYXRlQXN5bmMgPSBmdW5jdGlvbiAoQiwgRSwgY2FsbGJhY2spIHtcbiAgICAvL3ZhciBybmcgPSBuZXcgU2VlZGVkUmFuZG9tKCk7XG4gICAgdmFyIHJuZyA9IG5ldyBTZWN1cmVSYW5kb20oKTtcbiAgICB2YXIgcXMgPSBCID4+IDE7XG4gICAgdGhpcy5lID0gcGFyc2VJbnQoRSwgMTYpO1xuICAgIHZhciBlZSA9IG5ldyBCaWdJbnRlZ2VyKEUsIDE2KTtcbiAgICB2YXIgcnNhID0gdGhpcztcbiAgICAvLyBUaGVzZSBmdW5jdGlvbnMgaGF2ZSBub24tZGVzY3JpcHQgbmFtZXMgYmVjYXVzZSB0aGV5IHdlcmUgb3JpZ2luYWxseSBmb3IoOzspIGxvb3BzLlxuICAgIC8vIEkgZG9uJ3Qga25vdyBhYm91dCBjcnlwdG9ncmFwaHkgdG8gZ2l2ZSB0aGVtIGJldHRlciBuYW1lcyB0aGFuIGxvb3AxLTQuXG4gICAgdmFyIGxvb3AxID0gZnVuY3Rpb24oKSB7XG4gICAgICAgIHZhciBsb29wNCA9IGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgaWYgKHJzYS5wLmNvbXBhcmVUbyhyc2EucSkgPD0gMCkge1xuICAgICAgICAgICAgICAgIHZhciB0ID0gcnNhLnA7XG4gICAgICAgICAgICAgICAgcnNhLnAgPSByc2EucTtcbiAgICAgICAgICAgICAgICByc2EucSA9IHQ7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICB2YXIgcDEgPSByc2EucC5zdWJ0cmFjdChCaWdJbnRlZ2VyLk9ORSk7XG4gICAgICAgICAgICB2YXIgcTEgPSByc2EucS5zdWJ0cmFjdChCaWdJbnRlZ2VyLk9ORSk7XG4gICAgICAgICAgICB2YXIgcGhpID0gcDEubXVsdGlwbHkocTEpO1xuICAgICAgICAgICAgaWYgKHBoaS5nY2QoZWUpLmNvbXBhcmVUbyhCaWdJbnRlZ2VyLk9ORSkgPT0gMCkge1xuICAgICAgICAgICAgICAgIHJzYS5uID0gcnNhLnAubXVsdGlwbHkocnNhLnEpO1xuICAgICAgICAgICAgICAgIHJzYS5kID0gZWUubW9kSW52ZXJzZShwaGkpO1xuICAgICAgICAgICAgICAgIHJzYS5kbXAxID0gcnNhLmQubW9kKHAxKTtcbiAgICAgICAgICAgICAgICByc2EuZG1xMSA9IHJzYS5kLm1vZChxMSk7XG4gICAgICAgICAgICAgICAgcnNhLmNvZWZmID0gcnNhLnEubW9kSW52ZXJzZShyc2EucCk7XG4gICAgICAgICAgICAgICAgc2V0VGltZW91dChmdW5jdGlvbigpe2NhbGxiYWNrKCl9LDApOyAvLyBlc2NhcGVcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgc2V0VGltZW91dChsb29wMSwwKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfTtcbiAgICAgICAgdmFyIGxvb3AzID0gZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICByc2EucSA9IG5iaSgpO1xuICAgICAgICAgICAgcnNhLnEuZnJvbU51bWJlckFzeW5jKHFzLCAxLCBybmcsIGZ1bmN0aW9uKCl7XG4gICAgICAgICAgICAgICAgcnNhLnEuc3VidHJhY3QoQmlnSW50ZWdlci5PTkUpLmdjZGEoZWUsIGZ1bmN0aW9uKHIpe1xuICAgICAgICAgICAgICAgICAgICBpZiAoci5jb21wYXJlVG8oQmlnSW50ZWdlci5PTkUpID09IDAgJiYgcnNhLnEuaXNQcm9iYWJsZVByaW1lKDEwKSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgc2V0VGltZW91dChsb29wNCwwKTtcbiAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHNldFRpbWVvdXQobG9vcDMsMCk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9O1xuICAgICAgICB2YXIgbG9vcDIgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIHJzYS5wID0gbmJpKCk7XG4gICAgICAgICAgICByc2EucC5mcm9tTnVtYmVyQXN5bmMoQiAtIHFzLCAxLCBybmcsIGZ1bmN0aW9uKCl7XG4gICAgICAgICAgICAgICAgcnNhLnAuc3VidHJhY3QoQmlnSW50ZWdlci5PTkUpLmdjZGEoZWUsIGZ1bmN0aW9uKHIpe1xuICAgICAgICAgICAgICAgICAgICBpZiAoci5jb21wYXJlVG8oQmlnSW50ZWdlci5PTkUpID09IDAgJiYgcnNhLnAuaXNQcm9iYWJsZVByaW1lKDEwKSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgc2V0VGltZW91dChsb29wMywwKTtcbiAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHNldFRpbWVvdXQobG9vcDIsMCk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9O1xuICAgICAgICBzZXRUaW1lb3V0KGxvb3AyLDApO1xuICAgIH07XG4gICAgc2V0VGltZW91dChsb29wMSwwKTtcbn07XG5SU0FLZXkucHJvdG90eXBlLmdlbmVyYXRlQXN5bmMgPSBSU0FHZW5lcmF0ZUFzeW5jO1xuXG4vLyBQdWJsaWMgQVBJIG1ldGhvZFxudmFyIGJuR0NEQXN5bmMgPSBmdW5jdGlvbiAoYSwgY2FsbGJhY2spIHtcbiAgICB2YXIgeCA9ICh0aGlzLnMgPCAwKSA/IHRoaXMubmVnYXRlKCkgOiB0aGlzLmNsb25lKCk7XG4gICAgdmFyIHkgPSAoYS5zIDwgMCkgPyBhLm5lZ2F0ZSgpIDogYS5jbG9uZSgpO1xuICAgIGlmICh4LmNvbXBhcmVUbyh5KSA8IDApIHtcbiAgICAgICAgdmFyIHQgPSB4O1xuICAgICAgICB4ID0geTtcbiAgICAgICAgeSA9IHQ7XG4gICAgfVxuICAgIHZhciBpID0geC5nZXRMb3dlc3RTZXRCaXQoKSxcbiAgICAgICAgZyA9IHkuZ2V0TG93ZXN0U2V0Qml0KCk7XG4gICAgaWYgKGcgPCAwKSB7XG4gICAgICAgIGNhbGxiYWNrKHgpO1xuICAgICAgICByZXR1cm47XG4gICAgfVxuICAgIGlmIChpIDwgZykgZyA9IGk7XG4gICAgaWYgKGcgPiAwKSB7XG4gICAgICAgIHguclNoaWZ0VG8oZywgeCk7XG4gICAgICAgIHkuclNoaWZ0VG8oZywgeSk7XG4gICAgfVxuICAgIC8vIFdvcmtob3JzZSBvZiB0aGUgYWxnb3JpdGhtLCBnZXRzIGNhbGxlZCAyMDAgLSA4MDAgdGltZXMgcGVyIDUxMiBiaXQga2V5Z2VuLlxuICAgIHZhciBnY2RhMSA9IGZ1bmN0aW9uKCkge1xuICAgICAgICBpZiAoKGkgPSB4LmdldExvd2VzdFNldEJpdCgpKSA+IDApeyB4LnJTaGlmdFRvKGksIHgpOyB9XG4gICAgICAgIGlmICgoaSA9IHkuZ2V0TG93ZXN0U2V0Qml0KCkpID4gMCl7IHkuclNoaWZ0VG8oaSwgeSk7IH1cbiAgICAgICAgaWYgKHguY29tcGFyZVRvKHkpID49IDApIHtcbiAgICAgICAgICAgIHguc3ViVG8oeSwgeCk7XG4gICAgICAgICAgICB4LnJTaGlmdFRvKDEsIHgpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgeS5zdWJUbyh4LCB5KTtcbiAgICAgICAgICAgIHkuclNoaWZ0VG8oMSwgeSk7XG4gICAgICAgIH1cbiAgICAgICAgaWYoISh4LnNpZ251bSgpID4gMCkpIHtcbiAgICAgICAgICAgIGlmIChnID4gMCkgeS5sU2hpZnRUbyhnLCB5KTtcbiAgICAgICAgICAgIHNldFRpbWVvdXQoZnVuY3Rpb24oKXtjYWxsYmFjayh5KX0sMCk7IC8vIGVzY2FwZVxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgc2V0VGltZW91dChnY2RhMSwwKTtcbiAgICAgICAgfVxuICAgIH07XG4gICAgc2V0VGltZW91dChnY2RhMSwxMCk7XG59O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZ2NkYSA9IGJuR0NEQXN5bmM7XG5cbi8vIChwcm90ZWN0ZWQpIGFsdGVybmF0ZSBjb25zdHJ1Y3RvclxudmFyIGJucEZyb21OdW1iZXJBc3luYyA9IGZ1bmN0aW9uIChhLGIsYyxjYWxsYmFjaykge1xuICBpZihcIm51bWJlclwiID09IHR5cGVvZiBiKSB7XG4gICAgaWYoYSA8IDIpIHtcbiAgICAgICAgdGhpcy5mcm9tSW50KDEpO1xuICAgIH0gZWxzZSB7XG4gICAgICB0aGlzLmZyb21OdW1iZXIoYSxjKTtcbiAgICAgIGlmKCF0aGlzLnRlc3RCaXQoYS0xKSl7XG4gICAgICAgIHRoaXMuYml0d2lzZVRvKEJpZ0ludGVnZXIuT05FLnNoaWZ0TGVmdChhLTEpLG9wX29yLHRoaXMpO1xuICAgICAgfVxuICAgICAgaWYodGhpcy5pc0V2ZW4oKSkge1xuICAgICAgICB0aGlzLmRBZGRPZmZzZXQoMSwwKTtcbiAgICAgIH1cbiAgICAgIHZhciBibnAgPSB0aGlzO1xuICAgICAgdmFyIGJucGZuMSA9IGZ1bmN0aW9uKCl7XG4gICAgICAgIGJucC5kQWRkT2Zmc2V0KDIsMCk7XG4gICAgICAgIGlmKGJucC5iaXRMZW5ndGgoKSA+IGEpIGJucC5zdWJUbyhCaWdJbnRlZ2VyLk9ORS5zaGlmdExlZnQoYS0xKSxibnApO1xuICAgICAgICBpZihibnAuaXNQcm9iYWJsZVByaW1lKGIpKSB7XG4gICAgICAgICAgICBzZXRUaW1lb3V0KGZ1bmN0aW9uKCl7Y2FsbGJhY2soKX0sMCk7IC8vIGVzY2FwZVxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgc2V0VGltZW91dChibnBmbjEsMCk7XG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgICBzZXRUaW1lb3V0KGJucGZuMSwwKTtcbiAgICB9XG4gIH0gZWxzZSB7XG4gICAgdmFyIHggPSBuZXcgQXJyYXkoKSwgdCA9IGEmNztcbiAgICB4Lmxlbmd0aCA9IChhPj4zKSsxO1xuICAgIGIubmV4dEJ5dGVzKHgpO1xuICAgIGlmKHQgPiAwKSB4WzBdICY9ICgoMTw8dCktMSk7IGVsc2UgeFswXSA9IDA7XG4gICAgdGhpcy5mcm9tU3RyaW5nKHgsMjU2KTtcbiAgfVxufTtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmZyb21OdW1iZXJBc3luYyA9IGJucEZyb21OdW1iZXJBc3luYztcblxufSkoKTtcbnZhciBiNjRtYXA9XCJBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OSsvXCI7XG52YXIgYjY0cGFkPVwiPVwiO1xuXG5mdW5jdGlvbiBoZXgyYjY0KGgpIHtcbiAgdmFyIGk7XG4gIHZhciBjO1xuICB2YXIgcmV0ID0gXCJcIjtcbiAgZm9yKGkgPSAwOyBpKzMgPD0gaC5sZW5ndGg7IGkrPTMpIHtcbiAgICBjID0gcGFyc2VJbnQoaC5zdWJzdHJpbmcoaSxpKzMpLDE2KTtcbiAgICByZXQgKz0gYjY0bWFwLmNoYXJBdChjID4+IDYpICsgYjY0bWFwLmNoYXJBdChjICYgNjMpO1xuICB9XG4gIGlmKGkrMSA9PSBoLmxlbmd0aCkge1xuICAgIGMgPSBwYXJzZUludChoLnN1YnN0cmluZyhpLGkrMSksMTYpO1xuICAgIHJldCArPSBiNjRtYXAuY2hhckF0KGMgPDwgMik7XG4gIH1cbiAgZWxzZSBpZihpKzIgPT0gaC5sZW5ndGgpIHtcbiAgICBjID0gcGFyc2VJbnQoaC5zdWJzdHJpbmcoaSxpKzIpLDE2KTtcbiAgICByZXQgKz0gYjY0bWFwLmNoYXJBdChjID4+IDIpICsgYjY0bWFwLmNoYXJBdCgoYyAmIDMpIDw8IDQpO1xuICB9XG4gIHdoaWxlKChyZXQubGVuZ3RoICYgMykgPiAwKSByZXQgKz0gYjY0cGFkO1xuICByZXR1cm4gcmV0O1xufVxuXG4vLyBjb252ZXJ0IGEgYmFzZTY0IHN0cmluZyB0byBoZXhcbmZ1bmN0aW9uIGI2NHRvaGV4KHMpIHtcbiAgdmFyIHJldCA9IFwiXCJcbiAgdmFyIGk7XG4gIHZhciBrID0gMDsgLy8gYjY0IHN0YXRlLCAwLTNcbiAgdmFyIHNsb3A7XG4gIGZvcihpID0gMDsgaSA8IHMubGVuZ3RoOyArK2kpIHtcbiAgICBpZihzLmNoYXJBdChpKSA9PSBiNjRwYWQpIGJyZWFrO1xuICAgIHYgPSBiNjRtYXAuaW5kZXhPZihzLmNoYXJBdChpKSk7XG4gICAgaWYodiA8IDApIGNvbnRpbnVlO1xuICAgIGlmKGsgPT0gMCkge1xuICAgICAgcmV0ICs9IGludDJjaGFyKHYgPj4gMik7XG4gICAgICBzbG9wID0gdiAmIDM7XG4gICAgICBrID0gMTtcbiAgICB9XG4gICAgZWxzZSBpZihrID09IDEpIHtcbiAgICAgIHJldCArPSBpbnQyY2hhcigoc2xvcCA8PCAyKSB8ICh2ID4+IDQpKTtcbiAgICAgIHNsb3AgPSB2ICYgMHhmO1xuICAgICAgayA9IDI7XG4gICAgfVxuICAgIGVsc2UgaWYoayA9PSAyKSB7XG4gICAgICByZXQgKz0gaW50MmNoYXIoc2xvcCk7XG4gICAgICByZXQgKz0gaW50MmNoYXIodiA+PiAyKTtcbiAgICAgIHNsb3AgPSB2ICYgMztcbiAgICAgIGsgPSAzO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgIHJldCArPSBpbnQyY2hhcigoc2xvcCA8PCAyKSB8ICh2ID4+IDQpKTtcbiAgICAgIHJldCArPSBpbnQyY2hhcih2ICYgMHhmKTtcbiAgICAgIGsgPSAwO1xuICAgIH1cbiAgfVxuICBpZihrID09IDEpXG4gICAgcmV0ICs9IGludDJjaGFyKHNsb3AgPDwgMik7XG4gIHJldHVybiByZXQ7XG59XG5cbi8vIGNvbnZlcnQgYSBiYXNlNjQgc3RyaW5nIHRvIGEgYnl0ZS9udW1iZXIgYXJyYXlcbmZ1bmN0aW9uIGI2NHRvQkEocykge1xuICAvL3BpZ2d5YmFjayBvbiBiNjR0b2hleCBmb3Igbm93LCBvcHRpbWl6ZSBsYXRlclxuICB2YXIgaCA9IGI2NHRvaGV4KHMpO1xuICB2YXIgaTtcbiAgdmFyIGEgPSBuZXcgQXJyYXkoKTtcbiAgZm9yKGkgPSAwOyAyKmkgPCBoLmxlbmd0aDsgKytpKSB7XG4gICAgYVtpXSA9IHBhcnNlSW50KGguc3Vic3RyaW5nKDIqaSwyKmkrMiksMTYpO1xuICB9XG4gIHJldHVybiBhO1xufVxuXG4vKiEgYXNuMS0xLjAuMi5qcyAoYykgMjAxMyBLZW5qaSBVcnVzaGltYSB8IGtqdXIuZ2l0aHViLmNvbS9qc3JzYXNpZ24vbGljZW5zZVxuICovXG5cbnZhciBKU1ggPSBKU1ggfHwge307XG5KU1guZW52ID0gSlNYLmVudiB8fCB7fTtcblxudmFyIEwgPSBKU1gsIE9QID0gT2JqZWN0LnByb3RvdHlwZSwgRlVOQ1RJT05fVE9TVFJJTkcgPSAnW29iamVjdCBGdW5jdGlvbl0nLEFERCA9IFtcInRvU3RyaW5nXCIsIFwidmFsdWVPZlwiXTtcblxuSlNYLmVudi5wYXJzZVVBID0gZnVuY3Rpb24oYWdlbnQpIHtcblxuICAgIHZhciBudW1iZXJpZnkgPSBmdW5jdGlvbihzKSB7XG4gICAgICAgIHZhciBjID0gMDtcbiAgICAgICAgcmV0dXJuIHBhcnNlRmxvYXQocy5yZXBsYWNlKC9cXC4vZywgZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICByZXR1cm4gKGMrKyA9PSAxKSA/ICcnIDogJy4nO1xuICAgICAgICB9KSk7XG4gICAgfSxcblxuICAgIG5hdiA9IG5hdmlnYXRvcixcbiAgICBvID0ge1xuICAgICAgICBpZTogMCxcbiAgICAgICAgb3BlcmE6IDAsXG4gICAgICAgIGdlY2tvOiAwLFxuICAgICAgICB3ZWJraXQ6IDAsXG4gICAgICAgIGNocm9tZTogMCxcbiAgICAgICAgbW9iaWxlOiBudWxsLFxuICAgICAgICBhaXI6IDAsXG4gICAgICAgIGlwYWQ6IDAsXG4gICAgICAgIGlwaG9uZTogMCxcbiAgICAgICAgaXBvZDogMCxcbiAgICAgICAgaW9zOiBudWxsLFxuICAgICAgICBhbmRyb2lkOiAwLFxuICAgICAgICB3ZWJvczogMCxcbiAgICAgICAgY2FqYTogbmF2ICYmIG5hdi5jYWphVmVyc2lvbixcbiAgICAgICAgc2VjdXJlOiBmYWxzZSxcbiAgICAgICAgb3M6IG51bGxcblxuICAgIH0sXG5cbiAgICB1YSA9IGFnZW50IHx8IChuYXZpZ2F0b3IgJiYgbmF2aWdhdG9yLnVzZXJBZ2VudCksXG4gICAgbG9jID0gd2luZG93ICYmIHdpbmRvdy5sb2NhdGlvbixcbiAgICBocmVmID0gbG9jICYmIGxvYy5ocmVmLFxuICAgIG07XG5cbiAgICBvLnNlY3VyZSA9IGhyZWYgJiYgKGhyZWYudG9Mb3dlckNhc2UoKS5pbmRleE9mKFwiaHR0cHNcIikgPT09IDApO1xuXG4gICAgaWYgKHVhKSB7XG5cbiAgICAgICAgaWYgKCgvd2luZG93c3x3aW4zMi9pKS50ZXN0KHVhKSkge1xuICAgICAgICAgICAgby5vcyA9ICd3aW5kb3dzJztcbiAgICAgICAgfSBlbHNlIGlmICgoL21hY2ludG9zaC9pKS50ZXN0KHVhKSkge1xuICAgICAgICAgICAgby5vcyA9ICdtYWNpbnRvc2gnO1xuICAgICAgICB9IGVsc2UgaWYgKCgvcmhpbm8vaSkudGVzdCh1YSkpIHtcbiAgICAgICAgICAgIG8ub3MgPSAncmhpbm8nO1xuICAgICAgICB9XG4gICAgICAgIGlmICgoL0tIVE1MLykudGVzdCh1YSkpIHtcbiAgICAgICAgICAgIG8ud2Via2l0ID0gMTtcbiAgICAgICAgfVxuICAgICAgICBtID0gdWEubWF0Y2goL0FwcGxlV2ViS2l0XFwvKFteXFxzXSopLyk7XG4gICAgICAgIGlmIChtICYmIG1bMV0pIHtcbiAgICAgICAgICAgIG8ud2Via2l0ID0gbnVtYmVyaWZ5KG1bMV0pO1xuICAgICAgICAgICAgaWYgKC8gTW9iaWxlXFwvLy50ZXN0KHVhKSkge1xuICAgICAgICAgICAgICAgIG8ubW9iaWxlID0gJ0FwcGxlJzsgLy8gaVBob25lIG9yIGlQb2QgVG91Y2hcbiAgICAgICAgICAgICAgICBtID0gdWEubWF0Y2goL09TIChbXlxcc10qKS8pO1xuICAgICAgICAgICAgICAgIGlmIChtICYmIG1bMV0pIHtcbiAgICAgICAgICAgICAgICAgICAgbSA9IG51bWJlcmlmeShtWzFdLnJlcGxhY2UoJ18nLCAnLicpKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgby5pb3MgPSBtO1xuICAgICAgICAgICAgICAgIG8uaXBhZCA9IG8uaXBvZCA9IG8uaXBob25lID0gMDtcbiAgICAgICAgICAgICAgICBtID0gdWEubWF0Y2goL2lQYWR8aVBvZHxpUGhvbmUvKTtcbiAgICAgICAgICAgICAgICBpZiAobSAmJiBtWzBdKSB7XG4gICAgICAgICAgICAgICAgICAgIG9bbVswXS50b0xvd2VyQ2FzZSgpXSA9IG8uaW9zO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgbSA9IHVhLm1hdGNoKC9Ob2tpYU5bXlxcL10qfEFuZHJvaWQgXFxkXFwuXFxkfHdlYk9TXFwvXFxkXFwuXFxkLyk7XG4gICAgICAgICAgICAgICAgaWYgKG0pIHtcbiAgICAgICAgICAgICAgICAgICAgby5tb2JpbGUgPSBtWzBdO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoL3dlYk9TLy50ZXN0KHVhKSkge1xuICAgICAgICAgICAgICAgICAgICBvLm1vYmlsZSA9ICdXZWJPUyc7XG4gICAgICAgICAgICAgICAgICAgIG0gPSB1YS5tYXRjaCgvd2ViT1NcXC8oW15cXHNdKik7Lyk7XG4gICAgICAgICAgICAgICAgICAgIGlmIChtICYmIG1bMV0pIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIG8ud2Vib3MgPSBudW1iZXJpZnkobVsxXSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKC8gQW5kcm9pZC8udGVzdCh1YSkpIHtcbiAgICAgICAgICAgICAgICAgICAgby5tb2JpbGUgPSAnQW5kcm9pZCc7XG4gICAgICAgICAgICAgICAgICAgIG0gPSB1YS5tYXRjaCgvQW5kcm9pZCAoW15cXHNdKik7Lyk7XG4gICAgICAgICAgICAgICAgICAgIGlmIChtICYmIG1bMV0pIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIG8uYW5kcm9pZCA9IG51bWJlcmlmeShtWzFdKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIG0gPSB1YS5tYXRjaCgvQ2hyb21lXFwvKFteXFxzXSopLyk7XG4gICAgICAgICAgICBpZiAobSAmJiBtWzFdKSB7XG4gICAgICAgICAgICAgICAgby5jaHJvbWUgPSBudW1iZXJpZnkobVsxXSk7IC8vIENocm9tZVxuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICBtID0gdWEubWF0Y2goL0Fkb2JlQUlSXFwvKFteXFxzXSopLyk7XG4gICAgICAgICAgICAgICAgaWYgKG0pIHtcbiAgICAgICAgICAgICAgICAgICAgby5haXIgPSBtWzBdOyAvLyBBZG9iZSBBSVIgMS4wIG9yIGJldHRlclxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBpZiAoIW8ud2Via2l0KSB7XG4gICAgICAgICAgICBtID0gdWEubWF0Y2goL09wZXJhW1xcc1xcL10oW15cXHNdKikvKTtcbiAgICAgICAgICAgIGlmIChtICYmIG1bMV0pIHtcbiAgICAgICAgICAgICAgICBvLm9wZXJhID0gbnVtYmVyaWZ5KG1bMV0pO1xuICAgICAgICAgICAgICAgIG0gPSB1YS5tYXRjaCgvVmVyc2lvblxcLyhbXlxcc10qKS8pO1xuICAgICAgICAgICAgICAgIGlmIChtICYmIG1bMV0pIHtcbiAgICAgICAgICAgICAgICAgICAgby5vcGVyYSA9IG51bWJlcmlmeShtWzFdKTsgLy8gb3BlcmEgMTArXG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIG0gPSB1YS5tYXRjaCgvT3BlcmEgTWluaVteO10qLyk7XG4gICAgICAgICAgICAgICAgaWYgKG0pIHtcbiAgICAgICAgICAgICAgICAgICAgby5tb2JpbGUgPSBtWzBdOyAvLyBleDogT3BlcmEgTWluaS8yLjAuNDUwOS8xMzE2XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSBlbHNlIHsgLy8gbm90IG9wZXJhIG9yIHdlYmtpdFxuICAgICAgICAgICAgICAgIG0gPSB1YS5tYXRjaCgvTVNJRVxccyhbXjtdKikvKTtcbiAgICAgICAgICAgICAgICBpZiAobSAmJiBtWzFdKSB7XG4gICAgICAgICAgICAgICAgICAgIG8uaWUgPSBudW1iZXJpZnkobVsxXSk7XG4gICAgICAgICAgICAgICAgfSBlbHNlIHsgLy8gbm90IG9wZXJhLCB3ZWJraXQsIG9yIGllXG4gICAgICAgICAgICAgICAgICAgIG0gPSB1YS5tYXRjaCgvR2Vja29cXC8oW15cXHNdKikvKTtcbiAgICAgICAgICAgICAgICAgICAgaWYgKG0pIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIG8uZ2Vja28gPSAxOyAvLyBHZWNrbyBkZXRlY3RlZCwgbG9vayBmb3IgcmV2aXNpb25cbiAgICAgICAgICAgICAgICAgICAgICAgIG0gPSB1YS5tYXRjaCgvcnY6KFteXFxzXFwpXSopLyk7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAobSAmJiBtWzFdKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgby5nZWNrbyA9IG51bWJlcmlmeShtWzFdKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gbztcbn07XG5cbkpTWC5lbnYudWEgPSBKU1guZW52LnBhcnNlVUEoKTtcblxuSlNYLmlzRnVuY3Rpb24gPSBmdW5jdGlvbihvKSB7XG4gICAgcmV0dXJuICh0eXBlb2YgbyA9PT0gJ2Z1bmN0aW9uJykgfHwgT1AudG9TdHJpbmcuYXBwbHkobykgPT09IEZVTkNUSU9OX1RPU1RSSU5HO1xufTtcblxuSlNYLl9JRUVudW1GaXggPSAoSlNYLmVudi51YS5pZSkgPyBmdW5jdGlvbihyLCBzKSB7XG4gICAgdmFyIGksIGZuYW1lLCBmO1xuICAgIGZvciAoaT0wO2k8QURELmxlbmd0aDtpPWkrMSkge1xuXG4gICAgICAgIGZuYW1lID0gQUREW2ldO1xuICAgICAgICBmID0gc1tmbmFtZV07XG5cbiAgICAgICAgaWYgKEwuaXNGdW5jdGlvbihmKSAmJiBmIT1PUFtmbmFtZV0pIHtcbiAgICAgICAgICAgIHJbZm5hbWVdPWY7XG4gICAgICAgIH1cbiAgICB9XG59IDogZnVuY3Rpb24oKXt9O1xuXG5KU1guZXh0ZW5kID0gZnVuY3Rpb24oc3ViYywgc3VwZXJjLCBvdmVycmlkZXMpIHtcbiAgICBpZiAoIXN1cGVyY3x8IXN1YmMpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiZXh0ZW5kIGZhaWxlZCwgcGxlYXNlIGNoZWNrIHRoYXQgXCIgK1xuICAgICAgICAgICAgICAgICAgICAgICAgXCJhbGwgZGVwZW5kZW5jaWVzIGFyZSBpbmNsdWRlZC5cIik7XG4gICAgfVxuICAgIHZhciBGID0gZnVuY3Rpb24oKSB7fSwgaTtcbiAgICBGLnByb3RvdHlwZT1zdXBlcmMucHJvdG90eXBlO1xuICAgIHN1YmMucHJvdG90eXBlPW5ldyBGKCk7XG4gICAgc3ViYy5wcm90b3R5cGUuY29uc3RydWN0b3I9c3ViYztcbiAgICBzdWJjLnN1cGVyY2xhc3M9c3VwZXJjLnByb3RvdHlwZTtcbiAgICBpZiAoc3VwZXJjLnByb3RvdHlwZS5jb25zdHJ1Y3RvciA9PSBPUC5jb25zdHJ1Y3Rvcikge1xuICAgICAgICBzdXBlcmMucHJvdG90eXBlLmNvbnN0cnVjdG9yPXN1cGVyYztcbiAgICB9XG5cbiAgICBpZiAob3ZlcnJpZGVzKSB7XG4gICAgICAgIGZvciAoaSBpbiBvdmVycmlkZXMpIHtcbiAgICAgICAgICAgIGlmIChMLmhhc093blByb3BlcnR5KG92ZXJyaWRlcywgaSkpIHtcbiAgICAgICAgICAgICAgICBzdWJjLnByb3RvdHlwZVtpXT1vdmVycmlkZXNbaV07XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBMLl9JRUVudW1GaXgoc3ViYy5wcm90b3R5cGUsIG92ZXJyaWRlcyk7XG4gICAgfVxufTtcblxuLypcbiAqIGFzbjEuanMgLSBBU04uMSBERVIgZW5jb2RlciBjbGFzc2VzXG4gKlxuICogQ29weXJpZ2h0IChjKSAyMDEzIEtlbmppIFVydXNoaW1hIChrZW5qaS51cnVzaGltYUBnbWFpbC5jb20pXG4gKlxuICogVGhpcyBzb2Z0d2FyZSBpcyBsaWNlbnNlZCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIE1JVCBMaWNlbnNlLlxuICogaHR0cDovL2tqdXIuZ2l0aHViLmNvbS9qc3JzYXNpZ24vbGljZW5zZVxuICpcbiAqIFRoZSBhYm92ZSBjb3B5cmlnaHQgYW5kIGxpY2Vuc2Ugbm90aWNlIHNoYWxsIGJlIFxuICogaW5jbHVkZWQgaW4gYWxsIGNvcGllcyBvciBzdWJzdGFudGlhbCBwb3J0aW9ucyBvZiB0aGUgU29mdHdhcmUuXG4gKi9cblxuLyoqXG4gKiBAZmlsZU92ZXJ2aWV3XG4gKiBAbmFtZSBhc24xLTEuMC5qc1xuICogQGF1dGhvciBLZW5qaSBVcnVzaGltYSBrZW5qaS51cnVzaGltYUBnbWFpbC5jb21cbiAqIEB2ZXJzaW9uIDEuMC4yICgyMDEzLU1heS0zMClcbiAqIEBzaW5jZSAyLjFcbiAqIEBsaWNlbnNlIDxhIGhyZWY9XCJodHRwOi8va2p1ci5naXRodWIuaW8vanNyc2FzaWduL2xpY2Vuc2UvXCI+TUlUIExpY2Vuc2U8L2E+XG4gKi9cblxuLyoqIFxuICoga2p1cidzIGNsYXNzIGxpYnJhcnkgbmFtZSBzcGFjZVxuICogPHA+XG4gKiBUaGlzIG5hbWUgc3BhY2UgcHJvdmlkZXMgZm9sbG93aW5nIG5hbWUgc3BhY2VzOlxuICogPHVsPlxuICogPGxpPntAbGluayBLSlVSLmFzbjF9IC0gQVNOLjEgcHJpbWl0aXZlIGhleGFkZWNpbWFsIGVuY29kZXI8L2xpPlxuICogPGxpPntAbGluayBLSlVSLmFzbjEueDUwOX0gLSBBU04uMSBzdHJ1Y3R1cmUgZm9yIFguNTA5IGNlcnRpZmljYXRlIGFuZCBDUkw8L2xpPlxuICogPGxpPntAbGluayBLSlVSLmNyeXB0b30gLSBKYXZhIENyeXB0b2dyYXBoaWMgRXh0ZW5zaW9uKEpDRSkgc3R5bGUgTWVzc2FnZURpZ2VzdC9TaWduYXR1cmUgXG4gKiBjbGFzcyBhbmQgdXRpbGl0aWVzPC9saT5cbiAqIDwvdWw+XG4gKiA8L3A+IFxuICogTk9URTogUGxlYXNlIGlnbm9yZSBtZXRob2Qgc3VtbWFyeSBhbmQgZG9jdW1lbnQgb2YgdGhpcyBuYW1lc3BhY2UuIFRoaXMgY2F1c2VkIGJ5IGEgYnVnIG9mIGpzZG9jMi5cbiAgKiBAbmFtZSBLSlVSXG4gKiBAbmFtZXNwYWNlIGtqdXIncyBjbGFzcyBsaWJyYXJ5IG5hbWUgc3BhY2VcbiAqL1xuaWYgKHR5cGVvZiBLSlVSID09IFwidW5kZWZpbmVkXCIgfHwgIUtKVVIpIEtKVVIgPSB7fTtcblxuLyoqXG4gKiBranVyJ3MgQVNOLjEgY2xhc3MgbGlicmFyeSBuYW1lIHNwYWNlXG4gKiA8cD5cbiAqIFRoaXMgaXMgSVRVLVQgWC42OTAgQVNOLjEgREVSIGVuY29kZXIgY2xhc3MgbGlicmFyeSBhbmRcbiAqIGNsYXNzIHN0cnVjdHVyZSBhbmQgbWV0aG9kcyBpcyB2ZXJ5IHNpbWlsYXIgdG8gXG4gKiBvcmcuYm91bmN5Y2FzdGxlLmFzbjEgcGFja2FnZSBvZiBcbiAqIHdlbGwga25vd24gQm91bmN5Q2FzbHRlIENyeXB0b2dyYXBoeSBMaWJyYXJ5LlxuICpcbiAqIDxoND5QUk9WSURJTkcgQVNOLjEgUFJJTUlUSVZFUzwvaDQ+XG4gKiBIZXJlIGFyZSBBU04uMSBERVIgcHJpbWl0aXZlIGNsYXNzZXMuXG4gKiA8dWw+XG4gKiA8bGk+e0BsaW5rIEtKVVIuYXNuMS5ERVJCb29sZWFufTwvbGk+XG4gKiA8bGk+e0BsaW5rIEtKVVIuYXNuMS5ERVJJbnRlZ2VyfTwvbGk+XG4gKiA8bGk+e0BsaW5rIEtKVVIuYXNuMS5ERVJCaXRTdHJpbmd9PC9saT5cbiAqIDxsaT57QGxpbmsgS0pVUi5hc24xLkRFUk9jdGV0U3RyaW5nfTwvbGk+XG4gKiA8bGk+e0BsaW5rIEtKVVIuYXNuMS5ERVJOdWxsfTwvbGk+XG4gKiA8bGk+e0BsaW5rIEtKVVIuYXNuMS5ERVJPYmplY3RJZGVudGlmaWVyfTwvbGk+XG4gKiA8bGk+e0BsaW5rIEtKVVIuYXNuMS5ERVJVVEY4U3RyaW5nfTwvbGk+XG4gKiA8bGk+e0BsaW5rIEtKVVIuYXNuMS5ERVJOdW1lcmljU3RyaW5nfTwvbGk+XG4gKiA8bGk+e0BsaW5rIEtKVVIuYXNuMS5ERVJQcmludGFibGVTdHJpbmd9PC9saT5cbiAqIDxsaT57QGxpbmsgS0pVUi5hc24xLkRFUlRlbGV0ZXhTdHJpbmd9PC9saT5cbiAqIDxsaT57QGxpbmsgS0pVUi5hc24xLkRFUklBNVN0cmluZ308L2xpPlxuICogPGxpPntAbGluayBLSlVSLmFzbjEuREVSVVRDVGltZX08L2xpPlxuICogPGxpPntAbGluayBLSlVSLmFzbjEuREVSR2VuZXJhbGl6ZWRUaW1lfTwvbGk+XG4gKiA8bGk+e0BsaW5rIEtKVVIuYXNuMS5ERVJTZXF1ZW5jZX08L2xpPlxuICogPGxpPntAbGluayBLSlVSLmFzbjEuREVSU2V0fTwvbGk+XG4gKiA8L3VsPlxuICpcbiAqIDxoND5PVEhFUiBBU04uMSBDTEFTU0VTPC9oND5cbiAqIDx1bD5cbiAqIDxsaT57QGxpbmsgS0pVUi5hc24xLkFTTjFPYmplY3R9PC9saT5cbiAqIDxsaT57QGxpbmsgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nfTwvbGk+XG4gKiA8bGk+e0BsaW5rIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFRpbWV9PC9saT5cbiAqIDxsaT57QGxpbmsgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RydWN0dXJlZH08L2xpPlxuICogPGxpPntAbGluayBLSlVSLmFzbjEuREVSVGFnZ2VkT2JqZWN0fTwvbGk+XG4gKiA8L3VsPlxuICogPC9wPlxuICogTk9URTogUGxlYXNlIGlnbm9yZSBtZXRob2Qgc3VtbWFyeSBhbmQgZG9jdW1lbnQgb2YgdGhpcyBuYW1lc3BhY2UuIFRoaXMgY2F1c2VkIGJ5IGEgYnVnIG9mIGpzZG9jMi5cbiAqIEBuYW1lIEtKVVIuYXNuMVxuICogQG5hbWVzcGFjZVxuICovXG5pZiAodHlwZW9mIEtKVVIuYXNuMSA9PSBcInVuZGVmaW5lZFwiIHx8ICFLSlVSLmFzbjEpIEtKVVIuYXNuMSA9IHt9O1xuXG4vKipcbiAqIEFTTjEgdXRpbGl0aWVzIGNsYXNzXG4gKiBAbmFtZSBLSlVSLmFzbjEuQVNOMVV0aWxcbiAqIEBjbGFzc3MgQVNOMSB1dGlsaXRpZXMgY2xhc3NcbiAqIEBzaW5jZSBhc24xIDEuMC4yXG4gKi9cbktKVVIuYXNuMS5BU04xVXRpbCA9IG5ldyBmdW5jdGlvbigpIHtcbiAgICB0aGlzLmludGVnZXJUb0J5dGVIZXggPSBmdW5jdGlvbihpKSB7XG5cdHZhciBoID0gaS50b1N0cmluZygxNik7XG5cdGlmICgoaC5sZW5ndGggJSAyKSA9PSAxKSBoID0gJzAnICsgaDtcblx0cmV0dXJuIGg7XG4gICAgfTtcbiAgICB0aGlzLmJpZ0ludFRvTWluVHdvc0NvbXBsZW1lbnRzSGV4ID0gZnVuY3Rpb24oYmlnSW50ZWdlclZhbHVlKSB7XG5cdHZhciBoID0gYmlnSW50ZWdlclZhbHVlLnRvU3RyaW5nKDE2KTtcblx0aWYgKGguc3Vic3RyKDAsIDEpICE9ICctJykge1xuXHQgICAgaWYgKGgubGVuZ3RoICUgMiA9PSAxKSB7XG5cdFx0aCA9ICcwJyArIGg7XG5cdCAgICB9IGVsc2Uge1xuXHRcdGlmICghIGgubWF0Y2goL15bMC03XS8pKSB7XG5cdFx0ICAgIGggPSAnMDAnICsgaDtcblx0XHR9XG5cdCAgICB9XG5cdH0gZWxzZSB7XG5cdCAgICB2YXIgaFBvcyA9IGguc3Vic3RyKDEpO1xuXHQgICAgdmFyIHhvckxlbiA9IGhQb3MubGVuZ3RoO1xuXHQgICAgaWYgKHhvckxlbiAlIDIgPT0gMSkge1xuXHRcdHhvckxlbiArPSAxO1xuXHQgICAgfSBlbHNlIHtcblx0XHRpZiAoISBoLm1hdGNoKC9eWzAtN10vKSkge1xuXHRcdCAgICB4b3JMZW4gKz0gMjtcblx0XHR9XG5cdCAgICB9XG5cdCAgICB2YXIgaE1hc2sgPSAnJztcblx0ICAgIGZvciAodmFyIGkgPSAwOyBpIDwgeG9yTGVuOyBpKyspIHtcblx0XHRoTWFzayArPSAnZic7XG5cdCAgICB9XG5cdCAgICB2YXIgYmlNYXNrID0gbmV3IEJpZ0ludGVnZXIoaE1hc2ssIDE2KTtcblx0ICAgIHZhciBiaU5lZyA9IGJpTWFzay54b3IoYmlnSW50ZWdlclZhbHVlKS5hZGQoQmlnSW50ZWdlci5PTkUpO1xuXHQgICAgaCA9IGJpTmVnLnRvU3RyaW5nKDE2KS5yZXBsYWNlKC9eLS8sICcnKTtcblx0fVxuXHRyZXR1cm4gaDtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIGdldCBQRU0gc3RyaW5nIGZyb20gaGV4YWRlY2ltYWwgZGF0YSBhbmQgaGVhZGVyIHN0cmluZ1xuICAgICAqIEBuYW1lIGdldFBFTVN0cmluZ0Zyb21IZXhcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkFTTjFVdGlsXG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHBhcmFtIHtTdHJpbmd9IGRhdGFIZXggaGV4YWRlY2ltYWwgc3RyaW5nIG9mIFBFTSBib2R5XG4gICAgICogQHBhcmFtIHtTdHJpbmd9IHBlbUhlYWRlciBQRU0gaGVhZGVyIHN0cmluZyAoZXguICdSU0EgUFJJVkFURSBLRVknKVxuICAgICAqIEByZXR1cm4ge1N0cmluZ30gUEVNIGZvcm1hdHRlZCBzdHJpbmcgb2YgaW5wdXQgZGF0YVxuICAgICAqIEBkZXNjcmlwdGlvblxuICAgICAqIEBleGFtcGxlXG4gICAgICogdmFyIHBlbSAgPSBLSlVSLmFzbjEuQVNOMVV0aWwuZ2V0UEVNU3RyaW5nRnJvbUhleCgnNjE2MTYxJywgJ1JTQSBQUklWQVRFIEtFWScpO1xuICAgICAqIC8vIHZhbHVlIG9mIHBlbSB3aWxsIGJlOlxuICAgICAqIC0tLS0tQkVHSU4gUFJJVkFURSBLRVktLS0tLVxuICAgICAqIFlXRmhcbiAgICAgKiAtLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tXG4gICAgICovXG4gICAgdGhpcy5nZXRQRU1TdHJpbmdGcm9tSGV4ID0gZnVuY3Rpb24oZGF0YUhleCwgcGVtSGVhZGVyKSB7XG5cdHZhciBkYXRhV0EgPSBDcnlwdG9KUy5lbmMuSGV4LnBhcnNlKGRhdGFIZXgpO1xuXHR2YXIgZGF0YUI2NCA9IENyeXB0b0pTLmVuYy5CYXNlNjQuc3RyaW5naWZ5KGRhdGFXQSk7XG5cdHZhciBwZW1Cb2R5ID0gZGF0YUI2NC5yZXBsYWNlKC8oLns2NH0pL2csIFwiJDFcXHJcXG5cIik7XG4gICAgICAgIHBlbUJvZHkgPSBwZW1Cb2R5LnJlcGxhY2UoL1xcclxcbiQvLCAnJyk7XG5cdHJldHVybiBcIi0tLS0tQkVHSU4gXCIgKyBwZW1IZWFkZXIgKyBcIi0tLS0tXFxyXFxuXCIgKyBcbiAgICAgICAgICAgICAgIHBlbUJvZHkgKyBcbiAgICAgICAgICAgICAgIFwiXFxyXFxuLS0tLS1FTkQgXCIgKyBwZW1IZWFkZXIgKyBcIi0tLS0tXFxyXFxuXCI7XG4gICAgfTtcbn07XG5cbi8vICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXG4vLyAgQWJzdHJhY3QgQVNOLjEgQ2xhc3Nlc1xuLy8gKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcblxuLy8gKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcblxuLyoqXG4gKiBiYXNlIGNsYXNzIGZvciBBU04uMSBERVIgZW5jb2RlciBvYmplY3RcbiAqIEBuYW1lIEtKVVIuYXNuMS5BU04xT2JqZWN0XG4gKiBAY2xhc3MgYmFzZSBjbGFzcyBmb3IgQVNOLjEgREVSIGVuY29kZXIgb2JqZWN0XG4gKiBAcHJvcGVydHkge0Jvb2xlYW59IGlzTW9kaWZpZWQgZmxhZyB3aGV0aGVyIGludGVybmFsIGRhdGEgd2FzIGNoYW5nZWRcbiAqIEBwcm9wZXJ0eSB7U3RyaW5nfSBoVExWIGhleGFkZWNpbWFsIHN0cmluZyBvZiBBU04uMSBUTFZcbiAqIEBwcm9wZXJ0eSB7U3RyaW5nfSBoVCBoZXhhZGVjaW1hbCBzdHJpbmcgb2YgQVNOLjEgVExWIHRhZyhUKVxuICogQHByb3BlcnR5IHtTdHJpbmd9IGhMIGhleGFkZWNpbWFsIHN0cmluZyBvZiBBU04uMSBUTFYgbGVuZ3RoKEwpXG4gKiBAcHJvcGVydHkge1N0cmluZ30gaFYgaGV4YWRlY2ltYWwgc3RyaW5nIG9mIEFTTi4xIFRMViB2YWx1ZShWKVxuICogQGRlc2NyaXB0aW9uXG4gKi9cbktKVVIuYXNuMS5BU04xT2JqZWN0ID0gZnVuY3Rpb24oKSB7XG4gICAgdmFyIGlzTW9kaWZpZWQgPSB0cnVlO1xuICAgIHZhciBoVExWID0gbnVsbDtcbiAgICB2YXIgaFQgPSAnMDAnXG4gICAgdmFyIGhMID0gJzAwJztcbiAgICB2YXIgaFYgPSAnJztcblxuICAgIC8qKlxuICAgICAqIGdldCBoZXhhZGVjaW1hbCBBU04uMSBUTFYgbGVuZ3RoKEwpIGJ5dGVzIGZyb20gVExWIHZhbHVlKFYpXG4gICAgICogQG5hbWUgZ2V0TGVuZ3RoSGV4RnJvbVZhbHVlXG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5BU04xT2JqZWN0XG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHJldHVybiB7U3RyaW5nfSBoZXhhZGVjaW1hbCBzdHJpbmcgb2YgQVNOLjEgVExWIGxlbmd0aChMKVxuICAgICAqL1xuICAgIHRoaXMuZ2V0TGVuZ3RoSGV4RnJvbVZhbHVlID0gZnVuY3Rpb24oKSB7XG5cdGlmICh0eXBlb2YgdGhpcy5oViA9PSBcInVuZGVmaW5lZFwiIHx8IHRoaXMuaFYgPT0gbnVsbCkge1xuXHQgICAgdGhyb3cgXCJ0aGlzLmhWIGlzIG51bGwgb3IgdW5kZWZpbmVkLlwiO1xuXHR9XG5cdGlmICh0aGlzLmhWLmxlbmd0aCAlIDIgPT0gMSkge1xuXHQgICAgdGhyb3cgXCJ2YWx1ZSBoZXggbXVzdCBiZSBldmVuIGxlbmd0aDogbj1cIiArIGhWLmxlbmd0aCArIFwiLHY9XCIgKyB0aGlzLmhWO1xuXHR9XG5cdHZhciBuID0gdGhpcy5oVi5sZW5ndGggLyAyO1xuXHR2YXIgaE4gPSBuLnRvU3RyaW5nKDE2KTtcblx0aWYgKGhOLmxlbmd0aCAlIDIgPT0gMSkge1xuXHQgICAgaE4gPSBcIjBcIiArIGhOO1xuXHR9XG5cdGlmIChuIDwgMTI4KSB7XG5cdCAgICByZXR1cm4gaE47XG5cdH0gZWxzZSB7XG5cdCAgICB2YXIgaE5sZW4gPSBoTi5sZW5ndGggLyAyO1xuXHQgICAgaWYgKGhObGVuID4gMTUpIHtcblx0XHR0aHJvdyBcIkFTTi4xIGxlbmd0aCB0b28gbG9uZyB0byByZXByZXNlbnQgYnkgOHg6IG4gPSBcIiArIG4udG9TdHJpbmcoMTYpO1xuXHQgICAgfVxuXHQgICAgdmFyIGhlYWQgPSAxMjggKyBoTmxlbjtcblx0ICAgIHJldHVybiBoZWFkLnRvU3RyaW5nKDE2KSArIGhOO1xuXHR9XG4gICAgfTtcblxuICAgIC8qKlxuICAgICAqIGdldCBoZXhhZGVjaW1hbCBzdHJpbmcgb2YgQVNOLjEgVExWIGJ5dGVzXG4gICAgICogQG5hbWUgZ2V0RW5jb2RlZEhleFxuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuQVNOMU9iamVjdFxuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEByZXR1cm4ge1N0cmluZ30gaGV4YWRlY2ltYWwgc3RyaW5nIG9mIEFTTi4xIFRMVlxuICAgICAqL1xuICAgIHRoaXMuZ2V0RW5jb2RlZEhleCA9IGZ1bmN0aW9uKCkge1xuXHRpZiAodGhpcy5oVExWID09IG51bGwgfHwgdGhpcy5pc01vZGlmaWVkKSB7XG5cdCAgICB0aGlzLmhWID0gdGhpcy5nZXRGcmVzaFZhbHVlSGV4KCk7XG5cdCAgICB0aGlzLmhMID0gdGhpcy5nZXRMZW5ndGhIZXhGcm9tVmFsdWUoKTtcblx0ICAgIHRoaXMuaFRMViA9IHRoaXMuaFQgKyB0aGlzLmhMICsgdGhpcy5oVjtcblx0ICAgIHRoaXMuaXNNb2RpZmllZCA9IGZhbHNlO1xuXHQgICAgLy9jb25zb2xlLmVycm9yKFwiZmlyc3QgdGltZTogXCIgKyB0aGlzLmhUTFYpO1xuXHR9XG5cdHJldHVybiB0aGlzLmhUTFY7XG4gICAgfTtcblxuICAgIC8qKlxuICAgICAqIGdldCBoZXhhZGVjaW1hbCBzdHJpbmcgb2YgQVNOLjEgVExWIHZhbHVlKFYpIGJ5dGVzXG4gICAgICogQG5hbWUgZ2V0VmFsdWVIZXhcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkFTTjFPYmplY3RcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcmV0dXJuIHtTdHJpbmd9IGhleGFkZWNpbWFsIHN0cmluZyBvZiBBU04uMSBUTFYgdmFsdWUoVikgYnl0ZXNcbiAgICAgKi9cbiAgICB0aGlzLmdldFZhbHVlSGV4ID0gZnVuY3Rpb24oKSB7XG5cdHRoaXMuZ2V0RW5jb2RlZEhleCgpO1xuXHRyZXR1cm4gdGhpcy5oVjtcbiAgICB9XG5cbiAgICB0aGlzLmdldEZyZXNoVmFsdWVIZXggPSBmdW5jdGlvbigpIHtcblx0cmV0dXJuICcnO1xuICAgIH07XG59O1xuXG4vLyA9PSBCRUdJTiBERVJBYnN0cmFjdFN0cmluZyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cbi8qKlxuICogYmFzZSBjbGFzcyBmb3IgQVNOLjEgREVSIHN0cmluZyBjbGFzc2VzXG4gKiBAbmFtZSBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmdcbiAqIEBjbGFzcyBiYXNlIGNsYXNzIGZvciBBU04uMSBERVIgc3RyaW5nIGNsYXNzZXNcbiAqIEBwYXJhbSB7QXJyYXl9IHBhcmFtcyBhc3NvY2lhdGl2ZSBhcnJheSBvZiBwYXJhbWV0ZXJzIChleC4geydzdHInOiAnYWFhJ30pXG4gKiBAcHJvcGVydHkge1N0cmluZ30gcyBpbnRlcm5hbCBzdHJpbmcgb2YgdmFsdWVcbiAqIEBleHRlbmRzIEtKVVIuYXNuMS5BU04xT2JqZWN0XG4gKiBAZGVzY3JpcHRpb25cbiAqIDxici8+XG4gKiBBcyBmb3IgYXJndW1lbnQgJ3BhcmFtcycgZm9yIGNvbnN0cnVjdG9yLCB5b3UgY2FuIHNwZWNpZnkgb25lIG9mXG4gKiBmb2xsb3dpbmcgcHJvcGVydGllczpcbiAqIDx1bD5cbiAqIDxsaT5zdHIgLSBzcGVjaWZ5IGluaXRpYWwgQVNOLjEgdmFsdWUoVikgYnkgYSBzdHJpbmc8L2xpPlxuICogPGxpPmhleCAtIHNwZWNpZnkgaW5pdGlhbCBBU04uMSB2YWx1ZShWKSBieSBhIGhleGFkZWNpbWFsIHN0cmluZzwvbGk+XG4gKiA8L3VsPlxuICogTk9URTogJ3BhcmFtcycgY2FuIGJlIG9taXR0ZWQuXG4gKi9cbktKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZyA9IGZ1bmN0aW9uKHBhcmFtcykge1xuICAgIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZy5zdXBlcmNsYXNzLmNvbnN0cnVjdG9yLmNhbGwodGhpcyk7XG4gICAgdmFyIHMgPSBudWxsO1xuICAgIHZhciBoViA9IG51bGw7XG5cbiAgICAvKipcbiAgICAgKiBnZXQgc3RyaW5nIHZhbHVlIG9mIHRoaXMgc3RyaW5nIG9iamVjdFxuICAgICAqIEBuYW1lIGdldFN0cmluZ1xuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmdcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcmV0dXJuIHtTdHJpbmd9IHN0cmluZyB2YWx1ZSBvZiB0aGlzIHN0cmluZyBvYmplY3RcbiAgICAgKi9cbiAgICB0aGlzLmdldFN0cmluZyA9IGZ1bmN0aW9uKCkge1xuXHRyZXR1cm4gdGhpcy5zO1xuICAgIH07XG5cbiAgICAvKipcbiAgICAgKiBzZXQgdmFsdWUgYnkgYSBzdHJpbmdcbiAgICAgKiBAbmFtZSBzZXRTdHJpbmdcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nXG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHBhcmFtIHtTdHJpbmd9IG5ld1MgdmFsdWUgYnkgYSBzdHJpbmcgdG8gc2V0XG4gICAgICovXG4gICAgdGhpcy5zZXRTdHJpbmcgPSBmdW5jdGlvbihuZXdTKSB7XG5cdHRoaXMuaFRMViA9IG51bGw7XG5cdHRoaXMuaXNNb2RpZmllZCA9IHRydWU7XG5cdHRoaXMucyA9IG5ld1M7XG5cdHRoaXMuaFYgPSBzdG9oZXgodGhpcy5zKTtcbiAgICB9O1xuXG4gICAgLyoqXG4gICAgICogc2V0IHZhbHVlIGJ5IGEgaGV4YWRlY2ltYWwgc3RyaW5nXG4gICAgICogQG5hbWUgc2V0U3RyaW5nSGV4XG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZ1xuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEBwYXJhbSB7U3RyaW5nfSBuZXdIZXhTdHJpbmcgdmFsdWUgYnkgYSBoZXhhZGVjaW1hbCBzdHJpbmcgdG8gc2V0XG4gICAgICovXG4gICAgdGhpcy5zZXRTdHJpbmdIZXggPSBmdW5jdGlvbihuZXdIZXhTdHJpbmcpIHtcblx0dGhpcy5oVExWID0gbnVsbDtcblx0dGhpcy5pc01vZGlmaWVkID0gdHJ1ZTtcblx0dGhpcy5zID0gbnVsbDtcblx0dGhpcy5oViA9IG5ld0hleFN0cmluZztcbiAgICB9O1xuXG4gICAgdGhpcy5nZXRGcmVzaFZhbHVlSGV4ID0gZnVuY3Rpb24oKSB7XG5cdHJldHVybiB0aGlzLmhWO1xuICAgIH07XG5cbiAgICBpZiAodHlwZW9mIHBhcmFtcyAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdGlmICh0eXBlb2YgcGFyYW1zWydzdHInXSAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdCAgICB0aGlzLnNldFN0cmluZyhwYXJhbXNbJ3N0ciddKTtcblx0fSBlbHNlIGlmICh0eXBlb2YgcGFyYW1zWydoZXgnXSAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdCAgICB0aGlzLnNldFN0cmluZ0hleChwYXJhbXNbJ2hleCddKTtcblx0fVxuICAgIH1cbn07XG5KU1guZXh0ZW5kKEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZywgS0pVUi5hc24xLkFTTjFPYmplY3QpO1xuLy8gPT0gRU5EICAgREVSQWJzdHJhY3RTdHJpbmcgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG5cbi8vID09IEJFR0lOIERFUkFic3RyYWN0VGltZSA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxuLyoqXG4gKiBiYXNlIGNsYXNzIGZvciBBU04uMSBERVIgR2VuZXJhbGl6ZWQvVVRDVGltZSBjbGFzc1xuICogQG5hbWUgS0pVUi5hc24xLkRFUkFic3RyYWN0VGltZVxuICogQGNsYXNzIGJhc2UgY2xhc3MgZm9yIEFTTi4xIERFUiBHZW5lcmFsaXplZC9VVENUaW1lIGNsYXNzXG4gKiBAcGFyYW0ge0FycmF5fSBwYXJhbXMgYXNzb2NpYXRpdmUgYXJyYXkgb2YgcGFyYW1ldGVycyAoZXguIHsnc3RyJzogJzEzMDQzMDIzNTk1OVonfSlcbiAqIEBleHRlbmRzIEtKVVIuYXNuMS5BU04xT2JqZWN0XG4gKiBAZGVzY3JpcHRpb25cbiAqIEBzZWUgS0pVUi5hc24xLkFTTjFPYmplY3QgLSBzdXBlcmNsYXNzXG4gKi9cbktKVVIuYXNuMS5ERVJBYnN0cmFjdFRpbWUgPSBmdW5jdGlvbihwYXJhbXMpIHtcbiAgICBLSlVSLmFzbjEuREVSQWJzdHJhY3RUaW1lLnN1cGVyY2xhc3MuY29uc3RydWN0b3IuY2FsbCh0aGlzKTtcbiAgICB2YXIgcyA9IG51bGw7XG4gICAgdmFyIGRhdGUgPSBudWxsO1xuXG4gICAgLy8gLS0tIFBSSVZBVEUgTUVUSE9EUyAtLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAgIHRoaXMubG9jYWxEYXRlVG9VVEMgPSBmdW5jdGlvbihkKSB7XG5cdHV0YyA9IGQuZ2V0VGltZSgpICsgKGQuZ2V0VGltZXpvbmVPZmZzZXQoKSAqIDYwMDAwKTtcblx0dmFyIHV0Y0RhdGUgPSBuZXcgRGF0ZSh1dGMpO1xuXHRyZXR1cm4gdXRjRGF0ZTtcbiAgICB9O1xuXG4gICAgdGhpcy5mb3JtYXREYXRlID0gZnVuY3Rpb24oZGF0ZU9iamVjdCwgdHlwZSkge1xuXHR2YXIgcGFkID0gdGhpcy56ZXJvUGFkZGluZztcblx0dmFyIGQgPSB0aGlzLmxvY2FsRGF0ZVRvVVRDKGRhdGVPYmplY3QpO1xuXHR2YXIgeWVhciA9IFN0cmluZyhkLmdldEZ1bGxZZWFyKCkpO1xuXHRpZiAodHlwZSA9PSAndXRjJykgeWVhciA9IHllYXIuc3Vic3RyKDIsIDIpO1xuXHR2YXIgbW9udGggPSBwYWQoU3RyaW5nKGQuZ2V0TW9udGgoKSArIDEpLCAyKTtcblx0dmFyIGRheSA9IHBhZChTdHJpbmcoZC5nZXREYXRlKCkpLCAyKTtcblx0dmFyIGhvdXIgPSBwYWQoU3RyaW5nKGQuZ2V0SG91cnMoKSksIDIpO1xuXHR2YXIgbWluID0gcGFkKFN0cmluZyhkLmdldE1pbnV0ZXMoKSksIDIpO1xuXHR2YXIgc2VjID0gcGFkKFN0cmluZyhkLmdldFNlY29uZHMoKSksIDIpO1xuXHRyZXR1cm4geWVhciArIG1vbnRoICsgZGF5ICsgaG91ciArIG1pbiArIHNlYyArICdaJztcbiAgICB9O1xuXG4gICAgdGhpcy56ZXJvUGFkZGluZyA9IGZ1bmN0aW9uKHMsIGxlbikge1xuXHRpZiAocy5sZW5ndGggPj0gbGVuKSByZXR1cm4gcztcblx0cmV0dXJuIG5ldyBBcnJheShsZW4gLSBzLmxlbmd0aCArIDEpLmpvaW4oJzAnKSArIHM7XG4gICAgfTtcblxuICAgIC8vIC0tLSBQVUJMSUMgTUVUSE9EUyAtLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAgIC8qKlxuICAgICAqIGdldCBzdHJpbmcgdmFsdWUgb2YgdGhpcyBzdHJpbmcgb2JqZWN0XG4gICAgICogQG5hbWUgZ2V0U3RyaW5nXG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFRpbWVcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcmV0dXJuIHtTdHJpbmd9IHN0cmluZyB2YWx1ZSBvZiB0aGlzIHRpbWUgb2JqZWN0XG4gICAgICovXG4gICAgdGhpcy5nZXRTdHJpbmcgPSBmdW5jdGlvbigpIHtcblx0cmV0dXJuIHRoaXMucztcbiAgICB9O1xuXG4gICAgLyoqXG4gICAgICogc2V0IHZhbHVlIGJ5IGEgc3RyaW5nXG4gICAgICogQG5hbWUgc2V0U3RyaW5nXG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFRpbWVcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcGFyYW0ge1N0cmluZ30gbmV3UyB2YWx1ZSBieSBhIHN0cmluZyB0byBzZXQgc3VjaCBsaWtlIFwiMTMwNDMwMjM1OTU5WlwiXG4gICAgICovXG4gICAgdGhpcy5zZXRTdHJpbmcgPSBmdW5jdGlvbihuZXdTKSB7XG5cdHRoaXMuaFRMViA9IG51bGw7XG5cdHRoaXMuaXNNb2RpZmllZCA9IHRydWU7XG5cdHRoaXMucyA9IG5ld1M7XG5cdHRoaXMuaFYgPSBzdG9oZXgodGhpcy5zKTtcbiAgICB9O1xuXG4gICAgLyoqXG4gICAgICogc2V0IHZhbHVlIGJ5IGEgRGF0ZSBvYmplY3RcbiAgICAgKiBAbmFtZSBzZXRCeURhdGVWYWx1ZVxuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuREVSQWJzdHJhY3RUaW1lXG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHBhcmFtIHtJbnRlZ2VyfSB5ZWFyIHllYXIgb2YgZGF0ZSAoZXguIDIwMTMpXG4gICAgICogQHBhcmFtIHtJbnRlZ2VyfSBtb250aCBtb250aCBvZiBkYXRlIGJldHdlZW4gMSBhbmQgMTIgKGV4LiAxMilcbiAgICAgKiBAcGFyYW0ge0ludGVnZXJ9IGRheSBkYXkgb2YgbW9udGhcbiAgICAgKiBAcGFyYW0ge0ludGVnZXJ9IGhvdXIgaG91cnMgb2YgZGF0ZVxuICAgICAqIEBwYXJhbSB7SW50ZWdlcn0gbWluIG1pbnV0ZXMgb2YgZGF0ZVxuICAgICAqIEBwYXJhbSB7SW50ZWdlcn0gc2VjIHNlY29uZHMgb2YgZGF0ZVxuICAgICAqL1xuICAgIHRoaXMuc2V0QnlEYXRlVmFsdWUgPSBmdW5jdGlvbih5ZWFyLCBtb250aCwgZGF5LCBob3VyLCBtaW4sIHNlYykge1xuXHR2YXIgZGF0ZU9iamVjdCA9IG5ldyBEYXRlKERhdGUuVVRDKHllYXIsIG1vbnRoIC0gMSwgZGF5LCBob3VyLCBtaW4sIHNlYywgMCkpO1xuXHR0aGlzLnNldEJ5RGF0ZShkYXRlT2JqZWN0KTtcbiAgICB9O1xuXG4gICAgdGhpcy5nZXRGcmVzaFZhbHVlSGV4ID0gZnVuY3Rpb24oKSB7XG5cdHJldHVybiB0aGlzLmhWO1xuICAgIH07XG59O1xuSlNYLmV4dGVuZChLSlVSLmFzbjEuREVSQWJzdHJhY3RUaW1lLCBLSlVSLmFzbjEuQVNOMU9iamVjdCk7XG4vLyA9PSBFTkQgICBERVJBYnN0cmFjdFRpbWUgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cblxuLy8gPT0gQkVHSU4gREVSQWJzdHJhY3RTdHJ1Y3R1cmVkID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG4vKipcbiAqIGJhc2UgY2xhc3MgZm9yIEFTTi4xIERFUiBzdHJ1Y3R1cmVkIGNsYXNzXG4gKiBAbmFtZSBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJ1Y3R1cmVkXG4gKiBAY2xhc3MgYmFzZSBjbGFzcyBmb3IgQVNOLjEgREVSIHN0cnVjdHVyZWQgY2xhc3NcbiAqIEBwcm9wZXJ0eSB7QXJyYXl9IGFzbjFBcnJheSBpbnRlcm5hbCBhcnJheSBvZiBBU04xT2JqZWN0XG4gKiBAZXh0ZW5kcyBLSlVSLmFzbjEuQVNOMU9iamVjdFxuICogQGRlc2NyaXB0aW9uXG4gKiBAc2VlIEtKVVIuYXNuMS5BU04xT2JqZWN0IC0gc3VwZXJjbGFzc1xuICovXG5LSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJ1Y3R1cmVkID0gZnVuY3Rpb24ocGFyYW1zKSB7XG4gICAgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nLnN1cGVyY2xhc3MuY29uc3RydWN0b3IuY2FsbCh0aGlzKTtcbiAgICB2YXIgYXNuMUFycmF5ID0gbnVsbDtcblxuICAgIC8qKlxuICAgICAqIHNldCB2YWx1ZSBieSBhcnJheSBvZiBBU04xT2JqZWN0XG4gICAgICogQG5hbWUgc2V0QnlBU04xT2JqZWN0QXJyYXlcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RydWN0dXJlZFxuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEBwYXJhbSB7YXJyYXl9IGFzbjFPYmplY3RBcnJheSBhcnJheSBvZiBBU04xT2JqZWN0IHRvIHNldFxuICAgICAqL1xuICAgIHRoaXMuc2V0QnlBU04xT2JqZWN0QXJyYXkgPSBmdW5jdGlvbihhc24xT2JqZWN0QXJyYXkpIHtcblx0dGhpcy5oVExWID0gbnVsbDtcblx0dGhpcy5pc01vZGlmaWVkID0gdHJ1ZTtcblx0dGhpcy5hc24xQXJyYXkgPSBhc24xT2JqZWN0QXJyYXk7XG4gICAgfTtcblxuICAgIC8qKlxuICAgICAqIGFwcGVuZCBhbiBBU04xT2JqZWN0IHRvIGludGVybmFsIGFycmF5XG4gICAgICogQG5hbWUgYXBwZW5kQVNOMU9iamVjdFxuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJ1Y3R1cmVkXG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHBhcmFtIHtBU04xT2JqZWN0fSBhc24xT2JqZWN0IHRvIGFkZFxuICAgICAqL1xuICAgIHRoaXMuYXBwZW5kQVNOMU9iamVjdCA9IGZ1bmN0aW9uKGFzbjFPYmplY3QpIHtcblx0dGhpcy5oVExWID0gbnVsbDtcblx0dGhpcy5pc01vZGlmaWVkID0gdHJ1ZTtcblx0dGhpcy5hc24xQXJyYXkucHVzaChhc24xT2JqZWN0KTtcbiAgICB9O1xuXG4gICAgdGhpcy5hc24xQXJyYXkgPSBuZXcgQXJyYXkoKTtcbiAgICBpZiAodHlwZW9mIHBhcmFtcyAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdGlmICh0eXBlb2YgcGFyYW1zWydhcnJheSddICE9IFwidW5kZWZpbmVkXCIpIHtcblx0ICAgIHRoaXMuYXNuMUFycmF5ID0gcGFyYW1zWydhcnJheSddO1xuXHR9XG4gICAgfVxufTtcbkpTWC5leHRlbmQoS0pVUi5hc24xLkRFUkFic3RyYWN0U3RydWN0dXJlZCwgS0pVUi5hc24xLkFTTjFPYmplY3QpO1xuXG5cbi8vICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXG4vLyAgQVNOLjEgT2JqZWN0IENsYXNzZXNcbi8vICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXG5cbi8vICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXG4vKipcbiAqIGNsYXNzIGZvciBBU04uMSBERVIgQm9vbGVhblxuICogQG5hbWUgS0pVUi5hc24xLkRFUkJvb2xlYW5cbiAqIEBjbGFzcyBjbGFzcyBmb3IgQVNOLjEgREVSIEJvb2xlYW5cbiAqIEBleHRlbmRzIEtKVVIuYXNuMS5BU04xT2JqZWN0XG4gKiBAZGVzY3JpcHRpb25cbiAqIEBzZWUgS0pVUi5hc24xLkFTTjFPYmplY3QgLSBzdXBlcmNsYXNzXG4gKi9cbktKVVIuYXNuMS5ERVJCb29sZWFuID0gZnVuY3Rpb24oKSB7XG4gICAgS0pVUi5hc24xLkRFUkJvb2xlYW4uc3VwZXJjbGFzcy5jb25zdHJ1Y3Rvci5jYWxsKHRoaXMpO1xuICAgIHRoaXMuaFQgPSBcIjAxXCI7XG4gICAgdGhpcy5oVExWID0gXCIwMTAxZmZcIjtcbn07XG5KU1guZXh0ZW5kKEtKVVIuYXNuMS5ERVJCb29sZWFuLCBLSlVSLmFzbjEuQVNOMU9iamVjdCk7XG5cbi8vICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXG4vKipcbiAqIGNsYXNzIGZvciBBU04uMSBERVIgSW50ZWdlclxuICogQG5hbWUgS0pVUi5hc24xLkRFUkludGVnZXJcbiAqIEBjbGFzcyBjbGFzcyBmb3IgQVNOLjEgREVSIEludGVnZXJcbiAqIEBleHRlbmRzIEtKVVIuYXNuMS5BU04xT2JqZWN0XG4gKiBAZGVzY3JpcHRpb25cbiAqIDxici8+XG4gKiBBcyBmb3IgYXJndW1lbnQgJ3BhcmFtcycgZm9yIGNvbnN0cnVjdG9yLCB5b3UgY2FuIHNwZWNpZnkgb25lIG9mXG4gKiBmb2xsb3dpbmcgcHJvcGVydGllczpcbiAqIDx1bD5cbiAqIDxsaT5pbnQgLSBzcGVjaWZ5IGluaXRpYWwgQVNOLjEgdmFsdWUoVikgYnkgaW50ZWdlciB2YWx1ZTwvbGk+XG4gKiA8bGk+YmlnaW50IC0gc3BlY2lmeSBpbml0aWFsIEFTTi4xIHZhbHVlKFYpIGJ5IEJpZ0ludGVnZXIgb2JqZWN0PC9saT5cbiAqIDxsaT5oZXggLSBzcGVjaWZ5IGluaXRpYWwgQVNOLjEgdmFsdWUoVikgYnkgYSBoZXhhZGVjaW1hbCBzdHJpbmc8L2xpPlxuICogPC91bD5cbiAqIE5PVEU6ICdwYXJhbXMnIGNhbiBiZSBvbWl0dGVkLlxuICovXG5LSlVSLmFzbjEuREVSSW50ZWdlciA9IGZ1bmN0aW9uKHBhcmFtcykge1xuICAgIEtKVVIuYXNuMS5ERVJJbnRlZ2VyLnN1cGVyY2xhc3MuY29uc3RydWN0b3IuY2FsbCh0aGlzKTtcbiAgICB0aGlzLmhUID0gXCIwMlwiO1xuXG4gICAgLyoqXG4gICAgICogc2V0IHZhbHVlIGJ5IFRvbSBXdSdzIEJpZ0ludGVnZXIgb2JqZWN0XG4gICAgICogQG5hbWUgc2V0QnlCaWdJbnRlZ2VyXG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5ERVJJbnRlZ2VyXG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHBhcmFtIHtCaWdJbnRlZ2VyfSBiaWdJbnRlZ2VyVmFsdWUgdG8gc2V0XG4gICAgICovXG4gICAgdGhpcy5zZXRCeUJpZ0ludGVnZXIgPSBmdW5jdGlvbihiaWdJbnRlZ2VyVmFsdWUpIHtcblx0dGhpcy5oVExWID0gbnVsbDtcblx0dGhpcy5pc01vZGlmaWVkID0gdHJ1ZTtcblx0dGhpcy5oViA9IEtKVVIuYXNuMS5BU04xVXRpbC5iaWdJbnRUb01pblR3b3NDb21wbGVtZW50c0hleChiaWdJbnRlZ2VyVmFsdWUpO1xuICAgIH07XG5cbiAgICAvKipcbiAgICAgKiBzZXQgdmFsdWUgYnkgaW50ZWdlciB2YWx1ZVxuICAgICAqIEBuYW1lIHNldEJ5SW50ZWdlclxuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuREVSSW50ZWdlclxuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEBwYXJhbSB7SW50ZWdlcn0gaW50ZWdlciB2YWx1ZSB0byBzZXRcbiAgICAgKi9cbiAgICB0aGlzLnNldEJ5SW50ZWdlciA9IGZ1bmN0aW9uKGludFZhbHVlKSB7XG5cdHZhciBiaSA9IG5ldyBCaWdJbnRlZ2VyKFN0cmluZyhpbnRWYWx1ZSksIDEwKTtcblx0dGhpcy5zZXRCeUJpZ0ludGVnZXIoYmkpO1xuICAgIH07XG5cbiAgICAvKipcbiAgICAgKiBzZXQgdmFsdWUgYnkgaW50ZWdlciB2YWx1ZVxuICAgICAqIEBuYW1lIHNldFZhbHVlSGV4XG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5ERVJJbnRlZ2VyXG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHBhcmFtIHtTdHJpbmd9IGhleGFkZWNpbWFsIHN0cmluZyBvZiBpbnRlZ2VyIHZhbHVlXG4gICAgICogQGRlc2NyaXB0aW9uXG4gICAgICogPGJyLz5cbiAgICAgKiBOT1RFOiBWYWx1ZSBzaGFsbCBiZSByZXByZXNlbnRlZCBieSBtaW5pbXVtIG9jdGV0IGxlbmd0aCBvZlxuICAgICAqIHR3bydzIGNvbXBsZW1lbnQgcmVwcmVzZW50YXRpb24uXG4gICAgICovXG4gICAgdGhpcy5zZXRWYWx1ZUhleCA9IGZ1bmN0aW9uKG5ld0hleFN0cmluZykge1xuXHR0aGlzLmhWID0gbmV3SGV4U3RyaW5nO1xuICAgIH07XG5cbiAgICB0aGlzLmdldEZyZXNoVmFsdWVIZXggPSBmdW5jdGlvbigpIHtcblx0cmV0dXJuIHRoaXMuaFY7XG4gICAgfTtcblxuICAgIGlmICh0eXBlb2YgcGFyYW1zICE9IFwidW5kZWZpbmVkXCIpIHtcblx0aWYgKHR5cGVvZiBwYXJhbXNbJ2JpZ2ludCddICE9IFwidW5kZWZpbmVkXCIpIHtcblx0ICAgIHRoaXMuc2V0QnlCaWdJbnRlZ2VyKHBhcmFtc1snYmlnaW50J10pO1xuXHR9IGVsc2UgaWYgKHR5cGVvZiBwYXJhbXNbJ2ludCddICE9IFwidW5kZWZpbmVkXCIpIHtcblx0ICAgIHRoaXMuc2V0QnlJbnRlZ2VyKHBhcmFtc1snaW50J10pO1xuXHR9IGVsc2UgaWYgKHR5cGVvZiBwYXJhbXNbJ2hleCddICE9IFwidW5kZWZpbmVkXCIpIHtcblx0ICAgIHRoaXMuc2V0VmFsdWVIZXgocGFyYW1zWydoZXgnXSk7XG5cdH1cbiAgICB9XG59O1xuSlNYLmV4dGVuZChLSlVSLmFzbjEuREVSSW50ZWdlciwgS0pVUi5hc24xLkFTTjFPYmplY3QpO1xuXG4vLyAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxuLyoqXG4gKiBjbGFzcyBmb3IgQVNOLjEgREVSIGVuY29kZWQgQml0U3RyaW5nIHByaW1pdGl2ZVxuICogQG5hbWUgS0pVUi5hc24xLkRFUkJpdFN0cmluZ1xuICogQGNsYXNzIGNsYXNzIGZvciBBU04uMSBERVIgZW5jb2RlZCBCaXRTdHJpbmcgcHJpbWl0aXZlXG4gKiBAZXh0ZW5kcyBLSlVSLmFzbjEuQVNOMU9iamVjdFxuICogQGRlc2NyaXB0aW9uIFxuICogPGJyLz5cbiAqIEFzIGZvciBhcmd1bWVudCAncGFyYW1zJyBmb3IgY29uc3RydWN0b3IsIHlvdSBjYW4gc3BlY2lmeSBvbmUgb2ZcbiAqIGZvbGxvd2luZyBwcm9wZXJ0aWVzOlxuICogPHVsPlxuICogPGxpPmJpbiAtIHNwZWNpZnkgYmluYXJ5IHN0cmluZyAoZXguICcxMDExMScpPC9saT5cbiAqIDxsaT5hcnJheSAtIHNwZWNpZnkgYXJyYXkgb2YgYm9vbGVhbiAoZXguIFt0cnVlLGZhbHNlLHRydWUsdHJ1ZV0pPC9saT5cbiAqIDxsaT5oZXggLSBzcGVjaWZ5IGhleGFkZWNpbWFsIHN0cmluZyBvZiBBU04uMSB2YWx1ZShWKSBpbmNsdWRpbmcgdW51c2VkIGJpdHM8L2xpPlxuICogPC91bD5cbiAqIE5PVEU6ICdwYXJhbXMnIGNhbiBiZSBvbWl0dGVkLlxuICovXG5LSlVSLmFzbjEuREVSQml0U3RyaW5nID0gZnVuY3Rpb24ocGFyYW1zKSB7XG4gICAgS0pVUi5hc24xLkRFUkJpdFN0cmluZy5zdXBlcmNsYXNzLmNvbnN0cnVjdG9yLmNhbGwodGhpcyk7XG4gICAgdGhpcy5oVCA9IFwiMDNcIjtcblxuICAgIC8qKlxuICAgICAqIHNldCBBU04uMSB2YWx1ZShWKSBieSBhIGhleGFkZWNpbWFsIHN0cmluZyBpbmNsdWRpbmcgdW51c2VkIGJpdHNcbiAgICAgKiBAbmFtZSBzZXRIZXhWYWx1ZUluY2x1ZGluZ1VudXNlZEJpdHNcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkRFUkJpdFN0cmluZ1xuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEBwYXJhbSB7U3RyaW5nfSBuZXdIZXhTdHJpbmdJbmNsdWRpbmdVbnVzZWRCaXRzXG4gICAgICovXG4gICAgdGhpcy5zZXRIZXhWYWx1ZUluY2x1ZGluZ1VudXNlZEJpdHMgPSBmdW5jdGlvbihuZXdIZXhTdHJpbmdJbmNsdWRpbmdVbnVzZWRCaXRzKSB7XG5cdHRoaXMuaFRMViA9IG51bGw7XG5cdHRoaXMuaXNNb2RpZmllZCA9IHRydWU7XG5cdHRoaXMuaFYgPSBuZXdIZXhTdHJpbmdJbmNsdWRpbmdVbnVzZWRCaXRzO1xuICAgIH07XG5cbiAgICAvKipcbiAgICAgKiBzZXQgQVNOLjEgdmFsdWUoVikgYnkgdW51c2VkIGJpdCBhbmQgaGV4YWRlY2ltYWwgc3RyaW5nIG9mIHZhbHVlXG4gICAgICogQG5hbWUgc2V0VW51c2VkQml0c0FuZEhleFZhbHVlXG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5ERVJCaXRTdHJpbmdcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcGFyYW0ge0ludGVnZXJ9IHVudXNlZEJpdHNcbiAgICAgKiBAcGFyYW0ge1N0cmluZ30gaFZhbHVlXG4gICAgICovXG4gICAgdGhpcy5zZXRVbnVzZWRCaXRzQW5kSGV4VmFsdWUgPSBmdW5jdGlvbih1bnVzZWRCaXRzLCBoVmFsdWUpIHtcblx0aWYgKHVudXNlZEJpdHMgPCAwIHx8IDcgPCB1bnVzZWRCaXRzKSB7XG5cdCAgICB0aHJvdyBcInVudXNlZCBiaXRzIHNoYWxsIGJlIGZyb20gMCB0byA3OiB1ID0gXCIgKyB1bnVzZWRCaXRzO1xuXHR9XG5cdHZhciBoVW51c2VkQml0cyA9IFwiMFwiICsgdW51c2VkQml0cztcblx0dGhpcy5oVExWID0gbnVsbDtcblx0dGhpcy5pc01vZGlmaWVkID0gdHJ1ZTtcblx0dGhpcy5oViA9IGhVbnVzZWRCaXRzICsgaFZhbHVlO1xuICAgIH07XG5cbiAgICAvKipcbiAgICAgKiBzZXQgQVNOLjEgREVSIEJpdFN0cmluZyBieSBiaW5hcnkgc3RyaW5nXG4gICAgICogQG5hbWUgc2V0QnlCaW5hcnlTdHJpbmdcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkRFUkJpdFN0cmluZ1xuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEBwYXJhbSB7U3RyaW5nfSBiaW5hcnlTdHJpbmcgYmluYXJ5IHZhbHVlIHN0cmluZyAoaS5lLiAnMTAxMTEnKVxuICAgICAqIEBkZXNjcmlwdGlvblxuICAgICAqIEl0cyB1bnVzZWQgYml0cyB3aWxsIGJlIGNhbGN1bGF0ZWQgYXV0b21hdGljYWxseSBieSBsZW5ndGggb2YgXG4gICAgICogJ2JpbmFyeVZhbHVlJy4gPGJyLz5cbiAgICAgKiBOT1RFOiBUcmFpbGluZyB6ZXJvcyAnMCcgd2lsbCBiZSBpZ25vcmVkLlxuICAgICAqL1xuICAgIHRoaXMuc2V0QnlCaW5hcnlTdHJpbmcgPSBmdW5jdGlvbihiaW5hcnlTdHJpbmcpIHtcblx0YmluYXJ5U3RyaW5nID0gYmluYXJ5U3RyaW5nLnJlcGxhY2UoLzArJC8sICcnKTtcblx0dmFyIHVudXNlZEJpdHMgPSA4IC0gYmluYXJ5U3RyaW5nLmxlbmd0aCAlIDg7XG5cdGlmICh1bnVzZWRCaXRzID09IDgpIHVudXNlZEJpdHMgPSAwO1xuXHRmb3IgKHZhciBpID0gMDsgaSA8PSB1bnVzZWRCaXRzOyBpKyspIHtcblx0ICAgIGJpbmFyeVN0cmluZyArPSAnMCc7XG5cdH1cblx0dmFyIGggPSAnJztcblx0Zm9yICh2YXIgaSA9IDA7IGkgPCBiaW5hcnlTdHJpbmcubGVuZ3RoIC0gMTsgaSArPSA4KSB7XG5cdCAgICB2YXIgYiA9IGJpbmFyeVN0cmluZy5zdWJzdHIoaSwgOCk7XG5cdCAgICB2YXIgeCA9IHBhcnNlSW50KGIsIDIpLnRvU3RyaW5nKDE2KTtcblx0ICAgIGlmICh4Lmxlbmd0aCA9PSAxKSB4ID0gJzAnICsgeDtcblx0ICAgIGggKz0geDsgIFxuXHR9XG5cdHRoaXMuaFRMViA9IG51bGw7XG5cdHRoaXMuaXNNb2RpZmllZCA9IHRydWU7XG5cdHRoaXMuaFYgPSAnMCcgKyB1bnVzZWRCaXRzICsgaDtcbiAgICB9O1xuXG4gICAgLyoqXG4gICAgICogc2V0IEFTTi4xIFRMViB2YWx1ZShWKSBieSBhbiBhcnJheSBvZiBib29sZWFuXG4gICAgICogQG5hbWUgc2V0QnlCb29sZWFuQXJyYXlcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkRFUkJpdFN0cmluZ1xuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEBwYXJhbSB7YXJyYXl9IGJvb2xlYW5BcnJheSBhcnJheSBvZiBib29sZWFuIChleC4gW3RydWUsIGZhbHNlLCB0cnVlXSlcbiAgICAgKiBAZGVzY3JpcHRpb25cbiAgICAgKiBOT1RFOiBUcmFpbGluZyBmYWxzZXMgd2lsbCBiZSBpZ25vcmVkLlxuICAgICAqL1xuICAgIHRoaXMuc2V0QnlCb29sZWFuQXJyYXkgPSBmdW5jdGlvbihib29sZWFuQXJyYXkpIHtcblx0dmFyIHMgPSAnJztcblx0Zm9yICh2YXIgaSA9IDA7IGkgPCBib29sZWFuQXJyYXkubGVuZ3RoOyBpKyspIHtcblx0ICAgIGlmIChib29sZWFuQXJyYXlbaV0gPT0gdHJ1ZSkge1xuXHRcdHMgKz0gJzEnO1xuXHQgICAgfSBlbHNlIHtcblx0XHRzICs9ICcwJztcblx0ICAgIH1cblx0fVxuXHR0aGlzLnNldEJ5QmluYXJ5U3RyaW5nKHMpO1xuICAgIH07XG5cbiAgICAvKipcbiAgICAgKiBnZW5lcmF0ZSBhbiBhcnJheSBvZiBmYWxzZSB3aXRoIHNwZWNpZmllZCBsZW5ndGhcbiAgICAgKiBAbmFtZSBuZXdGYWxzZUFycmF5XG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5ERVJCaXRTdHJpbmdcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcGFyYW0ge0ludGVnZXJ9IG5MZW5ndGggbGVuZ3RoIG9mIGFycmF5IHRvIGdlbmVyYXRlXG4gICAgICogQHJldHVybiB7YXJyYXl9IGFycmF5IG9mIGJvb2xlYW4gZmFsdXNlXG4gICAgICogQGRlc2NyaXB0aW9uXG4gICAgICogVGhpcyBzdGF0aWMgbWV0aG9kIG1heSBiZSB1c2VmdWwgdG8gaW5pdGlhbGl6ZSBib29sZWFuIGFycmF5LlxuICAgICAqL1xuICAgIHRoaXMubmV3RmFsc2VBcnJheSA9IGZ1bmN0aW9uKG5MZW5ndGgpIHtcblx0dmFyIGEgPSBuZXcgQXJyYXkobkxlbmd0aCk7XG5cdGZvciAodmFyIGkgPSAwOyBpIDwgbkxlbmd0aDsgaSsrKSB7XG5cdCAgICBhW2ldID0gZmFsc2U7XG5cdH1cblx0cmV0dXJuIGE7XG4gICAgfTtcblxuICAgIHRoaXMuZ2V0RnJlc2hWYWx1ZUhleCA9IGZ1bmN0aW9uKCkge1xuXHRyZXR1cm4gdGhpcy5oVjtcbiAgICB9O1xuXG4gICAgaWYgKHR5cGVvZiBwYXJhbXMgIT0gXCJ1bmRlZmluZWRcIikge1xuXHRpZiAodHlwZW9mIHBhcmFtc1snaGV4J10gIT0gXCJ1bmRlZmluZWRcIikge1xuXHQgICAgdGhpcy5zZXRIZXhWYWx1ZUluY2x1ZGluZ1VudXNlZEJpdHMocGFyYW1zWydoZXgnXSk7XG5cdH0gZWxzZSBpZiAodHlwZW9mIHBhcmFtc1snYmluJ10gIT0gXCJ1bmRlZmluZWRcIikge1xuXHQgICAgdGhpcy5zZXRCeUJpbmFyeVN0cmluZyhwYXJhbXNbJ2JpbiddKTtcblx0fSBlbHNlIGlmICh0eXBlb2YgcGFyYW1zWydhcnJheSddICE9IFwidW5kZWZpbmVkXCIpIHtcblx0ICAgIHRoaXMuc2V0QnlCb29sZWFuQXJyYXkocGFyYW1zWydhcnJheSddKTtcblx0fVxuICAgIH1cbn07XG5KU1guZXh0ZW5kKEtKVVIuYXNuMS5ERVJCaXRTdHJpbmcsIEtKVVIuYXNuMS5BU04xT2JqZWN0KTtcblxuLy8gKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcbi8qKlxuICogY2xhc3MgZm9yIEFTTi4xIERFUiBPY3RldFN0cmluZ1xuICogQG5hbWUgS0pVUi5hc24xLkRFUk9jdGV0U3RyaW5nXG4gKiBAY2xhc3MgY2xhc3MgZm9yIEFTTi4xIERFUiBPY3RldFN0cmluZ1xuICogQHBhcmFtIHtBcnJheX0gcGFyYW1zIGFzc29jaWF0aXZlIGFycmF5IG9mIHBhcmFtZXRlcnMgKGV4LiB7J3N0cic6ICdhYWEnfSlcbiAqIEBleHRlbmRzIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZ1xuICogQGRlc2NyaXB0aW9uXG4gKiBAc2VlIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZyAtIHN1cGVyY2xhc3NcbiAqL1xuS0pVUi5hc24xLkRFUk9jdGV0U3RyaW5nID0gZnVuY3Rpb24ocGFyYW1zKSB7XG4gICAgS0pVUi5hc24xLkRFUk9jdGV0U3RyaW5nLnN1cGVyY2xhc3MuY29uc3RydWN0b3IuY2FsbCh0aGlzLCBwYXJhbXMpO1xuICAgIHRoaXMuaFQgPSBcIjA0XCI7XG59O1xuSlNYLmV4dGVuZChLSlVSLmFzbjEuREVST2N0ZXRTdHJpbmcsIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZyk7XG5cbi8vICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXG4vKipcbiAqIGNsYXNzIGZvciBBU04uMSBERVIgTnVsbFxuICogQG5hbWUgS0pVUi5hc24xLkRFUk51bGxcbiAqIEBjbGFzcyBjbGFzcyBmb3IgQVNOLjEgREVSIE51bGxcbiAqIEBleHRlbmRzIEtKVVIuYXNuMS5BU04xT2JqZWN0XG4gKiBAZGVzY3JpcHRpb25cbiAqIEBzZWUgS0pVUi5hc24xLkFTTjFPYmplY3QgLSBzdXBlcmNsYXNzXG4gKi9cbktKVVIuYXNuMS5ERVJOdWxsID0gZnVuY3Rpb24oKSB7XG4gICAgS0pVUi5hc24xLkRFUk51bGwuc3VwZXJjbGFzcy5jb25zdHJ1Y3Rvci5jYWxsKHRoaXMpO1xuICAgIHRoaXMuaFQgPSBcIjA1XCI7XG4gICAgdGhpcy5oVExWID0gXCIwNTAwXCI7XG59O1xuSlNYLmV4dGVuZChLSlVSLmFzbjEuREVSTnVsbCwgS0pVUi5hc24xLkFTTjFPYmplY3QpO1xuXG4vLyAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxuLyoqXG4gKiBjbGFzcyBmb3IgQVNOLjEgREVSIE9iamVjdElkZW50aWZpZXJcbiAqIEBuYW1lIEtKVVIuYXNuMS5ERVJPYmplY3RJZGVudGlmaWVyXG4gKiBAY2xhc3MgY2xhc3MgZm9yIEFTTi4xIERFUiBPYmplY3RJZGVudGlmaWVyXG4gKiBAcGFyYW0ge0FycmF5fSBwYXJhbXMgYXNzb2NpYXRpdmUgYXJyYXkgb2YgcGFyYW1ldGVycyAoZXguIHsnb2lkJzogJzIuNS40LjUnfSlcbiAqIEBleHRlbmRzIEtKVVIuYXNuMS5BU04xT2JqZWN0XG4gKiBAZGVzY3JpcHRpb25cbiAqIDxici8+XG4gKiBBcyBmb3IgYXJndW1lbnQgJ3BhcmFtcycgZm9yIGNvbnN0cnVjdG9yLCB5b3UgY2FuIHNwZWNpZnkgb25lIG9mXG4gKiBmb2xsb3dpbmcgcHJvcGVydGllczpcbiAqIDx1bD5cbiAqIDxsaT5vaWQgLSBzcGVjaWZ5IGluaXRpYWwgQVNOLjEgdmFsdWUoVikgYnkgYSBvaWQgc3RyaW5nIChleC4gMi41LjQuMTMpPC9saT5cbiAqIDxsaT5oZXggLSBzcGVjaWZ5IGluaXRpYWwgQVNOLjEgdmFsdWUoVikgYnkgYSBoZXhhZGVjaW1hbCBzdHJpbmc8L2xpPlxuICogPC91bD5cbiAqIE5PVEU6ICdwYXJhbXMnIGNhbiBiZSBvbWl0dGVkLlxuICovXG5LSlVSLmFzbjEuREVST2JqZWN0SWRlbnRpZmllciA9IGZ1bmN0aW9uKHBhcmFtcykge1xuICAgIHZhciBpdG94ID0gZnVuY3Rpb24oaSkge1xuXHR2YXIgaCA9IGkudG9TdHJpbmcoMTYpO1xuXHRpZiAoaC5sZW5ndGggPT0gMSkgaCA9ICcwJyArIGg7XG5cdHJldHVybiBoO1xuICAgIH07XG4gICAgdmFyIHJvaWR0b3ggPSBmdW5jdGlvbihyb2lkKSB7XG5cdHZhciBoID0gJyc7XG5cdHZhciBiaSA9IG5ldyBCaWdJbnRlZ2VyKHJvaWQsIDEwKTtcblx0dmFyIGIgPSBiaS50b1N0cmluZygyKTtcblx0dmFyIHBhZExlbiA9IDcgLSBiLmxlbmd0aCAlIDc7XG5cdGlmIChwYWRMZW4gPT0gNykgcGFkTGVuID0gMDtcblx0dmFyIGJQYWQgPSAnJztcblx0Zm9yICh2YXIgaSA9IDA7IGkgPCBwYWRMZW47IGkrKykgYlBhZCArPSAnMCc7XG5cdGIgPSBiUGFkICsgYjtcblx0Zm9yICh2YXIgaSA9IDA7IGkgPCBiLmxlbmd0aCAtIDE7IGkgKz0gNykge1xuXHQgICAgdmFyIGI4ID0gYi5zdWJzdHIoaSwgNyk7XG5cdCAgICBpZiAoaSAhPSBiLmxlbmd0aCAtIDcpIGI4ID0gJzEnICsgYjg7XG5cdCAgICBoICs9IGl0b3gocGFyc2VJbnQoYjgsIDIpKTtcblx0fVxuXHRyZXR1cm4gaDtcbiAgICB9XG5cbiAgICBLSlVSLmFzbjEuREVST2JqZWN0SWRlbnRpZmllci5zdXBlcmNsYXNzLmNvbnN0cnVjdG9yLmNhbGwodGhpcyk7XG4gICAgdGhpcy5oVCA9IFwiMDZcIjtcblxuICAgIC8qKlxuICAgICAqIHNldCB2YWx1ZSBieSBhIGhleGFkZWNpbWFsIHN0cmluZ1xuICAgICAqIEBuYW1lIHNldFZhbHVlSGV4XG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5ERVJPYmplY3RJZGVudGlmaWVyXG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHBhcmFtIHtTdHJpbmd9IG5ld0hleFN0cmluZyBoZXhhZGVjaW1hbCB2YWx1ZSBvZiBPSUQgYnl0ZXNcbiAgICAgKi9cbiAgICB0aGlzLnNldFZhbHVlSGV4ID0gZnVuY3Rpb24obmV3SGV4U3RyaW5nKSB7XG5cdHRoaXMuaFRMViA9IG51bGw7XG5cdHRoaXMuaXNNb2RpZmllZCA9IHRydWU7XG5cdHRoaXMucyA9IG51bGw7XG5cdHRoaXMuaFYgPSBuZXdIZXhTdHJpbmc7XG4gICAgfTtcblxuICAgIC8qKlxuICAgICAqIHNldCB2YWx1ZSBieSBhIE9JRCBzdHJpbmdcbiAgICAgKiBAbmFtZSBzZXRWYWx1ZU9pZFN0cmluZ1xuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuREVST2JqZWN0SWRlbnRpZmllclxuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEBwYXJhbSB7U3RyaW5nfSBvaWRTdHJpbmcgT0lEIHN0cmluZyAoZXguIDIuNS40LjEzKVxuICAgICAqL1xuICAgIHRoaXMuc2V0VmFsdWVPaWRTdHJpbmcgPSBmdW5jdGlvbihvaWRTdHJpbmcpIHtcblx0aWYgKCEgb2lkU3RyaW5nLm1hdGNoKC9eWzAtOS5dKyQvKSkge1xuXHQgICAgdGhyb3cgXCJtYWxmb3JtZWQgb2lkIHN0cmluZzogXCIgKyBvaWRTdHJpbmc7XG5cdH1cblx0dmFyIGggPSAnJztcblx0dmFyIGEgPSBvaWRTdHJpbmcuc3BsaXQoJy4nKTtcblx0dmFyIGkwID0gcGFyc2VJbnQoYVswXSkgKiA0MCArIHBhcnNlSW50KGFbMV0pO1xuXHRoICs9IGl0b3goaTApO1xuXHRhLnNwbGljZSgwLCAyKTtcblx0Zm9yICh2YXIgaSA9IDA7IGkgPCBhLmxlbmd0aDsgaSsrKSB7XG5cdCAgICBoICs9IHJvaWR0b3goYVtpXSk7XG5cdH1cblx0dGhpcy5oVExWID0gbnVsbDtcblx0dGhpcy5pc01vZGlmaWVkID0gdHJ1ZTtcblx0dGhpcy5zID0gbnVsbDtcblx0dGhpcy5oViA9IGg7XG4gICAgfTtcblxuICAgIC8qKlxuICAgICAqIHNldCB2YWx1ZSBieSBhIE9JRCBuYW1lXG4gICAgICogQG5hbWUgc2V0VmFsdWVOYW1lXG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5ERVJPYmplY3RJZGVudGlmaWVyXG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHBhcmFtIHtTdHJpbmd9IG9pZE5hbWUgT0lEIG5hbWUgKGV4LiAnc2VydmVyQXV0aCcpXG4gICAgICogQHNpbmNlIDEuMC4xXG4gICAgICogQGRlc2NyaXB0aW9uXG4gICAgICogT0lEIG5hbWUgc2hhbGwgYmUgZGVmaW5lZCBpbiAnS0pVUi5hc24xLng1MDkuT0lELm5hbWUyb2lkTGlzdCcuXG4gICAgICogT3RoZXJ3aXNlIHJhaXNlIGVycm9yLlxuICAgICAqL1xuICAgIHRoaXMuc2V0VmFsdWVOYW1lID0gZnVuY3Rpb24ob2lkTmFtZSkge1xuXHRpZiAodHlwZW9mIEtKVVIuYXNuMS54NTA5Lk9JRC5uYW1lMm9pZExpc3Rbb2lkTmFtZV0gIT0gXCJ1bmRlZmluZWRcIikge1xuXHQgICAgdmFyIG9pZCA9IEtKVVIuYXNuMS54NTA5Lk9JRC5uYW1lMm9pZExpc3Rbb2lkTmFtZV07XG5cdCAgICB0aGlzLnNldFZhbHVlT2lkU3RyaW5nKG9pZCk7XG5cdH0gZWxzZSB7XG5cdCAgICB0aHJvdyBcIkRFUk9iamVjdElkZW50aWZpZXIgb2lkTmFtZSB1bmRlZmluZWQ6IFwiICsgb2lkTmFtZTtcblx0fVxuICAgIH07XG5cbiAgICB0aGlzLmdldEZyZXNoVmFsdWVIZXggPSBmdW5jdGlvbigpIHtcblx0cmV0dXJuIHRoaXMuaFY7XG4gICAgfTtcblxuICAgIGlmICh0eXBlb2YgcGFyYW1zICE9IFwidW5kZWZpbmVkXCIpIHtcblx0aWYgKHR5cGVvZiBwYXJhbXNbJ29pZCddICE9IFwidW5kZWZpbmVkXCIpIHtcblx0ICAgIHRoaXMuc2V0VmFsdWVPaWRTdHJpbmcocGFyYW1zWydvaWQnXSk7XG5cdH0gZWxzZSBpZiAodHlwZW9mIHBhcmFtc1snaGV4J10gIT0gXCJ1bmRlZmluZWRcIikge1xuXHQgICAgdGhpcy5zZXRWYWx1ZUhleChwYXJhbXNbJ2hleCddKTtcblx0fSBlbHNlIGlmICh0eXBlb2YgcGFyYW1zWyduYW1lJ10gIT0gXCJ1bmRlZmluZWRcIikge1xuXHQgICAgdGhpcy5zZXRWYWx1ZU5hbWUocGFyYW1zWyduYW1lJ10pO1xuXHR9XG4gICAgfVxufTtcbkpTWC5leHRlbmQoS0pVUi5hc24xLkRFUk9iamVjdElkZW50aWZpZXIsIEtKVVIuYXNuMS5BU04xT2JqZWN0KTtcblxuLy8gKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcbi8qKlxuICogY2xhc3MgZm9yIEFTTi4xIERFUiBVVEY4U3RyaW5nXG4gKiBAbmFtZSBLSlVSLmFzbjEuREVSVVRGOFN0cmluZ1xuICogQGNsYXNzIGNsYXNzIGZvciBBU04uMSBERVIgVVRGOFN0cmluZ1xuICogQHBhcmFtIHtBcnJheX0gcGFyYW1zIGFzc29jaWF0aXZlIGFycmF5IG9mIHBhcmFtZXRlcnMgKGV4LiB7J3N0cic6ICdhYWEnfSlcbiAqIEBleHRlbmRzIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZ1xuICogQGRlc2NyaXB0aW9uXG4gKiBAc2VlIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZyAtIHN1cGVyY2xhc3NcbiAqL1xuS0pVUi5hc24xLkRFUlVURjhTdHJpbmcgPSBmdW5jdGlvbihwYXJhbXMpIHtcbiAgICBLSlVSLmFzbjEuREVSVVRGOFN0cmluZy5zdXBlcmNsYXNzLmNvbnN0cnVjdG9yLmNhbGwodGhpcywgcGFyYW1zKTtcbiAgICB0aGlzLmhUID0gXCIwY1wiO1xufTtcbkpTWC5leHRlbmQoS0pVUi5hc24xLkRFUlVURjhTdHJpbmcsIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZyk7XG5cbi8vICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXG4vKipcbiAqIGNsYXNzIGZvciBBU04uMSBERVIgTnVtZXJpY1N0cmluZ1xuICogQG5hbWUgS0pVUi5hc24xLkRFUk51bWVyaWNTdHJpbmdcbiAqIEBjbGFzcyBjbGFzcyBmb3IgQVNOLjEgREVSIE51bWVyaWNTdHJpbmdcbiAqIEBwYXJhbSB7QXJyYXl9IHBhcmFtcyBhc3NvY2lhdGl2ZSBhcnJheSBvZiBwYXJhbWV0ZXJzIChleC4geydzdHInOiAnYWFhJ30pXG4gKiBAZXh0ZW5kcyBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmdcbiAqIEBkZXNjcmlwdGlvblxuICogQHNlZSBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmcgLSBzdXBlcmNsYXNzXG4gKi9cbktKVVIuYXNuMS5ERVJOdW1lcmljU3RyaW5nID0gZnVuY3Rpb24ocGFyYW1zKSB7XG4gICAgS0pVUi5hc24xLkRFUk51bWVyaWNTdHJpbmcuc3VwZXJjbGFzcy5jb25zdHJ1Y3Rvci5jYWxsKHRoaXMsIHBhcmFtcyk7XG4gICAgdGhpcy5oVCA9IFwiMTJcIjtcbn07XG5KU1guZXh0ZW5kKEtKVVIuYXNuMS5ERVJOdW1lcmljU3RyaW5nLCBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmcpO1xuXG4vLyAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxuLyoqXG4gKiBjbGFzcyBmb3IgQVNOLjEgREVSIFByaW50YWJsZVN0cmluZ1xuICogQG5hbWUgS0pVUi5hc24xLkRFUlByaW50YWJsZVN0cmluZ1xuICogQGNsYXNzIGNsYXNzIGZvciBBU04uMSBERVIgUHJpbnRhYmxlU3RyaW5nXG4gKiBAcGFyYW0ge0FycmF5fSBwYXJhbXMgYXNzb2NpYXRpdmUgYXJyYXkgb2YgcGFyYW1ldGVycyAoZXguIHsnc3RyJzogJ2FhYSd9KVxuICogQGV4dGVuZHMgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nXG4gKiBAZGVzY3JpcHRpb25cbiAqIEBzZWUgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nIC0gc3VwZXJjbGFzc1xuICovXG5LSlVSLmFzbjEuREVSUHJpbnRhYmxlU3RyaW5nID0gZnVuY3Rpb24ocGFyYW1zKSB7XG4gICAgS0pVUi5hc24xLkRFUlByaW50YWJsZVN0cmluZy5zdXBlcmNsYXNzLmNvbnN0cnVjdG9yLmNhbGwodGhpcywgcGFyYW1zKTtcbiAgICB0aGlzLmhUID0gXCIxM1wiO1xufTtcbkpTWC5leHRlbmQoS0pVUi5hc24xLkRFUlByaW50YWJsZVN0cmluZywgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nKTtcblxuLy8gKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcbi8qKlxuICogY2xhc3MgZm9yIEFTTi4xIERFUiBUZWxldGV4U3RyaW5nXG4gKiBAbmFtZSBLSlVSLmFzbjEuREVSVGVsZXRleFN0cmluZ1xuICogQGNsYXNzIGNsYXNzIGZvciBBU04uMSBERVIgVGVsZXRleFN0cmluZ1xuICogQHBhcmFtIHtBcnJheX0gcGFyYW1zIGFzc29jaWF0aXZlIGFycmF5IG9mIHBhcmFtZXRlcnMgKGV4LiB7J3N0cic6ICdhYWEnfSlcbiAqIEBleHRlbmRzIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZ1xuICogQGRlc2NyaXB0aW9uXG4gKiBAc2VlIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZyAtIHN1cGVyY2xhc3NcbiAqL1xuS0pVUi5hc24xLkRFUlRlbGV0ZXhTdHJpbmcgPSBmdW5jdGlvbihwYXJhbXMpIHtcbiAgICBLSlVSLmFzbjEuREVSVGVsZXRleFN0cmluZy5zdXBlcmNsYXNzLmNvbnN0cnVjdG9yLmNhbGwodGhpcywgcGFyYW1zKTtcbiAgICB0aGlzLmhUID0gXCIxNFwiO1xufTtcbkpTWC5leHRlbmQoS0pVUi5hc24xLkRFUlRlbGV0ZXhTdHJpbmcsIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZyk7XG5cbi8vICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXG4vKipcbiAqIGNsYXNzIGZvciBBU04uMSBERVIgSUE1U3RyaW5nXG4gKiBAbmFtZSBLSlVSLmFzbjEuREVSSUE1U3RyaW5nXG4gKiBAY2xhc3MgY2xhc3MgZm9yIEFTTi4xIERFUiBJQTVTdHJpbmdcbiAqIEBwYXJhbSB7QXJyYXl9IHBhcmFtcyBhc3NvY2lhdGl2ZSBhcnJheSBvZiBwYXJhbWV0ZXJzIChleC4geydzdHInOiAnYWFhJ30pXG4gKiBAZXh0ZW5kcyBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmdcbiAqIEBkZXNjcmlwdGlvblxuICogQHNlZSBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmcgLSBzdXBlcmNsYXNzXG4gKi9cbktKVVIuYXNuMS5ERVJJQTVTdHJpbmcgPSBmdW5jdGlvbihwYXJhbXMpIHtcbiAgICBLSlVSLmFzbjEuREVSSUE1U3RyaW5nLnN1cGVyY2xhc3MuY29uc3RydWN0b3IuY2FsbCh0aGlzLCBwYXJhbXMpO1xuICAgIHRoaXMuaFQgPSBcIjE2XCI7XG59O1xuSlNYLmV4dGVuZChLSlVSLmFzbjEuREVSSUE1U3RyaW5nLCBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmcpO1xuXG4vLyAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxuLyoqXG4gKiBjbGFzcyBmb3IgQVNOLjEgREVSIFVUQ1RpbWVcbiAqIEBuYW1lIEtKVVIuYXNuMS5ERVJVVENUaW1lXG4gKiBAY2xhc3MgY2xhc3MgZm9yIEFTTi4xIERFUiBVVENUaW1lXG4gKiBAcGFyYW0ge0FycmF5fSBwYXJhbXMgYXNzb2NpYXRpdmUgYXJyYXkgb2YgcGFyYW1ldGVycyAoZXguIHsnc3RyJzogJzEzMDQzMDIzNTk1OVonfSlcbiAqIEBleHRlbmRzIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFRpbWVcbiAqIEBkZXNjcmlwdGlvblxuICogPGJyLz5cbiAqIEFzIGZvciBhcmd1bWVudCAncGFyYW1zJyBmb3IgY29uc3RydWN0b3IsIHlvdSBjYW4gc3BlY2lmeSBvbmUgb2ZcbiAqIGZvbGxvd2luZyBwcm9wZXJ0aWVzOlxuICogPHVsPlxuICogPGxpPnN0ciAtIHNwZWNpZnkgaW5pdGlhbCBBU04uMSB2YWx1ZShWKSBieSBhIHN0cmluZyAoZXguJzEzMDQzMDIzNTk1OVonKTwvbGk+XG4gKiA8bGk+aGV4IC0gc3BlY2lmeSBpbml0aWFsIEFTTi4xIHZhbHVlKFYpIGJ5IGEgaGV4YWRlY2ltYWwgc3RyaW5nPC9saT5cbiAqIDxsaT5kYXRlIC0gc3BlY2lmeSBEYXRlIG9iamVjdC48L2xpPlxuICogPC91bD5cbiAqIE5PVEU6ICdwYXJhbXMnIGNhbiBiZSBvbWl0dGVkLlxuICogPGg0PkVYQU1QTEVTPC9oND5cbiAqIEBleGFtcGxlXG4gKiB2YXIgZDEgPSBuZXcgS0pVUi5hc24xLkRFUlVUQ1RpbWUoKTtcbiAqIGQxLnNldFN0cmluZygnMTMwNDMwMTI1OTU5WicpO1xuICpcbiAqIHZhciBkMiA9IG5ldyBLSlVSLmFzbjEuREVSVVRDVGltZSh7J3N0cic6ICcxMzA0MzAxMjU5NTlaJ30pO1xuICpcbiAqIHZhciBkMyA9IG5ldyBLSlVSLmFzbjEuREVSVVRDVGltZSh7J2RhdGUnOiBuZXcgRGF0ZShEYXRlLlVUQygyMDE1LCAwLCAzMSwgMCwgMCwgMCwgMCkpfSk7XG4gKi9cbktKVVIuYXNuMS5ERVJVVENUaW1lID0gZnVuY3Rpb24ocGFyYW1zKSB7XG4gICAgS0pVUi5hc24xLkRFUlVUQ1RpbWUuc3VwZXJjbGFzcy5jb25zdHJ1Y3Rvci5jYWxsKHRoaXMsIHBhcmFtcyk7XG4gICAgdGhpcy5oVCA9IFwiMTdcIjtcblxuICAgIC8qKlxuICAgICAqIHNldCB2YWx1ZSBieSBhIERhdGUgb2JqZWN0XG4gICAgICogQG5hbWUgc2V0QnlEYXRlXG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5ERVJVVENUaW1lXG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHBhcmFtIHtEYXRlfSBkYXRlT2JqZWN0IERhdGUgb2JqZWN0IHRvIHNldCBBU04uMSB2YWx1ZShWKVxuICAgICAqL1xuICAgIHRoaXMuc2V0QnlEYXRlID0gZnVuY3Rpb24oZGF0ZU9iamVjdCkge1xuXHR0aGlzLmhUTFYgPSBudWxsO1xuXHR0aGlzLmlzTW9kaWZpZWQgPSB0cnVlO1xuXHR0aGlzLmRhdGUgPSBkYXRlT2JqZWN0O1xuXHR0aGlzLnMgPSB0aGlzLmZvcm1hdERhdGUodGhpcy5kYXRlLCAndXRjJyk7XG5cdHRoaXMuaFYgPSBzdG9oZXgodGhpcy5zKTtcbiAgICB9O1xuXG4gICAgaWYgKHR5cGVvZiBwYXJhbXMgIT0gXCJ1bmRlZmluZWRcIikge1xuXHRpZiAodHlwZW9mIHBhcmFtc1snc3RyJ10gIT0gXCJ1bmRlZmluZWRcIikge1xuXHQgICAgdGhpcy5zZXRTdHJpbmcocGFyYW1zWydzdHInXSk7XG5cdH0gZWxzZSBpZiAodHlwZW9mIHBhcmFtc1snaGV4J10gIT0gXCJ1bmRlZmluZWRcIikge1xuXHQgICAgdGhpcy5zZXRTdHJpbmdIZXgocGFyYW1zWydoZXgnXSk7XG5cdH0gZWxzZSBpZiAodHlwZW9mIHBhcmFtc1snZGF0ZSddICE9IFwidW5kZWZpbmVkXCIpIHtcblx0ICAgIHRoaXMuc2V0QnlEYXRlKHBhcmFtc1snZGF0ZSddKTtcblx0fVxuICAgIH1cbn07XG5KU1guZXh0ZW5kKEtKVVIuYXNuMS5ERVJVVENUaW1lLCBLSlVSLmFzbjEuREVSQWJzdHJhY3RUaW1lKTtcblxuLy8gKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcbi8qKlxuICogY2xhc3MgZm9yIEFTTi4xIERFUiBHZW5lcmFsaXplZFRpbWVcbiAqIEBuYW1lIEtKVVIuYXNuMS5ERVJHZW5lcmFsaXplZFRpbWVcbiAqIEBjbGFzcyBjbGFzcyBmb3IgQVNOLjEgREVSIEdlbmVyYWxpemVkVGltZVxuICogQHBhcmFtIHtBcnJheX0gcGFyYW1zIGFzc29jaWF0aXZlIGFycmF5IG9mIHBhcmFtZXRlcnMgKGV4LiB7J3N0cic6ICcyMDEzMDQzMDIzNTk1OVonfSlcbiAqIEBleHRlbmRzIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFRpbWVcbiAqIEBkZXNjcmlwdGlvblxuICogPGJyLz5cbiAqIEFzIGZvciBhcmd1bWVudCAncGFyYW1zJyBmb3IgY29uc3RydWN0b3IsIHlvdSBjYW4gc3BlY2lmeSBvbmUgb2ZcbiAqIGZvbGxvd2luZyBwcm9wZXJ0aWVzOlxuICogPHVsPlxuICogPGxpPnN0ciAtIHNwZWNpZnkgaW5pdGlhbCBBU04uMSB2YWx1ZShWKSBieSBhIHN0cmluZyAoZXguJzIwMTMwNDMwMjM1OTU5WicpPC9saT5cbiAqIDxsaT5oZXggLSBzcGVjaWZ5IGluaXRpYWwgQVNOLjEgdmFsdWUoVikgYnkgYSBoZXhhZGVjaW1hbCBzdHJpbmc8L2xpPlxuICogPGxpPmRhdGUgLSBzcGVjaWZ5IERhdGUgb2JqZWN0LjwvbGk+XG4gKiA8L3VsPlxuICogTk9URTogJ3BhcmFtcycgY2FuIGJlIG9taXR0ZWQuXG4gKi9cbktKVVIuYXNuMS5ERVJHZW5lcmFsaXplZFRpbWUgPSBmdW5jdGlvbihwYXJhbXMpIHtcbiAgICBLSlVSLmFzbjEuREVSR2VuZXJhbGl6ZWRUaW1lLnN1cGVyY2xhc3MuY29uc3RydWN0b3IuY2FsbCh0aGlzLCBwYXJhbXMpO1xuICAgIHRoaXMuaFQgPSBcIjE4XCI7XG5cbiAgICAvKipcbiAgICAgKiBzZXQgdmFsdWUgYnkgYSBEYXRlIG9iamVjdFxuICAgICAqIEBuYW1lIHNldEJ5RGF0ZVxuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuREVSR2VuZXJhbGl6ZWRUaW1lXG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHBhcmFtIHtEYXRlfSBkYXRlT2JqZWN0IERhdGUgb2JqZWN0IHRvIHNldCBBU04uMSB2YWx1ZShWKVxuICAgICAqIEBleGFtcGxlXG4gICAgICogV2hlbiB5b3Ugc3BlY2lmeSBVVEMgdGltZSwgdXNlICdEYXRlLlVUQycgbWV0aG9kIGxpa2UgdGhpczo8YnIvPlxuICAgICAqIHZhciBvID0gbmV3IERFUlVUQ1RpbWUoKTtcbiAgICAgKiB2YXIgZGF0ZSA9IG5ldyBEYXRlKERhdGUuVVRDKDIwMTUsIDAsIDMxLCAyMywgNTksIDU5LCAwKSk7ICMyMDE1SkFOMzEgMjM6NTk6NTlcbiAgICAgKiBvLnNldEJ5RGF0ZShkYXRlKTtcbiAgICAgKi9cbiAgICB0aGlzLnNldEJ5RGF0ZSA9IGZ1bmN0aW9uKGRhdGVPYmplY3QpIHtcblx0dGhpcy5oVExWID0gbnVsbDtcblx0dGhpcy5pc01vZGlmaWVkID0gdHJ1ZTtcblx0dGhpcy5kYXRlID0gZGF0ZU9iamVjdDtcblx0dGhpcy5zID0gdGhpcy5mb3JtYXREYXRlKHRoaXMuZGF0ZSwgJ2dlbicpO1xuXHR0aGlzLmhWID0gc3RvaGV4KHRoaXMucyk7XG4gICAgfTtcblxuICAgIGlmICh0eXBlb2YgcGFyYW1zICE9IFwidW5kZWZpbmVkXCIpIHtcblx0aWYgKHR5cGVvZiBwYXJhbXNbJ3N0ciddICE9IFwidW5kZWZpbmVkXCIpIHtcblx0ICAgIHRoaXMuc2V0U3RyaW5nKHBhcmFtc1snc3RyJ10pO1xuXHR9IGVsc2UgaWYgKHR5cGVvZiBwYXJhbXNbJ2hleCddICE9IFwidW5kZWZpbmVkXCIpIHtcblx0ICAgIHRoaXMuc2V0U3RyaW5nSGV4KHBhcmFtc1snaGV4J10pO1xuXHR9IGVsc2UgaWYgKHR5cGVvZiBwYXJhbXNbJ2RhdGUnXSAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdCAgICB0aGlzLnNldEJ5RGF0ZShwYXJhbXNbJ2RhdGUnXSk7XG5cdH1cbiAgICB9XG59O1xuSlNYLmV4dGVuZChLSlVSLmFzbjEuREVSR2VuZXJhbGl6ZWRUaW1lLCBLSlVSLmFzbjEuREVSQWJzdHJhY3RUaW1lKTtcblxuLy8gKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcbi8qKlxuICogY2xhc3MgZm9yIEFTTi4xIERFUiBTZXF1ZW5jZVxuICogQG5hbWUgS0pVUi5hc24xLkRFUlNlcXVlbmNlXG4gKiBAY2xhc3MgY2xhc3MgZm9yIEFTTi4xIERFUiBTZXF1ZW5jZVxuICogQGV4dGVuZHMgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RydWN0dXJlZFxuICogQGRlc2NyaXB0aW9uXG4gKiA8YnIvPlxuICogQXMgZm9yIGFyZ3VtZW50ICdwYXJhbXMnIGZvciBjb25zdHJ1Y3RvciwgeW91IGNhbiBzcGVjaWZ5IG9uZSBvZlxuICogZm9sbG93aW5nIHByb3BlcnRpZXM6XG4gKiA8dWw+XG4gKiA8bGk+YXJyYXkgLSBzcGVjaWZ5IGFycmF5IG9mIEFTTjFPYmplY3QgdG8gc2V0IGVsZW1lbnRzIG9mIGNvbnRlbnQ8L2xpPlxuICogPC91bD5cbiAqIE5PVEU6ICdwYXJhbXMnIGNhbiBiZSBvbWl0dGVkLlxuICovXG5LSlVSLmFzbjEuREVSU2VxdWVuY2UgPSBmdW5jdGlvbihwYXJhbXMpIHtcbiAgICBLSlVSLmFzbjEuREVSU2VxdWVuY2Uuc3VwZXJjbGFzcy5jb25zdHJ1Y3Rvci5jYWxsKHRoaXMsIHBhcmFtcyk7XG4gICAgdGhpcy5oVCA9IFwiMzBcIjtcbiAgICB0aGlzLmdldEZyZXNoVmFsdWVIZXggPSBmdW5jdGlvbigpIHtcblx0dmFyIGggPSAnJztcblx0Zm9yICh2YXIgaSA9IDA7IGkgPCB0aGlzLmFzbjFBcnJheS5sZW5ndGg7IGkrKykge1xuXHQgICAgdmFyIGFzbjFPYmogPSB0aGlzLmFzbjFBcnJheVtpXTtcblx0ICAgIGggKz0gYXNuMU9iai5nZXRFbmNvZGVkSGV4KCk7XG5cdH1cblx0dGhpcy5oViA9IGg7XG5cdHJldHVybiB0aGlzLmhWO1xuICAgIH07XG59O1xuSlNYLmV4dGVuZChLSlVSLmFzbjEuREVSU2VxdWVuY2UsIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cnVjdHVyZWQpO1xuXG4vLyAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxuLyoqXG4gKiBjbGFzcyBmb3IgQVNOLjEgREVSIFNldFxuICogQG5hbWUgS0pVUi5hc24xLkRFUlNldFxuICogQGNsYXNzIGNsYXNzIGZvciBBU04uMSBERVIgU2V0XG4gKiBAZXh0ZW5kcyBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJ1Y3R1cmVkXG4gKiBAZGVzY3JpcHRpb25cbiAqIDxici8+XG4gKiBBcyBmb3IgYXJndW1lbnQgJ3BhcmFtcycgZm9yIGNvbnN0cnVjdG9yLCB5b3UgY2FuIHNwZWNpZnkgb25lIG9mXG4gKiBmb2xsb3dpbmcgcHJvcGVydGllczpcbiAqIDx1bD5cbiAqIDxsaT5hcnJheSAtIHNwZWNpZnkgYXJyYXkgb2YgQVNOMU9iamVjdCB0byBzZXQgZWxlbWVudHMgb2YgY29udGVudDwvbGk+XG4gKiA8L3VsPlxuICogTk9URTogJ3BhcmFtcycgY2FuIGJlIG9taXR0ZWQuXG4gKi9cbktKVVIuYXNuMS5ERVJTZXQgPSBmdW5jdGlvbihwYXJhbXMpIHtcbiAgICBLSlVSLmFzbjEuREVSU2V0LnN1cGVyY2xhc3MuY29uc3RydWN0b3IuY2FsbCh0aGlzLCBwYXJhbXMpO1xuICAgIHRoaXMuaFQgPSBcIjMxXCI7XG4gICAgdGhpcy5nZXRGcmVzaFZhbHVlSGV4ID0gZnVuY3Rpb24oKSB7XG5cdHZhciBhID0gbmV3IEFycmF5KCk7XG5cdGZvciAodmFyIGkgPSAwOyBpIDwgdGhpcy5hc24xQXJyYXkubGVuZ3RoOyBpKyspIHtcblx0ICAgIHZhciBhc24xT2JqID0gdGhpcy5hc24xQXJyYXlbaV07XG5cdCAgICBhLnB1c2goYXNuMU9iai5nZXRFbmNvZGVkSGV4KCkpO1xuXHR9XG5cdGEuc29ydCgpO1xuXHR0aGlzLmhWID0gYS5qb2luKCcnKTtcblx0cmV0dXJuIHRoaXMuaFY7XG4gICAgfTtcbn07XG5KU1guZXh0ZW5kKEtKVVIuYXNuMS5ERVJTZXQsIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cnVjdHVyZWQpO1xuXG4vLyAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxuLyoqXG4gKiBjbGFzcyBmb3IgQVNOLjEgREVSIFRhZ2dlZE9iamVjdFxuICogQG5hbWUgS0pVUi5hc24xLkRFUlRhZ2dlZE9iamVjdFxuICogQGNsYXNzIGNsYXNzIGZvciBBU04uMSBERVIgVGFnZ2VkT2JqZWN0XG4gKiBAZXh0ZW5kcyBLSlVSLmFzbjEuQVNOMU9iamVjdFxuICogQGRlc2NyaXB0aW9uXG4gKiA8YnIvPlxuICogUGFyYW1ldGVyICd0YWdOb05leCcgaXMgQVNOLjEgdGFnKFQpIHZhbHVlIGZvciB0aGlzIG9iamVjdC5cbiAqIEZvciBleGFtcGxlLCBpZiB5b3UgZmluZCAnWzFdJyB0YWcgaW4gYSBBU04uMSBkdW1wLCBcbiAqICd0YWdOb0hleCcgd2lsbCBiZSAnYTEnLlxuICogPGJyLz5cbiAqIEFzIGZvciBvcHRpb25hbCBhcmd1bWVudCAncGFyYW1zJyBmb3IgY29uc3RydWN0b3IsIHlvdSBjYW4gc3BlY2lmeSAqQU5ZKiBvZlxuICogZm9sbG93aW5nIHByb3BlcnRpZXM6XG4gKiA8dWw+XG4gKiA8bGk+ZXhwbGljaXQgLSBzcGVjaWZ5IHRydWUgaWYgdGhpcyBpcyBleHBsaWNpdCB0YWcgb3RoZXJ3aXNlIGZhbHNlIFxuICogICAgIChkZWZhdWx0IGlzICd0cnVlJykuPC9saT5cbiAqIDxsaT50YWcgLSBzcGVjaWZ5IHRhZyAoZGVmYXVsdCBpcyAnYTAnIHdoaWNoIG1lYW5zIFswXSk8L2xpPlxuICogPGxpPm9iaiAtIHNwZWNpZnkgQVNOMU9iamVjdCB3aGljaCBpcyB0YWdnZWQ8L2xpPlxuICogPC91bD5cbiAqIEBleGFtcGxlXG4gKiBkMSA9IG5ldyBLSlVSLmFzbjEuREVSVVRGOFN0cmluZyh7J3N0cic6J2EnfSk7XG4gKiBkMiA9IG5ldyBLSlVSLmFzbjEuREVSVGFnZ2VkT2JqZWN0KHsnb2JqJzogZDF9KTtcbiAqIGhleCA9IGQyLmdldEVuY29kZWRIZXgoKTtcbiAqL1xuS0pVUi5hc24xLkRFUlRhZ2dlZE9iamVjdCA9IGZ1bmN0aW9uKHBhcmFtcykge1xuICAgIEtKVVIuYXNuMS5ERVJUYWdnZWRPYmplY3Quc3VwZXJjbGFzcy5jb25zdHJ1Y3Rvci5jYWxsKHRoaXMpO1xuICAgIHRoaXMuaFQgPSBcImEwXCI7XG4gICAgdGhpcy5oViA9ICcnO1xuICAgIHRoaXMuaXNFeHBsaWNpdCA9IHRydWU7XG4gICAgdGhpcy5hc24xT2JqZWN0ID0gbnVsbDtcblxuICAgIC8qKlxuICAgICAqIHNldCB2YWx1ZSBieSBhbiBBU04xT2JqZWN0XG4gICAgICogQG5hbWUgc2V0U3RyaW5nXG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5ERVJUYWdnZWRPYmplY3RcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcGFyYW0ge0Jvb2xlYW59IGlzRXhwbGljaXRGbGFnIGZsYWcgZm9yIGV4cGxpY2l0L2ltcGxpY2l0IHRhZ1xuICAgICAqIEBwYXJhbSB7SW50ZWdlcn0gdGFnTm9IZXggaGV4YWRlY2ltYWwgc3RyaW5nIG9mIEFTTi4xIHRhZ1xuICAgICAqIEBwYXJhbSB7QVNOMU9iamVjdH0gYXNuMU9iamVjdCBBU04uMSB0byBlbmNhcHN1bGF0ZVxuICAgICAqL1xuICAgIHRoaXMuc2V0QVNOMU9iamVjdCA9IGZ1bmN0aW9uKGlzRXhwbGljaXRGbGFnLCB0YWdOb0hleCwgYXNuMU9iamVjdCkge1xuXHR0aGlzLmhUID0gdGFnTm9IZXg7XG5cdHRoaXMuaXNFeHBsaWNpdCA9IGlzRXhwbGljaXRGbGFnO1xuXHR0aGlzLmFzbjFPYmplY3QgPSBhc24xT2JqZWN0O1xuXHRpZiAodGhpcy5pc0V4cGxpY2l0KSB7XG5cdCAgICB0aGlzLmhWID0gdGhpcy5hc24xT2JqZWN0LmdldEVuY29kZWRIZXgoKTtcblx0ICAgIHRoaXMuaFRMViA9IG51bGw7XG5cdCAgICB0aGlzLmlzTW9kaWZpZWQgPSB0cnVlO1xuXHR9IGVsc2Uge1xuXHQgICAgdGhpcy5oViA9IG51bGw7XG5cdCAgICB0aGlzLmhUTFYgPSBhc24xT2JqZWN0LmdldEVuY29kZWRIZXgoKTtcblx0ICAgIHRoaXMuaFRMViA9IHRoaXMuaFRMVi5yZXBsYWNlKC9eLi4vLCB0YWdOb0hleCk7XG5cdCAgICB0aGlzLmlzTW9kaWZpZWQgPSBmYWxzZTtcblx0fVxuICAgIH07XG5cbiAgICB0aGlzLmdldEZyZXNoVmFsdWVIZXggPSBmdW5jdGlvbigpIHtcblx0cmV0dXJuIHRoaXMuaFY7XG4gICAgfTtcblxuICAgIGlmICh0eXBlb2YgcGFyYW1zICE9IFwidW5kZWZpbmVkXCIpIHtcblx0aWYgKHR5cGVvZiBwYXJhbXNbJ3RhZyddICE9IFwidW5kZWZpbmVkXCIpIHtcblx0ICAgIHRoaXMuaFQgPSBwYXJhbXNbJ3RhZyddO1xuXHR9XG5cdGlmICh0eXBlb2YgcGFyYW1zWydleHBsaWNpdCddICE9IFwidW5kZWZpbmVkXCIpIHtcblx0ICAgIHRoaXMuaXNFeHBsaWNpdCA9IHBhcmFtc1snZXhwbGljaXQnXTtcblx0fVxuXHRpZiAodHlwZW9mIHBhcmFtc1snb2JqJ10gIT0gXCJ1bmRlZmluZWRcIikge1xuXHQgICAgdGhpcy5hc24xT2JqZWN0ID0gcGFyYW1zWydvYmonXTtcblx0ICAgIHRoaXMuc2V0QVNOMU9iamVjdCh0aGlzLmlzRXhwbGljaXQsIHRoaXMuaFQsIHRoaXMuYXNuMU9iamVjdCk7XG5cdH1cbiAgICB9XG59O1xuSlNYLmV4dGVuZChLSlVSLmFzbjEuREVSVGFnZ2VkT2JqZWN0LCBLSlVSLmFzbjEuQVNOMU9iamVjdCk7XG4vLyBIZXggSmF2YVNjcmlwdCBkZWNvZGVyXG4vLyBDb3B5cmlnaHQgKGMpIDIwMDgtMjAxMyBMYXBvIEx1Y2hpbmkgPGxhcG9AbGFwby5pdD5cblxuLy8gUGVybWlzc2lvbiB0byB1c2UsIGNvcHksIG1vZGlmeSwgYW5kL29yIGRpc3RyaWJ1dGUgdGhpcyBzb2Z0d2FyZSBmb3IgYW55XG4vLyBwdXJwb3NlIHdpdGggb3Igd2l0aG91dCBmZWUgaXMgaGVyZWJ5IGdyYW50ZWQsIHByb3ZpZGVkIHRoYXQgdGhlIGFib3ZlXG4vLyBjb3B5cmlnaHQgbm90aWNlIGFuZCB0aGlzIHBlcm1pc3Npb24gbm90aWNlIGFwcGVhciBpbiBhbGwgY29waWVzLlxuLy8gXG4vLyBUSEUgU09GVFdBUkUgSVMgUFJPVklERUQgXCJBUyBJU1wiIEFORCBUSEUgQVVUSE9SIERJU0NMQUlNUyBBTEwgV0FSUkFOVElFU1xuLy8gV0lUSCBSRUdBUkQgVE8gVEhJUyBTT0ZUV0FSRSBJTkNMVURJTkcgQUxMIElNUExJRUQgV0FSUkFOVElFUyBPRlxuLy8gTUVSQ0hBTlRBQklMSVRZIEFORCBGSVRORVNTLiBJTiBOTyBFVkVOVCBTSEFMTCBUSEUgQVVUSE9SIEJFIExJQUJMRSBGT1Jcbi8vIEFOWSBTUEVDSUFMLCBESVJFQ1QsIElORElSRUNULCBPUiBDT05TRVFVRU5USUFMIERBTUFHRVMgT1IgQU5ZIERBTUFHRVNcbi8vIFdIQVRTT0VWRVIgUkVTVUxUSU5HIEZST00gTE9TUyBPRiBVU0UsIERBVEEgT1IgUFJPRklUUywgV0hFVEhFUiBJTiBBTlxuLy8gQUNUSU9OIE9GIENPTlRSQUNULCBORUdMSUdFTkNFIE9SIE9USEVSIFRPUlRJT1VTIEFDVElPTiwgQVJJU0lORyBPVVQgT0Zcbi8vIE9SIElOIENPTk5FQ1RJT04gV0lUSCBUSEUgVVNFIE9SIFBFUkZPUk1BTkNFIE9GIFRISVMgU09GVFdBUkUuXG5cbi8qanNoaW50IGJyb3dzZXI6IHRydWUsIHN0cmljdDogdHJ1ZSwgaW1tZWQ6IHRydWUsIGxhdGVkZWY6IHRydWUsIHVuZGVmOiB0cnVlLCByZWdleGRhc2g6IGZhbHNlICovXG4oZnVuY3Rpb24gKHVuZGVmaW5lZCkge1xuXCJ1c2Ugc3RyaWN0XCI7XG5cbnZhciBIZXggPSB7fSxcbiAgICBkZWNvZGVyO1xuXG5IZXguZGVjb2RlID0gZnVuY3Rpb24oYSkge1xuICAgIHZhciBpO1xuICAgIGlmIChkZWNvZGVyID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgdmFyIGhleCA9IFwiMDEyMzQ1Njc4OUFCQ0RFRlwiLFxuICAgICAgICAgICAgaWdub3JlID0gXCIgXFxmXFxuXFxyXFx0XFx1MDBBMFxcdTIwMjhcXHUyMDI5XCI7XG4gICAgICAgIGRlY29kZXIgPSBbXTtcbiAgICAgICAgZm9yIChpID0gMDsgaSA8IDE2OyArK2kpXG4gICAgICAgICAgICBkZWNvZGVyW2hleC5jaGFyQXQoaSldID0gaTtcbiAgICAgICAgaGV4ID0gaGV4LnRvTG93ZXJDYXNlKCk7XG4gICAgICAgIGZvciAoaSA9IDEwOyBpIDwgMTY7ICsraSlcbiAgICAgICAgICAgIGRlY29kZXJbaGV4LmNoYXJBdChpKV0gPSBpO1xuICAgICAgICBmb3IgKGkgPSAwOyBpIDwgaWdub3JlLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgZGVjb2RlcltpZ25vcmUuY2hhckF0KGkpXSA9IC0xO1xuICAgIH1cbiAgICB2YXIgb3V0ID0gW10sXG4gICAgICAgIGJpdHMgPSAwLFxuICAgICAgICBjaGFyX2NvdW50ID0gMDtcbiAgICBmb3IgKGkgPSAwOyBpIDwgYS5sZW5ndGg7ICsraSkge1xuICAgICAgICB2YXIgYyA9IGEuY2hhckF0KGkpO1xuICAgICAgICBpZiAoYyA9PSAnPScpXG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgYyA9IGRlY29kZXJbY107XG4gICAgICAgIGlmIChjID09IC0xKVxuICAgICAgICAgICAgY29udGludWU7XG4gICAgICAgIGlmIChjID09PSB1bmRlZmluZWQpXG4gICAgICAgICAgICB0aHJvdyAnSWxsZWdhbCBjaGFyYWN0ZXIgYXQgb2Zmc2V0ICcgKyBpO1xuICAgICAgICBiaXRzIHw9IGM7XG4gICAgICAgIGlmICgrK2NoYXJfY291bnQgPj0gMikge1xuICAgICAgICAgICAgb3V0W291dC5sZW5ndGhdID0gYml0cztcbiAgICAgICAgICAgIGJpdHMgPSAwO1xuICAgICAgICAgICAgY2hhcl9jb3VudCA9IDA7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBiaXRzIDw8PSA0O1xuICAgICAgICB9XG4gICAgfVxuICAgIGlmIChjaGFyX2NvdW50KVxuICAgICAgICB0aHJvdyBcIkhleCBlbmNvZGluZyBpbmNvbXBsZXRlOiA0IGJpdHMgbWlzc2luZ1wiO1xuICAgIHJldHVybiBvdXQ7XG59O1xuXG4vLyBleHBvcnQgZ2xvYmFsc1xud2luZG93LkhleCA9IEhleDtcbn0pKCk7XG4vLyBCYXNlNjQgSmF2YVNjcmlwdCBkZWNvZGVyXG4vLyBDb3B5cmlnaHQgKGMpIDIwMDgtMjAxMyBMYXBvIEx1Y2hpbmkgPGxhcG9AbGFwby5pdD5cblxuLy8gUGVybWlzc2lvbiB0byB1c2UsIGNvcHksIG1vZGlmeSwgYW5kL29yIGRpc3RyaWJ1dGUgdGhpcyBzb2Z0d2FyZSBmb3IgYW55XG4vLyBwdXJwb3NlIHdpdGggb3Igd2l0aG91dCBmZWUgaXMgaGVyZWJ5IGdyYW50ZWQsIHByb3ZpZGVkIHRoYXQgdGhlIGFib3ZlXG4vLyBjb3B5cmlnaHQgbm90aWNlIGFuZCB0aGlzIHBlcm1pc3Npb24gbm90aWNlIGFwcGVhciBpbiBhbGwgY29waWVzLlxuLy8gXG4vLyBUSEUgU09GVFdBUkUgSVMgUFJPVklERUQgXCJBUyBJU1wiIEFORCBUSEUgQVVUSE9SIERJU0NMQUlNUyBBTEwgV0FSUkFOVElFU1xuLy8gV0lUSCBSRUdBUkQgVE8gVEhJUyBTT0ZUV0FSRSBJTkNMVURJTkcgQUxMIElNUExJRUQgV0FSUkFOVElFUyBPRlxuLy8gTUVSQ0hBTlRBQklMSVRZIEFORCBGSVRORVNTLiBJTiBOTyBFVkVOVCBTSEFMTCBUSEUgQVVUSE9SIEJFIExJQUJMRSBGT1Jcbi8vIEFOWSBTUEVDSUFMLCBESVJFQ1QsIElORElSRUNULCBPUiBDT05TRVFVRU5USUFMIERBTUFHRVMgT1IgQU5ZIERBTUFHRVNcbi8vIFdIQVRTT0VWRVIgUkVTVUxUSU5HIEZST00gTE9TUyBPRiBVU0UsIERBVEEgT1IgUFJPRklUUywgV0hFVEhFUiBJTiBBTlxuLy8gQUNUSU9OIE9GIENPTlRSQUNULCBORUdMSUdFTkNFIE9SIE9USEVSIFRPUlRJT1VTIEFDVElPTiwgQVJJU0lORyBPVVQgT0Zcbi8vIE9SIElOIENPTk5FQ1RJT04gV0lUSCBUSEUgVVNFIE9SIFBFUkZPUk1BTkNFIE9GIFRISVMgU09GVFdBUkUuXG5cbi8qanNoaW50IGJyb3dzZXI6IHRydWUsIHN0cmljdDogdHJ1ZSwgaW1tZWQ6IHRydWUsIGxhdGVkZWY6IHRydWUsIHVuZGVmOiB0cnVlLCByZWdleGRhc2g6IGZhbHNlICovXG4oZnVuY3Rpb24gKHVuZGVmaW5lZCkge1xuXCJ1c2Ugc3RyaWN0XCI7XG5cbnZhciBCYXNlNjQgPSB7fSxcbiAgICBkZWNvZGVyO1xuXG5CYXNlNjQuZGVjb2RlID0gZnVuY3Rpb24gKGEpIHtcbiAgICB2YXIgaTtcbiAgICBpZiAoZGVjb2RlciA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHZhciBiNjQgPSBcIkFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5Ky9cIixcbiAgICAgICAgICAgIGlnbm9yZSA9IFwiPSBcXGZcXG5cXHJcXHRcXHUwMEEwXFx1MjAyOFxcdTIwMjlcIjtcbiAgICAgICAgZGVjb2RlciA9IFtdO1xuICAgICAgICBmb3IgKGkgPSAwOyBpIDwgNjQ7ICsraSlcbiAgICAgICAgICAgIGRlY29kZXJbYjY0LmNoYXJBdChpKV0gPSBpO1xuICAgICAgICBmb3IgKGkgPSAwOyBpIDwgaWdub3JlLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgZGVjb2RlcltpZ25vcmUuY2hhckF0KGkpXSA9IC0xO1xuICAgIH1cbiAgICB2YXIgb3V0ID0gW107XG4gICAgdmFyIGJpdHMgPSAwLCBjaGFyX2NvdW50ID0gMDtcbiAgICBmb3IgKGkgPSAwOyBpIDwgYS5sZW5ndGg7ICsraSkge1xuICAgICAgICB2YXIgYyA9IGEuY2hhckF0KGkpO1xuICAgICAgICBpZiAoYyA9PSAnPScpXG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgYyA9IGRlY29kZXJbY107XG4gICAgICAgIGlmIChjID09IC0xKVxuICAgICAgICAgICAgY29udGludWU7XG4gICAgICAgIGlmIChjID09PSB1bmRlZmluZWQpXG4gICAgICAgICAgICB0aHJvdyAnSWxsZWdhbCBjaGFyYWN0ZXIgYXQgb2Zmc2V0ICcgKyBpO1xuICAgICAgICBiaXRzIHw9IGM7XG4gICAgICAgIGlmICgrK2NoYXJfY291bnQgPj0gNCkge1xuICAgICAgICAgICAgb3V0W291dC5sZW5ndGhdID0gKGJpdHMgPj4gMTYpO1xuICAgICAgICAgICAgb3V0W291dC5sZW5ndGhdID0gKGJpdHMgPj4gOCkgJiAweEZGO1xuICAgICAgICAgICAgb3V0W291dC5sZW5ndGhdID0gYml0cyAmIDB4RkY7XG4gICAgICAgICAgICBiaXRzID0gMDtcbiAgICAgICAgICAgIGNoYXJfY291bnQgPSAwO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgYml0cyA8PD0gNjtcbiAgICAgICAgfVxuICAgIH1cbiAgICBzd2l0Y2ggKGNoYXJfY291bnQpIHtcbiAgICAgIGNhc2UgMTpcbiAgICAgICAgdGhyb3cgXCJCYXNlNjQgZW5jb2RpbmcgaW5jb21wbGV0ZTogYXQgbGVhc3QgMiBiaXRzIG1pc3NpbmdcIjtcbiAgICAgIGNhc2UgMjpcbiAgICAgICAgb3V0W291dC5sZW5ndGhdID0gKGJpdHMgPj4gMTApO1xuICAgICAgICBicmVhaztcbiAgICAgIGNhc2UgMzpcbiAgICAgICAgb3V0W291dC5sZW5ndGhdID0gKGJpdHMgPj4gMTYpO1xuICAgICAgICBvdXRbb3V0Lmxlbmd0aF0gPSAoYml0cyA+PiA4KSAmIDB4RkY7XG4gICAgICAgIGJyZWFrO1xuICAgIH1cbiAgICByZXR1cm4gb3V0O1xufTtcblxuQmFzZTY0LnJlID0gLy0tLS0tQkVHSU4gW14tXSstLS0tLShbQS1aYS16MC05K1xcLz1cXHNdKyktLS0tLUVORCBbXi1dKy0tLS0tfGJlZ2luLWJhc2U2NFteXFxuXStcXG4oW0EtWmEtejAtOStcXC89XFxzXSspPT09PS87XG5CYXNlNjQudW5hcm1vciA9IGZ1bmN0aW9uIChhKSB7XG4gICAgdmFyIG0gPSBCYXNlNjQucmUuZXhlYyhhKTtcbiAgICBpZiAobSkge1xuICAgICAgICBpZiAobVsxXSlcbiAgICAgICAgICAgIGEgPSBtWzFdO1xuICAgICAgICBlbHNlIGlmIChtWzJdKVxuICAgICAgICAgICAgYSA9IG1bMl07XG4gICAgICAgIGVsc2VcbiAgICAgICAgICAgIHRocm93IFwiUmVnRXhwIG91dCBvZiBzeW5jXCI7XG4gICAgfVxuICAgIHJldHVybiBCYXNlNjQuZGVjb2RlKGEpO1xufTtcblxuLy8gZXhwb3J0IGdsb2JhbHNcbndpbmRvdy5CYXNlNjQgPSBCYXNlNjQ7XG59KSgpO1xuLy8gQVNOLjEgSmF2YVNjcmlwdCBkZWNvZGVyXG4vLyBDb3B5cmlnaHQgKGMpIDIwMDgtMjAxMyBMYXBvIEx1Y2hpbmkgPGxhcG9AbGFwby5pdD5cblxuLy8gUGVybWlzc2lvbiB0byB1c2UsIGNvcHksIG1vZGlmeSwgYW5kL29yIGRpc3RyaWJ1dGUgdGhpcyBzb2Z0d2FyZSBmb3IgYW55XG4vLyBwdXJwb3NlIHdpdGggb3Igd2l0aG91dCBmZWUgaXMgaGVyZWJ5IGdyYW50ZWQsIHByb3ZpZGVkIHRoYXQgdGhlIGFib3ZlXG4vLyBjb3B5cmlnaHQgbm90aWNlIGFuZCB0aGlzIHBlcm1pc3Npb24gbm90aWNlIGFwcGVhciBpbiBhbGwgY29waWVzLlxuLy8gXG4vLyBUSEUgU09GVFdBUkUgSVMgUFJPVklERUQgXCJBUyBJU1wiIEFORCBUSEUgQVVUSE9SIERJU0NMQUlNUyBBTEwgV0FSUkFOVElFU1xuLy8gV0lUSCBSRUdBUkQgVE8gVEhJUyBTT0ZUV0FSRSBJTkNMVURJTkcgQUxMIElNUExJRUQgV0FSUkFOVElFUyBPRlxuLy8gTUVSQ0hBTlRBQklMSVRZIEFORCBGSVRORVNTLiBJTiBOTyBFVkVOVCBTSEFMTCBUSEUgQVVUSE9SIEJFIExJQUJMRSBGT1Jcbi8vIEFOWSBTUEVDSUFMLCBESVJFQ1QsIElORElSRUNULCBPUiBDT05TRVFVRU5USUFMIERBTUFHRVMgT1IgQU5ZIERBTUFHRVNcbi8vIFdIQVRTT0VWRVIgUkVTVUxUSU5HIEZST00gTE9TUyBPRiBVU0UsIERBVEEgT1IgUFJPRklUUywgV0hFVEhFUiBJTiBBTlxuLy8gQUNUSU9OIE9GIENPTlRSQUNULCBORUdMSUdFTkNFIE9SIE9USEVSIFRPUlRJT1VTIEFDVElPTiwgQVJJU0lORyBPVVQgT0Zcbi8vIE9SIElOIENPTk5FQ1RJT04gV0lUSCBUSEUgVVNFIE9SIFBFUkZPUk1BTkNFIE9GIFRISVMgU09GVFdBUkUuXG5cbi8qanNoaW50IGJyb3dzZXI6IHRydWUsIHN0cmljdDogdHJ1ZSwgaW1tZWQ6IHRydWUsIGxhdGVkZWY6IHRydWUsIHVuZGVmOiB0cnVlLCByZWdleGRhc2g6IGZhbHNlICovXG4vKmdsb2JhbCBvaWRzICovXG4oZnVuY3Rpb24gKHVuZGVmaW5lZCkge1xuXCJ1c2Ugc3RyaWN0XCI7XG5cbnZhciBoYXJkTGltaXQgPSAxMDAsXG4gICAgZWxsaXBzaXMgPSBcIlxcdTIwMjZcIixcbiAgICBET00gPSB7XG4gICAgICAgIHRhZzogZnVuY3Rpb24gKHRhZ05hbWUsIGNsYXNzTmFtZSkge1xuICAgICAgICAgICAgdmFyIHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KHRhZ05hbWUpO1xuICAgICAgICAgICAgdC5jbGFzc05hbWUgPSBjbGFzc05hbWU7XG4gICAgICAgICAgICByZXR1cm4gdDtcbiAgICAgICAgfSxcbiAgICAgICAgdGV4dDogZnVuY3Rpb24gKHN0cikge1xuICAgICAgICAgICAgcmV0dXJuIGRvY3VtZW50LmNyZWF0ZVRleHROb2RlKHN0cik7XG4gICAgICAgIH1cbiAgICB9O1xuXG5mdW5jdGlvbiBTdHJlYW0oZW5jLCBwb3MpIHtcbiAgICBpZiAoZW5jIGluc3RhbmNlb2YgU3RyZWFtKSB7XG4gICAgICAgIHRoaXMuZW5jID0gZW5jLmVuYztcbiAgICAgICAgdGhpcy5wb3MgPSBlbmMucG9zO1xuICAgIH0gZWxzZSB7XG4gICAgICAgIHRoaXMuZW5jID0gZW5jO1xuICAgICAgICB0aGlzLnBvcyA9IHBvcztcbiAgICB9XG59XG5TdHJlYW0ucHJvdG90eXBlLmdldCA9IGZ1bmN0aW9uIChwb3MpIHtcbiAgICBpZiAocG9zID09PSB1bmRlZmluZWQpXG4gICAgICAgIHBvcyA9IHRoaXMucG9zKys7XG4gICAgaWYgKHBvcyA+PSB0aGlzLmVuYy5sZW5ndGgpXG4gICAgICAgIHRocm93ICdSZXF1ZXN0aW5nIGJ5dGUgb2Zmc2V0ICcgKyBwb3MgKyAnIG9uIGEgc3RyZWFtIG9mIGxlbmd0aCAnICsgdGhpcy5lbmMubGVuZ3RoO1xuICAgIHJldHVybiB0aGlzLmVuY1twb3NdO1xufTtcblN0cmVhbS5wcm90b3R5cGUuaGV4RGlnaXRzID0gXCIwMTIzNDU2Nzg5QUJDREVGXCI7XG5TdHJlYW0ucHJvdG90eXBlLmhleEJ5dGUgPSBmdW5jdGlvbiAoYikge1xuICAgIHJldHVybiB0aGlzLmhleERpZ2l0cy5jaGFyQXQoKGIgPj4gNCkgJiAweEYpICsgdGhpcy5oZXhEaWdpdHMuY2hhckF0KGIgJiAweEYpO1xufTtcblN0cmVhbS5wcm90b3R5cGUuaGV4RHVtcCA9IGZ1bmN0aW9uIChzdGFydCwgZW5kLCByYXcpIHtcbiAgICB2YXIgcyA9IFwiXCI7XG4gICAgZm9yICh2YXIgaSA9IHN0YXJ0OyBpIDwgZW5kOyArK2kpIHtcbiAgICAgICAgcyArPSB0aGlzLmhleEJ5dGUodGhpcy5nZXQoaSkpO1xuICAgICAgICBpZiAocmF3ICE9PSB0cnVlKVxuICAgICAgICAgICAgc3dpdGNoIChpICYgMHhGKSB7XG4gICAgICAgICAgICBjYXNlIDB4NzogcyArPSBcIiAgXCI7IGJyZWFrO1xuICAgICAgICAgICAgY2FzZSAweEY6IHMgKz0gXCJcXG5cIjsgYnJlYWs7XG4gICAgICAgICAgICBkZWZhdWx0OiAgcyArPSBcIiBcIjtcbiAgICAgICAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIHM7XG59O1xuU3RyZWFtLnByb3RvdHlwZS5wYXJzZVN0cmluZ0lTTyA9IGZ1bmN0aW9uIChzdGFydCwgZW5kKSB7XG4gICAgdmFyIHMgPSBcIlwiO1xuICAgIGZvciAodmFyIGkgPSBzdGFydDsgaSA8IGVuZDsgKytpKVxuICAgICAgICBzICs9IFN0cmluZy5mcm9tQ2hhckNvZGUodGhpcy5nZXQoaSkpO1xuICAgIHJldHVybiBzO1xufTtcblN0cmVhbS5wcm90b3R5cGUucGFyc2VTdHJpbmdVVEYgPSBmdW5jdGlvbiAoc3RhcnQsIGVuZCkge1xuICAgIHZhciBzID0gXCJcIjtcbiAgICBmb3IgKHZhciBpID0gc3RhcnQ7IGkgPCBlbmQ7ICkge1xuICAgICAgICB2YXIgYyA9IHRoaXMuZ2V0KGkrKyk7XG4gICAgICAgIGlmIChjIDwgMTI4KVxuICAgICAgICAgICAgcyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKGMpO1xuICAgICAgICBlbHNlIGlmICgoYyA+IDE5MSkgJiYgKGMgPCAyMjQpKVxuICAgICAgICAgICAgcyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKCgoYyAmIDB4MUYpIDw8IDYpIHwgKHRoaXMuZ2V0KGkrKykgJiAweDNGKSk7XG4gICAgICAgIGVsc2VcbiAgICAgICAgICAgIHMgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSgoKGMgJiAweDBGKSA8PCAxMikgfCAoKHRoaXMuZ2V0KGkrKykgJiAweDNGKSA8PCA2KSB8ICh0aGlzLmdldChpKyspICYgMHgzRikpO1xuICAgIH1cbiAgICByZXR1cm4gcztcbn07XG5TdHJlYW0ucHJvdG90eXBlLnBhcnNlU3RyaW5nQk1QID0gZnVuY3Rpb24gKHN0YXJ0LCBlbmQpIHtcbiAgICB2YXIgc3RyID0gXCJcIlxuICAgIGZvciAodmFyIGkgPSBzdGFydDsgaSA8IGVuZDsgaSArPSAyKSB7XG4gICAgICAgIHZhciBoaWdoX2J5dGUgPSB0aGlzLmdldChpKTtcbiAgICAgICAgdmFyIGxvd19ieXRlID0gdGhpcy5nZXQoaSArIDEpO1xuICAgICAgICBzdHIgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSggKGhpZ2hfYnl0ZSA8PCA4KSArIGxvd19ieXRlICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHN0cjtcbn07XG5TdHJlYW0ucHJvdG90eXBlLnJlVGltZSA9IC9eKCg/OjFbODldfDJcXGQpP1xcZFxcZCkoMFsxLTldfDFbMC0yXSkoMFsxLTldfFsxMl1cXGR8M1swMV0pKFswMV1cXGR8MlswLTNdKSg/OihbMC01XVxcZCkoPzooWzAtNV1cXGQpKD86Wy4sXShcXGR7MSwzfSkpPyk/KT8oWnxbLStdKD86WzBdXFxkfDFbMC0yXSkoWzAtNV1cXGQpPyk/JC87XG5TdHJlYW0ucHJvdG90eXBlLnBhcnNlVGltZSA9IGZ1bmN0aW9uIChzdGFydCwgZW5kKSB7XG4gICAgdmFyIHMgPSB0aGlzLnBhcnNlU3RyaW5nSVNPKHN0YXJ0LCBlbmQpLFxuICAgICAgICBtID0gdGhpcy5yZVRpbWUuZXhlYyhzKTtcbiAgICBpZiAoIW0pXG4gICAgICAgIHJldHVybiBcIlVucmVjb2duaXplZCB0aW1lOiBcIiArIHM7XG4gICAgcyA9IG1bMV0gKyBcIi1cIiArIG1bMl0gKyBcIi1cIiArIG1bM10gKyBcIiBcIiArIG1bNF07XG4gICAgaWYgKG1bNV0pIHtcbiAgICAgICAgcyArPSBcIjpcIiArIG1bNV07XG4gICAgICAgIGlmIChtWzZdKSB7XG4gICAgICAgICAgICBzICs9IFwiOlwiICsgbVs2XTtcbiAgICAgICAgICAgIGlmIChtWzddKVxuICAgICAgICAgICAgICAgIHMgKz0gXCIuXCIgKyBtWzddO1xuICAgICAgICB9XG4gICAgfVxuICAgIGlmIChtWzhdKSB7XG4gICAgICAgIHMgKz0gXCIgVVRDXCI7XG4gICAgICAgIGlmIChtWzhdICE9ICdaJykge1xuICAgICAgICAgICAgcyArPSBtWzhdO1xuICAgICAgICAgICAgaWYgKG1bOV0pXG4gICAgICAgICAgICAgICAgcyArPSBcIjpcIiArIG1bOV07XG4gICAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIHM7XG59O1xuU3RyZWFtLnByb3RvdHlwZS5wYXJzZUludGVnZXIgPSBmdW5jdGlvbiAoc3RhcnQsIGVuZCkge1xuICAgIC8vVE9ETyBzdXBwb3J0IG5lZ2F0aXZlIG51bWJlcnNcbiAgICB2YXIgbGVuID0gZW5kIC0gc3RhcnQ7XG4gICAgaWYgKGxlbiA+IDQpIHtcbiAgICAgICAgbGVuIDw8PSAzO1xuICAgICAgICB2YXIgcyA9IHRoaXMuZ2V0KHN0YXJ0KTtcbiAgICAgICAgaWYgKHMgPT09IDApXG4gICAgICAgICAgICBsZW4gLT0gODtcbiAgICAgICAgZWxzZVxuICAgICAgICAgICAgd2hpbGUgKHMgPCAxMjgpIHtcbiAgICAgICAgICAgICAgICBzIDw8PSAxO1xuICAgICAgICAgICAgICAgIC0tbGVuO1xuICAgICAgICAgICAgfVxuICAgICAgICByZXR1cm4gXCIoXCIgKyBsZW4gKyBcIiBiaXQpXCI7XG4gICAgfVxuICAgIHZhciBuID0gMDtcbiAgICBmb3IgKHZhciBpID0gc3RhcnQ7IGkgPCBlbmQ7ICsraSlcbiAgICAgICAgbiA9IChuIDw8IDgpIHwgdGhpcy5nZXQoaSk7XG4gICAgcmV0dXJuIG47XG59O1xuU3RyZWFtLnByb3RvdHlwZS5wYXJzZUJpdFN0cmluZyA9IGZ1bmN0aW9uIChzdGFydCwgZW5kKSB7XG4gICAgdmFyIHVudXNlZEJpdCA9IHRoaXMuZ2V0KHN0YXJ0KSxcbiAgICAgICAgbGVuQml0ID0gKChlbmQgLSBzdGFydCAtIDEpIDw8IDMpIC0gdW51c2VkQml0LFxuICAgICAgICBzID0gXCIoXCIgKyBsZW5CaXQgKyBcIiBiaXQpXCI7XG4gICAgaWYgKGxlbkJpdCA8PSAyMCkge1xuICAgICAgICB2YXIgc2tpcCA9IHVudXNlZEJpdDtcbiAgICAgICAgcyArPSBcIiBcIjtcbiAgICAgICAgZm9yICh2YXIgaSA9IGVuZCAtIDE7IGkgPiBzdGFydDsgLS1pKSB7XG4gICAgICAgICAgICB2YXIgYiA9IHRoaXMuZ2V0KGkpO1xuICAgICAgICAgICAgZm9yICh2YXIgaiA9IHNraXA7IGogPCA4OyArK2opXG4gICAgICAgICAgICAgICAgcyArPSAoYiA+PiBqKSAmIDEgPyBcIjFcIiA6IFwiMFwiO1xuICAgICAgICAgICAgc2tpcCA9IDA7XG4gICAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIHM7XG59O1xuU3RyZWFtLnByb3RvdHlwZS5wYXJzZU9jdGV0U3RyaW5nID0gZnVuY3Rpb24gKHN0YXJ0LCBlbmQpIHtcbiAgICB2YXIgbGVuID0gZW5kIC0gc3RhcnQsXG4gICAgICAgIHMgPSBcIihcIiArIGxlbiArIFwiIGJ5dGUpIFwiO1xuICAgIGlmIChsZW4gPiBoYXJkTGltaXQpXG4gICAgICAgIGVuZCA9IHN0YXJ0ICsgaGFyZExpbWl0O1xuICAgIGZvciAodmFyIGkgPSBzdGFydDsgaSA8IGVuZDsgKytpKVxuICAgICAgICBzICs9IHRoaXMuaGV4Qnl0ZSh0aGlzLmdldChpKSk7IC8vVE9ETzogYWxzbyB0cnkgTGF0aW4xP1xuICAgIGlmIChsZW4gPiBoYXJkTGltaXQpXG4gICAgICAgIHMgKz0gZWxsaXBzaXM7XG4gICAgcmV0dXJuIHM7XG59O1xuU3RyZWFtLnByb3RvdHlwZS5wYXJzZU9JRCA9IGZ1bmN0aW9uIChzdGFydCwgZW5kKSB7XG4gICAgdmFyIHMgPSAnJyxcbiAgICAgICAgbiA9IDAsXG4gICAgICAgIGJpdHMgPSAwO1xuICAgIGZvciAodmFyIGkgPSBzdGFydDsgaSA8IGVuZDsgKytpKSB7XG4gICAgICAgIHZhciB2ID0gdGhpcy5nZXQoaSk7XG4gICAgICAgIG4gPSAobiA8PCA3KSB8ICh2ICYgMHg3Rik7XG4gICAgICAgIGJpdHMgKz0gNztcbiAgICAgICAgaWYgKCEodiAmIDB4ODApKSB7IC8vIGZpbmlzaGVkXG4gICAgICAgICAgICBpZiAocyA9PT0gJycpIHtcbiAgICAgICAgICAgICAgICB2YXIgbSA9IG4gPCA4MCA/IG4gPCA0MCA/IDAgOiAxIDogMjtcbiAgICAgICAgICAgICAgICBzID0gbSArIFwiLlwiICsgKG4gLSBtICogNDApO1xuICAgICAgICAgICAgfSBlbHNlXG4gICAgICAgICAgICAgICAgcyArPSBcIi5cIiArICgoYml0cyA+PSAzMSkgPyBcImJpZ2ludFwiIDogbik7XG4gICAgICAgICAgICBuID0gYml0cyA9IDA7XG4gICAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIHM7XG59O1xuXG5mdW5jdGlvbiBBU04xKHN0cmVhbSwgaGVhZGVyLCBsZW5ndGgsIHRhZywgc3ViKSB7XG4gICAgdGhpcy5zdHJlYW0gPSBzdHJlYW07XG4gICAgdGhpcy5oZWFkZXIgPSBoZWFkZXI7XG4gICAgdGhpcy5sZW5ndGggPSBsZW5ndGg7XG4gICAgdGhpcy50YWcgPSB0YWc7XG4gICAgdGhpcy5zdWIgPSBzdWI7XG59XG5BU04xLnByb3RvdHlwZS50eXBlTmFtZSA9IGZ1bmN0aW9uICgpIHtcbiAgICBpZiAodGhpcy50YWcgPT09IHVuZGVmaW5lZClcbiAgICAgICAgcmV0dXJuIFwidW5rbm93blwiO1xuICAgIHZhciB0YWdDbGFzcyA9IHRoaXMudGFnID4+IDYsXG4gICAgICAgIHRhZ0NvbnN0cnVjdGVkID0gKHRoaXMudGFnID4+IDUpICYgMSxcbiAgICAgICAgdGFnTnVtYmVyID0gdGhpcy50YWcgJiAweDFGO1xuICAgIHN3aXRjaCAodGFnQ2xhc3MpIHtcbiAgICBjYXNlIDA6IC8vIHVuaXZlcnNhbFxuICAgICAgICBzd2l0Y2ggKHRhZ051bWJlcikge1xuICAgICAgICBjYXNlIDB4MDA6IHJldHVybiBcIkVPQ1wiO1xuICAgICAgICBjYXNlIDB4MDE6IHJldHVybiBcIkJPT0xFQU5cIjtcbiAgICAgICAgY2FzZSAweDAyOiByZXR1cm4gXCJJTlRFR0VSXCI7XG4gICAgICAgIGNhc2UgMHgwMzogcmV0dXJuIFwiQklUX1NUUklOR1wiO1xuICAgICAgICBjYXNlIDB4MDQ6IHJldHVybiBcIk9DVEVUX1NUUklOR1wiO1xuICAgICAgICBjYXNlIDB4MDU6IHJldHVybiBcIk5VTExcIjtcbiAgICAgICAgY2FzZSAweDA2OiByZXR1cm4gXCJPQkpFQ1RfSURFTlRJRklFUlwiO1xuICAgICAgICBjYXNlIDB4MDc6IHJldHVybiBcIk9iamVjdERlc2NyaXB0b3JcIjtcbiAgICAgICAgY2FzZSAweDA4OiByZXR1cm4gXCJFWFRFUk5BTFwiO1xuICAgICAgICBjYXNlIDB4MDk6IHJldHVybiBcIlJFQUxcIjtcbiAgICAgICAgY2FzZSAweDBBOiByZXR1cm4gXCJFTlVNRVJBVEVEXCI7XG4gICAgICAgIGNhc2UgMHgwQjogcmV0dXJuIFwiRU1CRURERURfUERWXCI7XG4gICAgICAgIGNhc2UgMHgwQzogcmV0dXJuIFwiVVRGOFN0cmluZ1wiO1xuICAgICAgICBjYXNlIDB4MTA6IHJldHVybiBcIlNFUVVFTkNFXCI7XG4gICAgICAgIGNhc2UgMHgxMTogcmV0dXJuIFwiU0VUXCI7XG4gICAgICAgIGNhc2UgMHgxMjogcmV0dXJuIFwiTnVtZXJpY1N0cmluZ1wiO1xuICAgICAgICBjYXNlIDB4MTM6IHJldHVybiBcIlByaW50YWJsZVN0cmluZ1wiOyAvLyBBU0NJSSBzdWJzZXRcbiAgICAgICAgY2FzZSAweDE0OiByZXR1cm4gXCJUZWxldGV4U3RyaW5nXCI7IC8vIGFrYSBUNjFTdHJpbmdcbiAgICAgICAgY2FzZSAweDE1OiByZXR1cm4gXCJWaWRlb3RleFN0cmluZ1wiO1xuICAgICAgICBjYXNlIDB4MTY6IHJldHVybiBcIklBNVN0cmluZ1wiOyAvLyBBU0NJSVxuICAgICAgICBjYXNlIDB4MTc6IHJldHVybiBcIlVUQ1RpbWVcIjtcbiAgICAgICAgY2FzZSAweDE4OiByZXR1cm4gXCJHZW5lcmFsaXplZFRpbWVcIjtcbiAgICAgICAgY2FzZSAweDE5OiByZXR1cm4gXCJHcmFwaGljU3RyaW5nXCI7XG4gICAgICAgIGNhc2UgMHgxQTogcmV0dXJuIFwiVmlzaWJsZVN0cmluZ1wiOyAvLyBBU0NJSSBzdWJzZXRcbiAgICAgICAgY2FzZSAweDFCOiByZXR1cm4gXCJHZW5lcmFsU3RyaW5nXCI7XG4gICAgICAgIGNhc2UgMHgxQzogcmV0dXJuIFwiVW5pdmVyc2FsU3RyaW5nXCI7XG4gICAgICAgIGNhc2UgMHgxRTogcmV0dXJuIFwiQk1QU3RyaW5nXCI7XG4gICAgICAgIGRlZmF1bHQ6ICAgcmV0dXJuIFwiVW5pdmVyc2FsX1wiICsgdGFnTnVtYmVyLnRvU3RyaW5nKDE2KTtcbiAgICAgICAgfVxuICAgIGNhc2UgMTogcmV0dXJuIFwiQXBwbGljYXRpb25fXCIgKyB0YWdOdW1iZXIudG9TdHJpbmcoMTYpO1xuICAgIGNhc2UgMjogcmV0dXJuIFwiW1wiICsgdGFnTnVtYmVyICsgXCJdXCI7IC8vIENvbnRleHRcbiAgICBjYXNlIDM6IHJldHVybiBcIlByaXZhdGVfXCIgKyB0YWdOdW1iZXIudG9TdHJpbmcoMTYpO1xuICAgIH1cbn07XG5BU04xLnByb3RvdHlwZS5yZVNlZW1zQVNDSUkgPSAvXlsgLX5dKyQvO1xuQVNOMS5wcm90b3R5cGUuY29udGVudCA9IGZ1bmN0aW9uICgpIHtcbiAgICBpZiAodGhpcy50YWcgPT09IHVuZGVmaW5lZClcbiAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgdmFyIHRhZ0NsYXNzID0gdGhpcy50YWcgPj4gNixcbiAgICAgICAgdGFnTnVtYmVyID0gdGhpcy50YWcgJiAweDFGLFxuICAgICAgICBjb250ZW50ID0gdGhpcy5wb3NDb250ZW50KCksXG4gICAgICAgIGxlbiA9IE1hdGguYWJzKHRoaXMubGVuZ3RoKTtcbiAgICBpZiAodGFnQ2xhc3MgIT09IDApIHsgLy8gdW5pdmVyc2FsXG4gICAgICAgIGlmICh0aGlzLnN1YiAhPT0gbnVsbClcbiAgICAgICAgICAgIHJldHVybiBcIihcIiArIHRoaXMuc3ViLmxlbmd0aCArIFwiIGVsZW0pXCI7XG4gICAgICAgIC8vVE9ETzogVFJZIFRPIFBBUlNFIEFTQ0lJIFNUUklOR1xuICAgICAgICB2YXIgcyA9IHRoaXMuc3RyZWFtLnBhcnNlU3RyaW5nSVNPKGNvbnRlbnQsIGNvbnRlbnQgKyBNYXRoLm1pbihsZW4sIGhhcmRMaW1pdCkpO1xuICAgICAgICBpZiAodGhpcy5yZVNlZW1zQVNDSUkudGVzdChzKSlcbiAgICAgICAgICAgIHJldHVybiBzLnN1YnN0cmluZygwLCAyICogaGFyZExpbWl0KSArICgocy5sZW5ndGggPiAyICogaGFyZExpbWl0KSA/IGVsbGlwc2lzIDogXCJcIik7XG4gICAgICAgIGVsc2VcbiAgICAgICAgICAgIHJldHVybiB0aGlzLnN0cmVhbS5wYXJzZU9jdGV0U3RyaW5nKGNvbnRlbnQsIGNvbnRlbnQgKyBsZW4pO1xuICAgIH1cbiAgICBzd2l0Y2ggKHRhZ051bWJlcikge1xuICAgIGNhc2UgMHgwMTogLy8gQk9PTEVBTlxuICAgICAgICByZXR1cm4gKHRoaXMuc3RyZWFtLmdldChjb250ZW50KSA9PT0gMCkgPyBcImZhbHNlXCIgOiBcInRydWVcIjtcbiAgICBjYXNlIDB4MDI6IC8vIElOVEVHRVJcbiAgICAgICAgcmV0dXJuIHRoaXMuc3RyZWFtLnBhcnNlSW50ZWdlcihjb250ZW50LCBjb250ZW50ICsgbGVuKTtcbiAgICBjYXNlIDB4MDM6IC8vIEJJVF9TVFJJTkdcbiAgICAgICAgcmV0dXJuIHRoaXMuc3ViID8gXCIoXCIgKyB0aGlzLnN1Yi5sZW5ndGggKyBcIiBlbGVtKVwiIDpcbiAgICAgICAgICAgIHRoaXMuc3RyZWFtLnBhcnNlQml0U3RyaW5nKGNvbnRlbnQsIGNvbnRlbnQgKyBsZW4pO1xuICAgIGNhc2UgMHgwNDogLy8gT0NURVRfU1RSSU5HXG4gICAgICAgIHJldHVybiB0aGlzLnN1YiA/IFwiKFwiICsgdGhpcy5zdWIubGVuZ3RoICsgXCIgZWxlbSlcIiA6XG4gICAgICAgICAgICB0aGlzLnN0cmVhbS5wYXJzZU9jdGV0U3RyaW5nKGNvbnRlbnQsIGNvbnRlbnQgKyBsZW4pO1xuICAgIC8vY2FzZSAweDA1OiAvLyBOVUxMXG4gICAgY2FzZSAweDA2OiAvLyBPQkpFQ1RfSURFTlRJRklFUlxuICAgICAgICByZXR1cm4gdGhpcy5zdHJlYW0ucGFyc2VPSUQoY29udGVudCwgY29udGVudCArIGxlbik7XG4gICAgLy9jYXNlIDB4MDc6IC8vIE9iamVjdERlc2NyaXB0b3JcbiAgICAvL2Nhc2UgMHgwODogLy8gRVhURVJOQUxcbiAgICAvL2Nhc2UgMHgwOTogLy8gUkVBTFxuICAgIC8vY2FzZSAweDBBOiAvLyBFTlVNRVJBVEVEXG4gICAgLy9jYXNlIDB4MEI6IC8vIEVNQkVEREVEX1BEVlxuICAgIGNhc2UgMHgxMDogLy8gU0VRVUVOQ0VcbiAgICBjYXNlIDB4MTE6IC8vIFNFVFxuICAgICAgICByZXR1cm4gXCIoXCIgKyB0aGlzLnN1Yi5sZW5ndGggKyBcIiBlbGVtKVwiO1xuICAgIGNhc2UgMHgwQzogLy8gVVRGOFN0cmluZ1xuICAgICAgICByZXR1cm4gdGhpcy5zdHJlYW0ucGFyc2VTdHJpbmdVVEYoY29udGVudCwgY29udGVudCArIGxlbik7XG4gICAgY2FzZSAweDEyOiAvLyBOdW1lcmljU3RyaW5nXG4gICAgY2FzZSAweDEzOiAvLyBQcmludGFibGVTdHJpbmdcbiAgICBjYXNlIDB4MTQ6IC8vIFRlbGV0ZXhTdHJpbmdcbiAgICBjYXNlIDB4MTU6IC8vIFZpZGVvdGV4U3RyaW5nXG4gICAgY2FzZSAweDE2OiAvLyBJQTVTdHJpbmdcbiAgICAvL2Nhc2UgMHgxOTogLy8gR3JhcGhpY1N0cmluZ1xuICAgIGNhc2UgMHgxQTogLy8gVmlzaWJsZVN0cmluZ1xuICAgIC8vY2FzZSAweDFCOiAvLyBHZW5lcmFsU3RyaW5nXG4gICAgLy9jYXNlIDB4MUM6IC8vIFVuaXZlcnNhbFN0cmluZ1xuICAgICAgICByZXR1cm4gdGhpcy5zdHJlYW0ucGFyc2VTdHJpbmdJU08oY29udGVudCwgY29udGVudCArIGxlbik7XG4gICAgY2FzZSAweDFFOiAvLyBCTVBTdHJpbmdcbiAgICAgICAgcmV0dXJuIHRoaXMuc3RyZWFtLnBhcnNlU3RyaW5nQk1QKGNvbnRlbnQsIGNvbnRlbnQgKyBsZW4pO1xuICAgIGNhc2UgMHgxNzogLy8gVVRDVGltZVxuICAgIGNhc2UgMHgxODogLy8gR2VuZXJhbGl6ZWRUaW1lXG4gICAgICAgIHJldHVybiB0aGlzLnN0cmVhbS5wYXJzZVRpbWUoY29udGVudCwgY29udGVudCArIGxlbik7XG4gICAgfVxuICAgIHJldHVybiBudWxsO1xufTtcbkFTTjEucHJvdG90eXBlLnRvU3RyaW5nID0gZnVuY3Rpb24gKCkge1xuICAgIHJldHVybiB0aGlzLnR5cGVOYW1lKCkgKyBcIkBcIiArIHRoaXMuc3RyZWFtLnBvcyArIFwiW2hlYWRlcjpcIiArIHRoaXMuaGVhZGVyICsgXCIsbGVuZ3RoOlwiICsgdGhpcy5sZW5ndGggKyBcIixzdWI6XCIgKyAoKHRoaXMuc3ViID09PSBudWxsKSA/ICdudWxsJyA6IHRoaXMuc3ViLmxlbmd0aCkgKyBcIl1cIjtcbn07XG5BU04xLnByb3RvdHlwZS5wcmludCA9IGZ1bmN0aW9uIChpbmRlbnQpIHtcbiAgICBpZiAoaW5kZW50ID09PSB1bmRlZmluZWQpIGluZGVudCA9ICcnO1xuICAgIGRvY3VtZW50LndyaXRlbG4oaW5kZW50ICsgdGhpcyk7XG4gICAgaWYgKHRoaXMuc3ViICE9PSBudWxsKSB7XG4gICAgICAgIGluZGVudCArPSAnICAnO1xuICAgICAgICBmb3IgKHZhciBpID0gMCwgbWF4ID0gdGhpcy5zdWIubGVuZ3RoOyBpIDwgbWF4OyArK2kpXG4gICAgICAgICAgICB0aGlzLnN1YltpXS5wcmludChpbmRlbnQpO1xuICAgIH1cbn07XG5BU04xLnByb3RvdHlwZS50b1ByZXR0eVN0cmluZyA9IGZ1bmN0aW9uIChpbmRlbnQpIHtcbiAgICBpZiAoaW5kZW50ID09PSB1bmRlZmluZWQpIGluZGVudCA9ICcnO1xuICAgIHZhciBzID0gaW5kZW50ICsgdGhpcy50eXBlTmFtZSgpICsgXCIgQFwiICsgdGhpcy5zdHJlYW0ucG9zO1xuICAgIGlmICh0aGlzLmxlbmd0aCA+PSAwKVxuICAgICAgICBzICs9IFwiK1wiO1xuICAgIHMgKz0gdGhpcy5sZW5ndGg7XG4gICAgaWYgKHRoaXMudGFnICYgMHgyMClcbiAgICAgICAgcyArPSBcIiAoY29uc3RydWN0ZWQpXCI7XG4gICAgZWxzZSBpZiAoKCh0aGlzLnRhZyA9PSAweDAzKSB8fCAodGhpcy50YWcgPT0gMHgwNCkpICYmICh0aGlzLnN1YiAhPT0gbnVsbCkpXG4gICAgICAgIHMgKz0gXCIgKGVuY2Fwc3VsYXRlcylcIjtcbiAgICBzICs9IFwiXFxuXCI7XG4gICAgaWYgKHRoaXMuc3ViICE9PSBudWxsKSB7XG4gICAgICAgIGluZGVudCArPSAnICAnO1xuICAgICAgICBmb3IgKHZhciBpID0gMCwgbWF4ID0gdGhpcy5zdWIubGVuZ3RoOyBpIDwgbWF4OyArK2kpXG4gICAgICAgICAgICBzICs9IHRoaXMuc3ViW2ldLnRvUHJldHR5U3RyaW5nKGluZGVudCk7XG4gICAgfVxuICAgIHJldHVybiBzO1xufTtcbkFTTjEucHJvdG90eXBlLnRvRE9NID0gZnVuY3Rpb24gKCkge1xuICAgIHZhciBub2RlID0gRE9NLnRhZyhcImRpdlwiLCBcIm5vZGVcIik7XG4gICAgbm9kZS5hc24xID0gdGhpcztcbiAgICB2YXIgaGVhZCA9IERPTS50YWcoXCJkaXZcIiwgXCJoZWFkXCIpO1xuICAgIHZhciBzID0gdGhpcy50eXBlTmFtZSgpLnJlcGxhY2UoL18vZywgXCIgXCIpO1xuICAgIGhlYWQuaW5uZXJIVE1MID0gcztcbiAgICB2YXIgY29udGVudCA9IHRoaXMuY29udGVudCgpO1xuICAgIGlmIChjb250ZW50ICE9PSBudWxsKSB7XG4gICAgICAgIGNvbnRlbnQgPSBTdHJpbmcoY29udGVudCkucmVwbGFjZSgvPC9nLCBcIiZsdDtcIik7XG4gICAgICAgIHZhciBwcmV2aWV3ID0gRE9NLnRhZyhcInNwYW5cIiwgXCJwcmV2aWV3XCIpO1xuICAgICAgICBwcmV2aWV3LmFwcGVuZENoaWxkKERPTS50ZXh0KGNvbnRlbnQpKTtcbiAgICAgICAgaGVhZC5hcHBlbmRDaGlsZChwcmV2aWV3KTtcbiAgICB9XG4gICAgbm9kZS5hcHBlbmRDaGlsZChoZWFkKTtcbiAgICB0aGlzLm5vZGUgPSBub2RlO1xuICAgIHRoaXMuaGVhZCA9IGhlYWQ7XG4gICAgdmFyIHZhbHVlID0gRE9NLnRhZyhcImRpdlwiLCBcInZhbHVlXCIpO1xuICAgIHMgPSBcIk9mZnNldDogXCIgKyB0aGlzLnN0cmVhbS5wb3MgKyBcIjxici8+XCI7XG4gICAgcyArPSBcIkxlbmd0aDogXCIgKyB0aGlzLmhlYWRlciArIFwiK1wiO1xuICAgIGlmICh0aGlzLmxlbmd0aCA+PSAwKVxuICAgICAgICBzICs9IHRoaXMubGVuZ3RoO1xuICAgIGVsc2VcbiAgICAgICAgcyArPSAoLXRoaXMubGVuZ3RoKSArIFwiICh1bmRlZmluZWQpXCI7XG4gICAgaWYgKHRoaXMudGFnICYgMHgyMClcbiAgICAgICAgcyArPSBcIjxici8+KGNvbnN0cnVjdGVkKVwiO1xuICAgIGVsc2UgaWYgKCgodGhpcy50YWcgPT0gMHgwMykgfHwgKHRoaXMudGFnID09IDB4MDQpKSAmJiAodGhpcy5zdWIgIT09IG51bGwpKVxuICAgICAgICBzICs9IFwiPGJyLz4oZW5jYXBzdWxhdGVzKVwiO1xuICAgIC8vVE9ETyBpZiAodGhpcy50YWcgPT0gMHgwMykgcyArPSBcIlVudXNlZCBiaXRzOiBcIlxuICAgIGlmIChjb250ZW50ICE9PSBudWxsKSB7XG4gICAgICAgIHMgKz0gXCI8YnIvPlZhbHVlOjxici8+PGI+XCIgKyBjb250ZW50ICsgXCI8L2I+XCI7XG4gICAgICAgIGlmICgodHlwZW9mIG9pZHMgPT09ICdvYmplY3QnKSAmJiAodGhpcy50YWcgPT0gMHgwNikpIHtcbiAgICAgICAgICAgIHZhciBvaWQgPSBvaWRzW2NvbnRlbnRdO1xuICAgICAgICAgICAgaWYgKG9pZCkge1xuICAgICAgICAgICAgICAgIGlmIChvaWQuZCkgcyArPSBcIjxici8+XCIgKyBvaWQuZDtcbiAgICAgICAgICAgICAgICBpZiAob2lkLmMpIHMgKz0gXCI8YnIvPlwiICsgb2lkLmM7XG4gICAgICAgICAgICAgICAgaWYgKG9pZC53KSBzICs9IFwiPGJyLz4od2FybmluZyEpXCI7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG4gICAgdmFsdWUuaW5uZXJIVE1MID0gcztcbiAgICBub2RlLmFwcGVuZENoaWxkKHZhbHVlKTtcbiAgICB2YXIgc3ViID0gRE9NLnRhZyhcImRpdlwiLCBcInN1YlwiKTtcbiAgICBpZiAodGhpcy5zdWIgIT09IG51bGwpIHtcbiAgICAgICAgZm9yICh2YXIgaSA9IDAsIG1heCA9IHRoaXMuc3ViLmxlbmd0aDsgaSA8IG1heDsgKytpKVxuICAgICAgICAgICAgc3ViLmFwcGVuZENoaWxkKHRoaXMuc3ViW2ldLnRvRE9NKCkpO1xuICAgIH1cbiAgICBub2RlLmFwcGVuZENoaWxkKHN1Yik7XG4gICAgaGVhZC5vbmNsaWNrID0gZnVuY3Rpb24gKCkge1xuICAgICAgICBub2RlLmNsYXNzTmFtZSA9IChub2RlLmNsYXNzTmFtZSA9PSBcIm5vZGUgY29sbGFwc2VkXCIpID8gXCJub2RlXCIgOiBcIm5vZGUgY29sbGFwc2VkXCI7XG4gICAgfTtcbiAgICByZXR1cm4gbm9kZTtcbn07XG5BU04xLnByb3RvdHlwZS5wb3NTdGFydCA9IGZ1bmN0aW9uICgpIHtcbiAgICByZXR1cm4gdGhpcy5zdHJlYW0ucG9zO1xufTtcbkFTTjEucHJvdG90eXBlLnBvc0NvbnRlbnQgPSBmdW5jdGlvbiAoKSB7XG4gICAgcmV0dXJuIHRoaXMuc3RyZWFtLnBvcyArIHRoaXMuaGVhZGVyO1xufTtcbkFTTjEucHJvdG90eXBlLnBvc0VuZCA9IGZ1bmN0aW9uICgpIHtcbiAgICByZXR1cm4gdGhpcy5zdHJlYW0ucG9zICsgdGhpcy5oZWFkZXIgKyBNYXRoLmFicyh0aGlzLmxlbmd0aCk7XG59O1xuQVNOMS5wcm90b3R5cGUuZmFrZUhvdmVyID0gZnVuY3Rpb24gKGN1cnJlbnQpIHtcbiAgICB0aGlzLm5vZGUuY2xhc3NOYW1lICs9IFwiIGhvdmVyXCI7XG4gICAgaWYgKGN1cnJlbnQpXG4gICAgICAgIHRoaXMuaGVhZC5jbGFzc05hbWUgKz0gXCIgaG92ZXJcIjtcbn07XG5BU04xLnByb3RvdHlwZS5mYWtlT3V0ID0gZnVuY3Rpb24gKGN1cnJlbnQpIHtcbiAgICB2YXIgcmUgPSAvID9ob3Zlci87XG4gICAgdGhpcy5ub2RlLmNsYXNzTmFtZSA9IHRoaXMubm9kZS5jbGFzc05hbWUucmVwbGFjZShyZSwgXCJcIik7XG4gICAgaWYgKGN1cnJlbnQpXG4gICAgICAgIHRoaXMuaGVhZC5jbGFzc05hbWUgPSB0aGlzLmhlYWQuY2xhc3NOYW1lLnJlcGxhY2UocmUsIFwiXCIpO1xufTtcbkFTTjEucHJvdG90eXBlLnRvSGV4RE9NX3N1YiA9IGZ1bmN0aW9uIChub2RlLCBjbGFzc05hbWUsIHN0cmVhbSwgc3RhcnQsIGVuZCkge1xuICAgIGlmIChzdGFydCA+PSBlbmQpXG4gICAgICAgIHJldHVybjtcbiAgICB2YXIgc3ViID0gRE9NLnRhZyhcInNwYW5cIiwgY2xhc3NOYW1lKTtcbiAgICBzdWIuYXBwZW5kQ2hpbGQoRE9NLnRleHQoXG4gICAgICAgIHN0cmVhbS5oZXhEdW1wKHN0YXJ0LCBlbmQpKSk7XG4gICAgbm9kZS5hcHBlbmRDaGlsZChzdWIpO1xufTtcbkFTTjEucHJvdG90eXBlLnRvSGV4RE9NID0gZnVuY3Rpb24gKHJvb3QpIHtcbiAgICB2YXIgbm9kZSA9IERPTS50YWcoXCJzcGFuXCIsIFwiaGV4XCIpO1xuICAgIGlmIChyb290ID09PSB1bmRlZmluZWQpIHJvb3QgPSBub2RlO1xuICAgIHRoaXMuaGVhZC5oZXhOb2RlID0gbm9kZTtcbiAgICB0aGlzLmhlYWQub25tb3VzZW92ZXIgPSBmdW5jdGlvbiAoKSB7IHRoaXMuaGV4Tm9kZS5jbGFzc05hbWUgPSBcImhleEN1cnJlbnRcIjsgfTtcbiAgICB0aGlzLmhlYWQub25tb3VzZW91dCAgPSBmdW5jdGlvbiAoKSB7IHRoaXMuaGV4Tm9kZS5jbGFzc05hbWUgPSBcImhleFwiOyB9O1xuICAgIG5vZGUuYXNuMSA9IHRoaXM7XG4gICAgbm9kZS5vbm1vdXNlb3ZlciA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdmFyIGN1cnJlbnQgPSAhcm9vdC5zZWxlY3RlZDtcbiAgICAgICAgaWYgKGN1cnJlbnQpIHtcbiAgICAgICAgICAgIHJvb3Quc2VsZWN0ZWQgPSB0aGlzLmFzbjE7XG4gICAgICAgICAgICB0aGlzLmNsYXNzTmFtZSA9IFwiaGV4Q3VycmVudFwiO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuYXNuMS5mYWtlSG92ZXIoY3VycmVudCk7XG4gICAgfTtcbiAgICBub2RlLm9ubW91c2VvdXQgID0gZnVuY3Rpb24gKCkge1xuICAgICAgICB2YXIgY3VycmVudCA9IChyb290LnNlbGVjdGVkID09IHRoaXMuYXNuMSk7XG4gICAgICAgIHRoaXMuYXNuMS5mYWtlT3V0KGN1cnJlbnQpO1xuICAgICAgICBpZiAoY3VycmVudCkge1xuICAgICAgICAgICAgcm9vdC5zZWxlY3RlZCA9IG51bGw7XG4gICAgICAgICAgICB0aGlzLmNsYXNzTmFtZSA9IFwiaGV4XCI7XG4gICAgICAgIH1cbiAgICB9O1xuICAgIHRoaXMudG9IZXhET01fc3ViKG5vZGUsIFwidGFnXCIsIHRoaXMuc3RyZWFtLCB0aGlzLnBvc1N0YXJ0KCksIHRoaXMucG9zU3RhcnQoKSArIDEpO1xuICAgIHRoaXMudG9IZXhET01fc3ViKG5vZGUsICh0aGlzLmxlbmd0aCA+PSAwKSA/IFwiZGxlblwiIDogXCJ1bGVuXCIsIHRoaXMuc3RyZWFtLCB0aGlzLnBvc1N0YXJ0KCkgKyAxLCB0aGlzLnBvc0NvbnRlbnQoKSk7XG4gICAgaWYgKHRoaXMuc3ViID09PSBudWxsKVxuICAgICAgICBub2RlLmFwcGVuZENoaWxkKERPTS50ZXh0KFxuICAgICAgICAgICAgdGhpcy5zdHJlYW0uaGV4RHVtcCh0aGlzLnBvc0NvbnRlbnQoKSwgdGhpcy5wb3NFbmQoKSkpKTtcbiAgICBlbHNlIGlmICh0aGlzLnN1Yi5sZW5ndGggPiAwKSB7XG4gICAgICAgIHZhciBmaXJzdCA9IHRoaXMuc3ViWzBdO1xuICAgICAgICB2YXIgbGFzdCA9IHRoaXMuc3ViW3RoaXMuc3ViLmxlbmd0aCAtIDFdO1xuICAgICAgICB0aGlzLnRvSGV4RE9NX3N1Yihub2RlLCBcImludHJvXCIsIHRoaXMuc3RyZWFtLCB0aGlzLnBvc0NvbnRlbnQoKSwgZmlyc3QucG9zU3RhcnQoKSk7XG4gICAgICAgIGZvciAodmFyIGkgPSAwLCBtYXggPSB0aGlzLnN1Yi5sZW5ndGg7IGkgPCBtYXg7ICsraSlcbiAgICAgICAgICAgIG5vZGUuYXBwZW5kQ2hpbGQodGhpcy5zdWJbaV0udG9IZXhET00ocm9vdCkpO1xuICAgICAgICB0aGlzLnRvSGV4RE9NX3N1Yihub2RlLCBcIm91dHJvXCIsIHRoaXMuc3RyZWFtLCBsYXN0LnBvc0VuZCgpLCB0aGlzLnBvc0VuZCgpKTtcbiAgICB9XG4gICAgcmV0dXJuIG5vZGU7XG59O1xuQVNOMS5wcm90b3R5cGUudG9IZXhTdHJpbmcgPSBmdW5jdGlvbiAocm9vdCkge1xuICAgIHJldHVybiB0aGlzLnN0cmVhbS5oZXhEdW1wKHRoaXMucG9zU3RhcnQoKSwgdGhpcy5wb3NFbmQoKSwgdHJ1ZSk7XG59O1xuQVNOMS5kZWNvZGVMZW5ndGggPSBmdW5jdGlvbiAoc3RyZWFtKSB7XG4gICAgdmFyIGJ1ZiA9IHN0cmVhbS5nZXQoKSxcbiAgICAgICAgbGVuID0gYnVmICYgMHg3RjtcbiAgICBpZiAobGVuID09IGJ1ZilcbiAgICAgICAgcmV0dXJuIGxlbjtcbiAgICBpZiAobGVuID4gMylcbiAgICAgICAgdGhyb3cgXCJMZW5ndGggb3ZlciAyNCBiaXRzIG5vdCBzdXBwb3J0ZWQgYXQgcG9zaXRpb24gXCIgKyAoc3RyZWFtLnBvcyAtIDEpO1xuICAgIGlmIChsZW4gPT09IDApXG4gICAgICAgIHJldHVybiAtMTsgLy8gdW5kZWZpbmVkXG4gICAgYnVmID0gMDtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGxlbjsgKytpKVxuICAgICAgICBidWYgPSAoYnVmIDw8IDgpIHwgc3RyZWFtLmdldCgpO1xuICAgIHJldHVybiBidWY7XG59O1xuQVNOMS5oYXNDb250ZW50ID0gZnVuY3Rpb24gKHRhZywgbGVuLCBzdHJlYW0pIHtcbiAgICBpZiAodGFnICYgMHgyMCkgLy8gY29uc3RydWN0ZWRcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgaWYgKCh0YWcgPCAweDAzKSB8fCAodGFnID4gMHgwNCkpXG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICB2YXIgcCA9IG5ldyBTdHJlYW0oc3RyZWFtKTtcbiAgICBpZiAodGFnID09IDB4MDMpIHAuZ2V0KCk7IC8vIEJpdFN0cmluZyB1bnVzZWQgYml0cywgbXVzdCBiZSBpbiBbMCwgN11cbiAgICB2YXIgc3ViVGFnID0gcC5nZXQoKTtcbiAgICBpZiAoKHN1YlRhZyA+PiA2KSAmIDB4MDEpIC8vIG5vdCAodW5pdmVyc2FsIG9yIGNvbnRleHQpXG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICB0cnkge1xuICAgICAgICB2YXIgc3ViTGVuZ3RoID0gQVNOMS5kZWNvZGVMZW5ndGgocCk7XG4gICAgICAgIHJldHVybiAoKHAucG9zIC0gc3RyZWFtLnBvcykgKyBzdWJMZW5ndGggPT0gbGVuKTtcbiAgICB9IGNhdGNoIChleGNlcHRpb24pIHtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbn07XG5BU04xLmRlY29kZSA9IGZ1bmN0aW9uIChzdHJlYW0pIHtcbiAgICBpZiAoIShzdHJlYW0gaW5zdGFuY2VvZiBTdHJlYW0pKVxuICAgICAgICBzdHJlYW0gPSBuZXcgU3RyZWFtKHN0cmVhbSwgMCk7XG4gICAgdmFyIHN0cmVhbVN0YXJ0ID0gbmV3IFN0cmVhbShzdHJlYW0pLFxuICAgICAgICB0YWcgPSBzdHJlYW0uZ2V0KCksXG4gICAgICAgIGxlbiA9IEFTTjEuZGVjb2RlTGVuZ3RoKHN0cmVhbSksXG4gICAgICAgIGhlYWRlciA9IHN0cmVhbS5wb3MgLSBzdHJlYW1TdGFydC5wb3MsXG4gICAgICAgIHN1YiA9IG51bGw7XG4gICAgaWYgKEFTTjEuaGFzQ29udGVudCh0YWcsIGxlbiwgc3RyZWFtKSkge1xuICAgICAgICAvLyBpdCBoYXMgY29udGVudCwgc28gd2UgZGVjb2RlIGl0XG4gICAgICAgIHZhciBzdGFydCA9IHN0cmVhbS5wb3M7XG4gICAgICAgIGlmICh0YWcgPT0gMHgwMykgc3RyZWFtLmdldCgpOyAvLyBza2lwIEJpdFN0cmluZyB1bnVzZWQgYml0cywgbXVzdCBiZSBpbiBbMCwgN11cbiAgICAgICAgc3ViID0gW107XG4gICAgICAgIGlmIChsZW4gPj0gMCkge1xuICAgICAgICAgICAgLy8gZGVmaW5pdGUgbGVuZ3RoXG4gICAgICAgICAgICB2YXIgZW5kID0gc3RhcnQgKyBsZW47XG4gICAgICAgICAgICB3aGlsZSAoc3RyZWFtLnBvcyA8IGVuZClcbiAgICAgICAgICAgICAgICBzdWJbc3ViLmxlbmd0aF0gPSBBU04xLmRlY29kZShzdHJlYW0pO1xuICAgICAgICAgICAgaWYgKHN0cmVhbS5wb3MgIT0gZW5kKVxuICAgICAgICAgICAgICAgIHRocm93IFwiQ29udGVudCBzaXplIGlzIG5vdCBjb3JyZWN0IGZvciBjb250YWluZXIgc3RhcnRpbmcgYXQgb2Zmc2V0IFwiICsgc3RhcnQ7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAvLyB1bmRlZmluZWQgbGVuZ3RoXG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGZvciAoOzspIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHMgPSBBU04xLmRlY29kZShzdHJlYW0pO1xuICAgICAgICAgICAgICAgICAgICBpZiAocy50YWcgPT09IDApXG4gICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICAgICAgc3ViW3N1Yi5sZW5ndGhdID0gcztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgbGVuID0gc3RhcnQgLSBzdHJlYW0ucG9zO1xuICAgICAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgICAgICAgIHRocm93IFwiRXhjZXB0aW9uIHdoaWxlIGRlY29kaW5nIHVuZGVmaW5lZCBsZW5ndGggY29udGVudDogXCIgKyBlO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfSBlbHNlXG4gICAgICAgIHN0cmVhbS5wb3MgKz0gbGVuOyAvLyBza2lwIGNvbnRlbnRcbiAgICByZXR1cm4gbmV3IEFTTjEoc3RyZWFtU3RhcnQsIGhlYWRlciwgbGVuLCB0YWcsIHN1Yik7XG59O1xuQVNOMS50ZXN0ID0gZnVuY3Rpb24gKCkge1xuICAgIHZhciB0ZXN0ID0gW1xuICAgICAgICB7IHZhbHVlOiBbMHgyN10sICAgICAgICAgICAgICAgICAgIGV4cGVjdGVkOiAweDI3ICAgICB9LFxuICAgICAgICB7IHZhbHVlOiBbMHg4MSwgMHhDOV0sICAgICAgICAgICAgIGV4cGVjdGVkOiAweEM5ICAgICB9LFxuICAgICAgICB7IHZhbHVlOiBbMHg4MywgMHhGRSwgMHhEQywgMHhCQV0sIGV4cGVjdGVkOiAweEZFRENCQSB9XG4gICAgXTtcbiAgICBmb3IgKHZhciBpID0gMCwgbWF4ID0gdGVzdC5sZW5ndGg7IGkgPCBtYXg7ICsraSkge1xuICAgICAgICB2YXIgcG9zID0gMCxcbiAgICAgICAgICAgIHN0cmVhbSA9IG5ldyBTdHJlYW0odGVzdFtpXS52YWx1ZSwgMCksXG4gICAgICAgICAgICByZXMgPSBBU04xLmRlY29kZUxlbmd0aChzdHJlYW0pO1xuICAgICAgICBpZiAocmVzICE9IHRlc3RbaV0uZXhwZWN0ZWQpXG4gICAgICAgICAgICBkb2N1bWVudC53cml0ZShcIkluIHRlc3RbXCIgKyBpICsgXCJdIGV4cGVjdGVkIFwiICsgdGVzdFtpXS5leHBlY3RlZCArIFwiIGdvdCBcIiArIHJlcyArIFwiXFxuXCIpO1xuICAgIH1cbn07XG5cbi8vIGV4cG9ydCBnbG9iYWxzXG53aW5kb3cuQVNOMSA9IEFTTjE7XG59KSgpO1xuLyoqXG4gKiBSZXRyaWV2ZSB0aGUgaGV4YWRlY2ltYWwgdmFsdWUgKGFzIGEgc3RyaW5nKSBvZiB0aGUgY3VycmVudCBBU04uMSBlbGVtZW50XG4gKiBAcmV0dXJucyB7c3RyaW5nfVxuICogQHB1YmxpY1xuICovXG5BU04xLnByb3RvdHlwZS5nZXRIZXhTdHJpbmdWYWx1ZSA9IGZ1bmN0aW9uICgpIHtcbiAgdmFyIGhleFN0cmluZyA9IHRoaXMudG9IZXhTdHJpbmcoKTtcbiAgdmFyIG9mZnNldCA9IHRoaXMuaGVhZGVyICogMjtcbiAgdmFyIGxlbmd0aCA9IHRoaXMubGVuZ3RoICogMjtcbiAgcmV0dXJuIGhleFN0cmluZy5zdWJzdHIob2Zmc2V0LCBsZW5ndGgpO1xufTtcblxuLyoqXG4gKiBNZXRob2QgdG8gcGFyc2UgYSBwZW0gZW5jb2RlZCBzdHJpbmcgY29udGFpbmluZyBib3RoIGEgcHVibGljIG9yIHByaXZhdGUga2V5LlxuICogVGhlIG1ldGhvZCB3aWxsIHRyYW5zbGF0ZSB0aGUgcGVtIGVuY29kZWQgc3RyaW5nIGluIGEgZGVyIGVuY29kZWQgc3RyaW5nIGFuZFxuICogd2lsbCBwYXJzZSBwcml2YXRlIGtleSBhbmQgcHVibGljIGtleSBwYXJhbWV0ZXJzLiBUaGlzIG1ldGhvZCBhY2NlcHRzIHB1YmxpYyBrZXlcbiAqIGluIHRoZSByc2FlbmNyeXB0aW9uIHBrY3MgIzEgZm9ybWF0IChvaWQ6IDEuMi44NDAuMTEzNTQ5LjEuMS4xKS5cbiAqXG4gKiBAdG9kbyBDaGVjayBob3cgbWFueSByc2EgZm9ybWF0cyB1c2UgdGhlIHNhbWUgZm9ybWF0IG9mIHBrY3MgIzEuXG4gKlxuICogVGhlIGZvcm1hdCBpcyBkZWZpbmVkIGFzOlxuICogUHVibGljS2V5SW5mbyA6Oj0gU0VRVUVOQ0Uge1xuICogICBhbGdvcml0aG0gICAgICAgQWxnb3JpdGhtSWRlbnRpZmllcixcbiAqICAgUHVibGljS2V5ICAgICAgIEJJVCBTVFJJTkdcbiAqIH1cbiAqIFdoZXJlIEFsZ29yaXRobUlkZW50aWZpZXIgaXM6XG4gKiBBbGdvcml0aG1JZGVudGlmaWVyIDo6PSBTRVFVRU5DRSB7XG4gKiAgIGFsZ29yaXRobSAgICAgICBPQkpFQ1QgSURFTlRJRklFUiwgICAgIHRoZSBPSUQgb2YgdGhlIGVuYyBhbGdvcml0aG1cbiAqICAgcGFyYW1ldGVycyAgICAgIEFOWSBERUZJTkVEIEJZIGFsZ29yaXRobSBPUFRJT05BTCAoTlVMTCBmb3IgUEtDUyAjMSlcbiAqIH1cbiAqIGFuZCBQdWJsaWNLZXkgaXMgYSBTRVFVRU5DRSBlbmNhcHN1bGF0ZWQgaW4gYSBCSVQgU1RSSU5HXG4gKiBSU0FQdWJsaWNLZXkgOjo9IFNFUVVFTkNFIHtcbiAqICAgbW9kdWx1cyAgICAgICAgICAgSU5URUdFUiwgIC0tIG5cbiAqICAgcHVibGljRXhwb25lbnQgICAgSU5URUdFUiAgIC0tIGVcbiAqIH1cbiAqIGl0J3MgcG9zc2libGUgdG8gZXhhbWluZSB0aGUgc3RydWN0dXJlIG9mIHRoZSBrZXlzIG9idGFpbmVkIGZyb20gb3BlbnNzbCB1c2luZ1xuICogYW4gYXNuLjEgZHVtcGVyIGFzIHRoZSBvbmUgdXNlZCBoZXJlIHRvIHBhcnNlIHRoZSBjb21wb25lbnRzOiBodHRwOi8vbGFwby5pdC9hc24xanMvXG4gKiBAYXJndW1lbnQge3N0cmluZ30gcGVtIHRoZSBwZW0gZW5jb2RlZCBzdHJpbmcsIGNhbiBpbmNsdWRlIHRoZSBCRUdJTi9FTkQgaGVhZGVyL2Zvb3RlclxuICogQHByaXZhdGVcbiAqL1xuUlNBS2V5LnByb3RvdHlwZS5wYXJzZUtleSA9IGZ1bmN0aW9uIChwZW0pIHtcbiAgdHJ5IHtcbiAgICB2YXIgbW9kdWx1cyA9IDA7XG4gICAgdmFyIHB1YmxpY19leHBvbmVudCA9IDA7XG4gICAgdmFyIHJlSGV4ID0gL15cXHMqKD86WzAtOUEtRmEtZl1bMC05QS1GYS1mXVxccyopKyQvO1xuICAgIHZhciBkZXIgPSByZUhleC50ZXN0KHBlbSkgPyBIZXguZGVjb2RlKHBlbSkgOiBCYXNlNjQudW5hcm1vcihwZW0pO1xuICAgIHZhciBhc24xID0gQVNOMS5kZWNvZGUoZGVyKTtcblxuICAgIC8vRml4ZXMgYSBidWcgd2l0aCBPcGVuU1NMIDEuMCsgcHJpdmF0ZSBrZXlzXG4gICAgaWYoYXNuMS5zdWIubGVuZ3RoID09PSAzKXtcbiAgICAgICAgYXNuMSA9IGFzbjEuc3ViWzJdLnN1YlswXTtcbiAgICB9XG4gICAgaWYgKGFzbjEuc3ViLmxlbmd0aCA9PT0gOSkge1xuXG4gICAgICAvLyBQYXJzZSB0aGUgcHJpdmF0ZSBrZXkuXG4gICAgICBtb2R1bHVzID0gYXNuMS5zdWJbMV0uZ2V0SGV4U3RyaW5nVmFsdWUoKTsgLy9iaWdpbnRcbiAgICAgIHRoaXMubiA9IHBhcnNlQmlnSW50KG1vZHVsdXMsIDE2KTtcblxuICAgICAgcHVibGljX2V4cG9uZW50ID0gYXNuMS5zdWJbMl0uZ2V0SGV4U3RyaW5nVmFsdWUoKTsgLy9pbnRcbiAgICAgIHRoaXMuZSA9IHBhcnNlSW50KHB1YmxpY19leHBvbmVudCwgMTYpO1xuXG4gICAgICB2YXIgcHJpdmF0ZV9leHBvbmVudCA9IGFzbjEuc3ViWzNdLmdldEhleFN0cmluZ1ZhbHVlKCk7IC8vYmlnaW50XG4gICAgICB0aGlzLmQgPSBwYXJzZUJpZ0ludChwcml2YXRlX2V4cG9uZW50LCAxNik7XG5cbiAgICAgIHZhciBwcmltZTEgPSBhc24xLnN1Yls0XS5nZXRIZXhTdHJpbmdWYWx1ZSgpOyAvL2JpZ2ludFxuICAgICAgdGhpcy5wID0gcGFyc2VCaWdJbnQocHJpbWUxLCAxNik7XG5cbiAgICAgIHZhciBwcmltZTIgPSBhc24xLnN1Yls1XS5nZXRIZXhTdHJpbmdWYWx1ZSgpOyAvL2JpZ2ludFxuICAgICAgdGhpcy5xID0gcGFyc2VCaWdJbnQocHJpbWUyLCAxNik7XG5cbiAgICAgIHZhciBleHBvbmVudDEgPSBhc24xLnN1Yls2XS5nZXRIZXhTdHJpbmdWYWx1ZSgpOyAvL2JpZ2ludFxuICAgICAgdGhpcy5kbXAxID0gcGFyc2VCaWdJbnQoZXhwb25lbnQxLCAxNik7XG5cbiAgICAgIHZhciBleHBvbmVudDIgPSBhc24xLnN1Yls3XS5nZXRIZXhTdHJpbmdWYWx1ZSgpOyAvL2JpZ2ludFxuICAgICAgdGhpcy5kbXExID0gcGFyc2VCaWdJbnQoZXhwb25lbnQyLCAxNik7XG5cbiAgICAgIHZhciBjb2VmZmljaWVudCA9IGFzbjEuc3ViWzhdLmdldEhleFN0cmluZ1ZhbHVlKCk7IC8vYmlnaW50XG4gICAgICB0aGlzLmNvZWZmID0gcGFyc2VCaWdJbnQoY29lZmZpY2llbnQsIDE2KTtcblxuICAgIH1cbiAgICBlbHNlIGlmIChhc24xLnN1Yi5sZW5ndGggPT09IDIpIHtcblxuICAgICAgLy8gUGFyc2UgdGhlIHB1YmxpYyBrZXkuXG4gICAgICB2YXIgYml0X3N0cmluZyA9IGFzbjEuc3ViWzFdO1xuICAgICAgdmFyIHNlcXVlbmNlID0gYml0X3N0cmluZy5zdWJbMF07XG5cbiAgICAgIG1vZHVsdXMgPSBzZXF1ZW5jZS5zdWJbMF0uZ2V0SGV4U3RyaW5nVmFsdWUoKTtcbiAgICAgIHRoaXMubiA9IHBhcnNlQmlnSW50KG1vZHVsdXMsIDE2KTtcbiAgICAgIHB1YmxpY19leHBvbmVudCA9IHNlcXVlbmNlLnN1YlsxXS5nZXRIZXhTdHJpbmdWYWx1ZSgpO1xuICAgICAgdGhpcy5lID0gcGFyc2VJbnQocHVibGljX2V4cG9uZW50LCAxNik7XG5cbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuICAgIHJldHVybiB0cnVlO1xuICB9XG4gIGNhdGNoIChleCkge1xuICAgIHJldHVybiBmYWxzZTtcbiAgfVxufTtcblxuLyoqXG4gKiBUcmFuc2xhdGUgcnNhIHBhcmFtZXRlcnMgaW4gYSBoZXggZW5jb2RlZCBzdHJpbmcgcmVwcmVzZW50aW5nIHRoZSByc2Ega2V5LlxuICpcbiAqIFRoZSB0cmFuc2xhdGlvbiBmb2xsb3cgdGhlIEFTTi4xIG5vdGF0aW9uIDpcbiAqIFJTQVByaXZhdGVLZXkgOjo9IFNFUVVFTkNFIHtcbiAqICAgdmVyc2lvbiAgICAgICAgICAgVmVyc2lvbixcbiAqICAgbW9kdWx1cyAgICAgICAgICAgSU5URUdFUiwgIC0tIG5cbiAqICAgcHVibGljRXhwb25lbnQgICAgSU5URUdFUiwgIC0tIGVcbiAqICAgcHJpdmF0ZUV4cG9uZW50ICAgSU5URUdFUiwgIC0tIGRcbiAqICAgcHJpbWUxICAgICAgICAgICAgSU5URUdFUiwgIC0tIHBcbiAqICAgcHJpbWUyICAgICAgICAgICAgSU5URUdFUiwgIC0tIHFcbiAqICAgZXhwb25lbnQxICAgICAgICAgSU5URUdFUiwgIC0tIGQgbW9kIChwMSlcbiAqICAgZXhwb25lbnQyICAgICAgICAgSU5URUdFUiwgIC0tIGQgbW9kIChxLTEpXG4gKiAgIGNvZWZmaWNpZW50ICAgICAgIElOVEVHRVIsICAtLSAoaW52ZXJzZSBvZiBxKSBtb2QgcFxuICogfVxuICogQHJldHVybnMge3N0cmluZ30gIERFUiBFbmNvZGVkIFN0cmluZyByZXByZXNlbnRpbmcgdGhlIHJzYSBwcml2YXRlIGtleVxuICogQHByaXZhdGVcbiAqL1xuUlNBS2V5LnByb3RvdHlwZS5nZXRQcml2YXRlQmFzZUtleSA9IGZ1bmN0aW9uICgpIHtcbiAgdmFyIG9wdGlvbnMgPSB7XG4gICAgJ2FycmF5JzogW1xuICAgICAgbmV3IEtKVVIuYXNuMS5ERVJJbnRlZ2VyKHsnaW50JzogMH0pLFxuICAgICAgbmV3IEtKVVIuYXNuMS5ERVJJbnRlZ2VyKHsnYmlnaW50JzogdGhpcy5ufSksXG4gICAgICBuZXcgS0pVUi5hc24xLkRFUkludGVnZXIoeydpbnQnOiB0aGlzLmV9KSxcbiAgICAgIG5ldyBLSlVSLmFzbjEuREVSSW50ZWdlcih7J2JpZ2ludCc6IHRoaXMuZH0pLFxuICAgICAgbmV3IEtKVVIuYXNuMS5ERVJJbnRlZ2VyKHsnYmlnaW50JzogdGhpcy5wfSksXG4gICAgICBuZXcgS0pVUi5hc24xLkRFUkludGVnZXIoeydiaWdpbnQnOiB0aGlzLnF9KSxcbiAgICAgIG5ldyBLSlVSLmFzbjEuREVSSW50ZWdlcih7J2JpZ2ludCc6IHRoaXMuZG1wMX0pLFxuICAgICAgbmV3IEtKVVIuYXNuMS5ERVJJbnRlZ2VyKHsnYmlnaW50JzogdGhpcy5kbXExfSksXG4gICAgICBuZXcgS0pVUi5hc24xLkRFUkludGVnZXIoeydiaWdpbnQnOiB0aGlzLmNvZWZmfSlcbiAgICBdXG4gIH07XG4gIHZhciBzZXEgPSBuZXcgS0pVUi5hc24xLkRFUlNlcXVlbmNlKG9wdGlvbnMpO1xuICByZXR1cm4gc2VxLmdldEVuY29kZWRIZXgoKTtcbn07XG5cbi8qKlxuICogYmFzZTY0IChwZW0pIGVuY29kZWQgdmVyc2lvbiBvZiB0aGUgREVSIGVuY29kZWQgcmVwcmVzZW50YXRpb25cbiAqIEByZXR1cm5zIHtzdHJpbmd9IHBlbSBlbmNvZGVkIHJlcHJlc2VudGF0aW9uIHdpdGhvdXQgaGVhZGVyIGFuZCBmb290ZXJcbiAqIEBwdWJsaWNcbiAqL1xuUlNBS2V5LnByb3RvdHlwZS5nZXRQcml2YXRlQmFzZUtleUI2NCA9IGZ1bmN0aW9uICgpIHtcbiAgcmV0dXJuIGhleDJiNjQodGhpcy5nZXRQcml2YXRlQmFzZUtleSgpKTtcbn07XG5cbi8qKlxuICogVHJhbnNsYXRlIHJzYSBwYXJhbWV0ZXJzIGluIGEgaGV4IGVuY29kZWQgc3RyaW5nIHJlcHJlc2VudGluZyB0aGUgcnNhIHB1YmxpYyBrZXkuXG4gKiBUaGUgcmVwcmVzZW50YXRpb24gZm9sbG93IHRoZSBBU04uMSBub3RhdGlvbiA6XG4gKiBQdWJsaWNLZXlJbmZvIDo6PSBTRVFVRU5DRSB7XG4gKiAgIGFsZ29yaXRobSAgICAgICBBbGdvcml0aG1JZGVudGlmaWVyLFxuICogICBQdWJsaWNLZXkgICAgICAgQklUIFNUUklOR1xuICogfVxuICogV2hlcmUgQWxnb3JpdGhtSWRlbnRpZmllciBpczpcbiAqIEFsZ29yaXRobUlkZW50aWZpZXIgOjo9IFNFUVVFTkNFIHtcbiAqICAgYWxnb3JpdGhtICAgICAgIE9CSkVDVCBJREVOVElGSUVSLCAgICAgdGhlIE9JRCBvZiB0aGUgZW5jIGFsZ29yaXRobVxuICogICBwYXJhbWV0ZXJzICAgICAgQU5ZIERFRklORUQgQlkgYWxnb3JpdGhtIE9QVElPTkFMIChOVUxMIGZvciBQS0NTICMxKVxuICogfVxuICogYW5kIFB1YmxpY0tleSBpcyBhIFNFUVVFTkNFIGVuY2Fwc3VsYXRlZCBpbiBhIEJJVCBTVFJJTkdcbiAqIFJTQVB1YmxpY0tleSA6Oj0gU0VRVUVOQ0Uge1xuICogICBtb2R1bHVzICAgICAgICAgICBJTlRFR0VSLCAgLS0gblxuICogICBwdWJsaWNFeHBvbmVudCAgICBJTlRFR0VSICAgLS0gZVxuICogfVxuICogQHJldHVybnMge3N0cmluZ30gREVSIEVuY29kZWQgU3RyaW5nIHJlcHJlc2VudGluZyB0aGUgcnNhIHB1YmxpYyBrZXlcbiAqIEBwcml2YXRlXG4gKi9cblJTQUtleS5wcm90b3R5cGUuZ2V0UHVibGljQmFzZUtleSA9IGZ1bmN0aW9uICgpIHtcbiAgdmFyIG9wdGlvbnMgPSB7XG4gICAgJ2FycmF5JzogW1xuICAgICAgbmV3IEtKVVIuYXNuMS5ERVJPYmplY3RJZGVudGlmaWVyKHsnb2lkJzogJzEuMi44NDAuMTEzNTQ5LjEuMS4xJ30pLCAvL1JTQSBFbmNyeXB0aW9uIHBrY3MgIzEgb2lkXG4gICAgICBuZXcgS0pVUi5hc24xLkRFUk51bGwoKVxuICAgIF1cbiAgfTtcbiAgdmFyIGZpcnN0X3NlcXVlbmNlID0gbmV3IEtKVVIuYXNuMS5ERVJTZXF1ZW5jZShvcHRpb25zKTtcblxuICBvcHRpb25zID0ge1xuICAgICdhcnJheSc6IFtcbiAgICAgIG5ldyBLSlVSLmFzbjEuREVSSW50ZWdlcih7J2JpZ2ludCc6IHRoaXMubn0pLFxuICAgICAgbmV3IEtKVVIuYXNuMS5ERVJJbnRlZ2VyKHsnaW50JzogdGhpcy5lfSlcbiAgICBdXG4gIH07XG4gIHZhciBzZWNvbmRfc2VxdWVuY2UgPSBuZXcgS0pVUi5hc24xLkRFUlNlcXVlbmNlKG9wdGlvbnMpO1xuXG4gIG9wdGlvbnMgPSB7XG4gICAgJ2hleCc6ICcwMCcgKyBzZWNvbmRfc2VxdWVuY2UuZ2V0RW5jb2RlZEhleCgpXG4gIH07XG4gIHZhciBiaXRfc3RyaW5nID0gbmV3IEtKVVIuYXNuMS5ERVJCaXRTdHJpbmcob3B0aW9ucyk7XG5cbiAgb3B0aW9ucyA9IHtcbiAgICAnYXJyYXknOiBbXG4gICAgICBmaXJzdF9zZXF1ZW5jZSxcbiAgICAgIGJpdF9zdHJpbmdcbiAgICBdXG4gIH07XG4gIHZhciBzZXEgPSBuZXcgS0pVUi5hc24xLkRFUlNlcXVlbmNlKG9wdGlvbnMpO1xuICByZXR1cm4gc2VxLmdldEVuY29kZWRIZXgoKTtcbn07XG5cbi8qKlxuICogYmFzZTY0IChwZW0pIGVuY29kZWQgdmVyc2lvbiBvZiB0aGUgREVSIGVuY29kZWQgcmVwcmVzZW50YXRpb25cbiAqIEByZXR1cm5zIHtzdHJpbmd9IHBlbSBlbmNvZGVkIHJlcHJlc2VudGF0aW9uIHdpdGhvdXQgaGVhZGVyIGFuZCBmb290ZXJcbiAqIEBwdWJsaWNcbiAqL1xuUlNBS2V5LnByb3RvdHlwZS5nZXRQdWJsaWNCYXNlS2V5QjY0ID0gZnVuY3Rpb24gKCkge1xuICByZXR1cm4gaGV4MmI2NCh0aGlzLmdldFB1YmxpY0Jhc2VLZXkoKSk7XG59O1xuXG4vKipcbiAqIHdyYXAgdGhlIHN0cmluZyBpbiBibG9jayBvZiB3aWR0aCBjaGFycy4gVGhlIGRlZmF1bHQgdmFsdWUgZm9yIHJzYSBrZXlzIGlzIDY0XG4gKiBjaGFyYWN0ZXJzLlxuICogQHBhcmFtIHtzdHJpbmd9IHN0ciB0aGUgcGVtIGVuY29kZWQgc3RyaW5nIHdpdGhvdXQgaGVhZGVyIGFuZCBmb290ZXJcbiAqIEBwYXJhbSB7TnVtYmVyfSBbd2lkdGg9NjRdIC0gdGhlIGxlbmd0aCB0aGUgc3RyaW5nIGhhcyB0byBiZSB3cmFwcGVkIGF0XG4gKiBAcmV0dXJucyB7c3RyaW5nfVxuICogQHByaXZhdGVcbiAqL1xuUlNBS2V5LnByb3RvdHlwZS53b3Jkd3JhcCA9IGZ1bmN0aW9uIChzdHIsIHdpZHRoKSB7XG4gIHdpZHRoID0gd2lkdGggfHwgNjQ7XG4gIGlmICghc3RyKSB7XG4gICAgcmV0dXJuIHN0cjtcbiAgfVxuICB2YXIgcmVnZXggPSAnKC57MSwnICsgd2lkdGggKyAnfSkoICt8JFxcbj8pfCguezEsJyArIHdpZHRoICsgJ30pJztcbiAgcmV0dXJuIHN0ci5tYXRjaChSZWdFeHAocmVnZXgsICdnJykpLmpvaW4oJ1xcbicpO1xufTtcblxuLyoqXG4gKiBSZXRyaWV2ZSB0aGUgcGVtIGVuY29kZWQgcHJpdmF0ZSBrZXlcbiAqIEByZXR1cm5zIHtzdHJpbmd9IHRoZSBwZW0gZW5jb2RlZCBwcml2YXRlIGtleSB3aXRoIGhlYWRlci9mb290ZXJcbiAqIEBwdWJsaWNcbiAqL1xuUlNBS2V5LnByb3RvdHlwZS5nZXRQcml2YXRlS2V5ID0gZnVuY3Rpb24gKCkge1xuICB2YXIga2V5ID0gXCItLS0tLUJFR0lOIFJTQSBQUklWQVRFIEtFWS0tLS0tXFxuXCI7XG4gIGtleSArPSB0aGlzLndvcmR3cmFwKHRoaXMuZ2V0UHJpdmF0ZUJhc2VLZXlCNjQoKSkgKyBcIlxcblwiO1xuICBrZXkgKz0gXCItLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLVwiO1xuICByZXR1cm4ga2V5O1xufTtcblxuLyoqXG4gKiBSZXRyaWV2ZSB0aGUgcGVtIGVuY29kZWQgcHVibGljIGtleVxuICogQHJldHVybnMge3N0cmluZ30gdGhlIHBlbSBlbmNvZGVkIHB1YmxpYyBrZXkgd2l0aCBoZWFkZXIvZm9vdGVyXG4gKiBAcHVibGljXG4gKi9cblJTQUtleS5wcm90b3R5cGUuZ2V0UHVibGljS2V5ID0gZnVuY3Rpb24gKCkge1xuICB2YXIga2V5ID0gXCItLS0tLUJFR0lOIFBVQkxJQyBLRVktLS0tLVxcblwiO1xuICBrZXkgKz0gdGhpcy53b3Jkd3JhcCh0aGlzLmdldFB1YmxpY0Jhc2VLZXlCNjQoKSkgKyBcIlxcblwiO1xuICBrZXkgKz0gXCItLS0tLUVORCBQVUJMSUMgS0VZLS0tLS1cIjtcbiAgcmV0dXJuIGtleTtcbn07XG5cbi8qKlxuICogQ2hlY2sgaWYgdGhlIG9iamVjdCBjb250YWlucyB0aGUgbmVjZXNzYXJ5IHBhcmFtZXRlcnMgdG8gcG9wdWxhdGUgdGhlIHJzYSBtb2R1bHVzXG4gKiBhbmQgcHVibGljIGV4cG9uZW50IHBhcmFtZXRlcnMuXG4gKiBAcGFyYW0ge09iamVjdH0gW29iaj17fV0gLSBBbiBvYmplY3QgdGhhdCBtYXkgY29udGFpbiB0aGUgdHdvIHB1YmxpYyBrZXlcbiAqIHBhcmFtZXRlcnNcbiAqIEByZXR1cm5zIHtib29sZWFufSB0cnVlIGlmIHRoZSBvYmplY3QgY29udGFpbnMgYm90aCB0aGUgbW9kdWx1cyBhbmQgdGhlIHB1YmxpYyBleHBvbmVudFxuICogcHJvcGVydGllcyAobiBhbmQgZSlcbiAqIEB0b2RvIGNoZWNrIGZvciB0eXBlcyBvZiBuIGFuZCBlLiBOIHNob3VsZCBiZSBhIHBhcnNlYWJsZSBiaWdJbnQgb2JqZWN0LCBFIHNob3VsZFxuICogYmUgYSBwYXJzZWFibGUgaW50ZWdlciBudW1iZXJcbiAqIEBwcml2YXRlXG4gKi9cblJTQUtleS5wcm90b3R5cGUuaGFzUHVibGljS2V5UHJvcGVydHkgPSBmdW5jdGlvbiAob2JqKSB7XG4gIG9iaiA9IG9iaiB8fCB7fTtcbiAgcmV0dXJuIChcbiAgICBvYmouaGFzT3duUHJvcGVydHkoJ24nKSAmJlxuICAgIG9iai5oYXNPd25Qcm9wZXJ0eSgnZScpXG4gICk7XG59O1xuXG4vKipcbiAqIENoZWNrIGlmIHRoZSBvYmplY3QgY29udGFpbnMgQUxMIHRoZSBwYXJhbWV0ZXJzIG9mIGFuIFJTQSBrZXkuXG4gKiBAcGFyYW0ge09iamVjdH0gW29iaj17fV0gLSBBbiBvYmplY3QgdGhhdCBtYXkgY29udGFpbiBuaW5lIHJzYSBrZXlcbiAqIHBhcmFtZXRlcnNcbiAqIEByZXR1cm5zIHtib29sZWFufSB0cnVlIGlmIHRoZSBvYmplY3QgY29udGFpbnMgYWxsIHRoZSBwYXJhbWV0ZXJzIG5lZWRlZFxuICogQHRvZG8gY2hlY2sgZm9yIHR5cGVzIG9mIHRoZSBwYXJhbWV0ZXJzIGFsbCB0aGUgcGFyYW1ldGVycyBidXQgdGhlIHB1YmxpYyBleHBvbmVudFxuICogc2hvdWxkIGJlIHBhcnNlYWJsZSBiaWdpbnQgb2JqZWN0cywgdGhlIHB1YmxpYyBleHBvbmVudCBzaG91bGQgYmUgYSBwYXJzZWFibGUgaW50ZWdlciBudW1iZXJcbiAqIEBwcml2YXRlXG4gKi9cblJTQUtleS5wcm90b3R5cGUuaGFzUHJpdmF0ZUtleVByb3BlcnR5ID0gZnVuY3Rpb24gKG9iaikge1xuICBvYmogPSBvYmogfHwge307XG4gIHJldHVybiAoXG4gICAgb2JqLmhhc093blByb3BlcnR5KCduJykgJiZcbiAgICBvYmouaGFzT3duUHJvcGVydHkoJ2UnKSAmJlxuICAgIG9iai5oYXNPd25Qcm9wZXJ0eSgnZCcpICYmXG4gICAgb2JqLmhhc093blByb3BlcnR5KCdwJykgJiZcbiAgICBvYmouaGFzT3duUHJvcGVydHkoJ3EnKSAmJlxuICAgIG9iai5oYXNPd25Qcm9wZXJ0eSgnZG1wMScpICYmXG4gICAgb2JqLmhhc093blByb3BlcnR5KCdkbXExJykgJiZcbiAgICBvYmouaGFzT3duUHJvcGVydHkoJ2NvZWZmJylcbiAgKTtcbn07XG5cbi8qKlxuICogUGFyc2UgdGhlIHByb3BlcnRpZXMgb2Ygb2JqIGluIHRoZSBjdXJyZW50IHJzYSBvYmplY3QuIE9iaiBzaG91bGQgQVQgTEVBU1RcbiAqIGluY2x1ZGUgdGhlIG1vZHVsdXMgYW5kIHB1YmxpYyBleHBvbmVudCAobiwgZSkgcGFyYW1ldGVycy5cbiAqIEBwYXJhbSB7T2JqZWN0fSBvYmogLSB0aGUgb2JqZWN0IGNvbnRhaW5pbmcgcnNhIHBhcmFtZXRlcnNcbiAqIEBwcml2YXRlXG4gKi9cblJTQUtleS5wcm90b3R5cGUucGFyc2VQcm9wZXJ0aWVzRnJvbSA9IGZ1bmN0aW9uIChvYmopIHtcbiAgdGhpcy5uID0gb2JqLm47XG4gIHRoaXMuZSA9IG9iai5lO1xuXG4gIGlmIChvYmouaGFzT3duUHJvcGVydHkoJ2QnKSkge1xuICAgIHRoaXMuZCA9IG9iai5kO1xuICAgIHRoaXMucCA9IG9iai5wO1xuICAgIHRoaXMucSA9IG9iai5xO1xuICAgIHRoaXMuZG1wMSA9IG9iai5kbXAxO1xuICAgIHRoaXMuZG1xMSA9IG9iai5kbXExO1xuICAgIHRoaXMuY29lZmYgPSBvYmouY29lZmY7XG4gIH1cbn07XG5cbi8qKlxuICogQ3JlYXRlIGEgbmV3IEpTRW5jcnlwdFJTQUtleSB0aGF0IGV4dGVuZHMgVG9tIFd1J3MgUlNBIGtleSBvYmplY3QuXG4gKiBUaGlzIG9iamVjdCBpcyBqdXN0IGEgZGVjb3JhdG9yIGZvciBwYXJzaW5nIHRoZSBrZXkgcGFyYW1ldGVyXG4gKiBAcGFyYW0ge3N0cmluZ3xPYmplY3R9IGtleSAtIFRoZSBrZXkgaW4gc3RyaW5nIGZvcm1hdCwgb3IgYW4gb2JqZWN0IGNvbnRhaW5pbmdcbiAqIHRoZSBwYXJhbWV0ZXJzIG5lZWRlZCB0byBidWlsZCBhIFJTQUtleSBvYmplY3QuXG4gKiBAY29uc3RydWN0b3JcbiAqL1xudmFyIEpTRW5jcnlwdFJTQUtleSA9IGZ1bmN0aW9uIChrZXkpIHtcbiAgLy8gQ2FsbCB0aGUgc3VwZXIgY29uc3RydWN0b3IuXG4gIFJTQUtleS5jYWxsKHRoaXMpO1xuICAvLyBJZiBhIGtleSBrZXkgd2FzIHByb3ZpZGVkLlxuICBpZiAoa2V5KSB7XG4gICAgLy8gSWYgdGhpcyBpcyBhIHN0cmluZy4uLlxuICAgIGlmICh0eXBlb2Yga2V5ID09PSAnc3RyaW5nJykge1xuICAgICAgdGhpcy5wYXJzZUtleShrZXkpO1xuICAgIH1cbiAgICBlbHNlIGlmIChcbiAgICAgIHRoaXMuaGFzUHJpdmF0ZUtleVByb3BlcnR5KGtleSkgfHxcbiAgICAgIHRoaXMuaGFzUHVibGljS2V5UHJvcGVydHkoa2V5KVxuICAgICkge1xuICAgICAgLy8gU2V0IHRoZSB2YWx1ZXMgZm9yIHRoZSBrZXkuXG4gICAgICB0aGlzLnBhcnNlUHJvcGVydGllc0Zyb20oa2V5KTtcbiAgICB9XG4gIH1cbn07XG5cbi8vIERlcml2ZSBmcm9tIFJTQUtleS5cbkpTRW5jcnlwdFJTQUtleS5wcm90b3R5cGUgPSBuZXcgUlNBS2V5KCk7XG5cbi8vIFJlc2V0IHRoZSBjb250cnVjdG9yLlxuSlNFbmNyeXB0UlNBS2V5LnByb3RvdHlwZS5jb25zdHJ1Y3RvciA9IEpTRW5jcnlwdFJTQUtleTtcblxuXG4vKipcbiAqXG4gKiBAcGFyYW0ge09iamVjdH0gW29wdGlvbnMgPSB7fV0gLSBBbiBvYmplY3QgdG8gY3VzdG9taXplIEpTRW5jcnlwdCBiZWhhdmlvdXJcbiAqIHBvc3NpYmxlIHBhcmFtZXRlcnMgYXJlOlxuICogLSBkZWZhdWx0X2tleV9zaXplICAgICAgICB7bnVtYmVyfSAgZGVmYXVsdDogMTAyNCB0aGUga2V5IHNpemUgaW4gYml0XG4gKiAtIGRlZmF1bHRfcHVibGljX2V4cG9uZW50IHtzdHJpbmd9ICBkZWZhdWx0OiAnMDEwMDAxJyB0aGUgaGV4YWRlY2ltYWwgcmVwcmVzZW50YXRpb24gb2YgdGhlIHB1YmxpYyBleHBvbmVudFxuICogLSBsb2cgICAgICAgICAgICAgICAgICAgICB7Ym9vbGVhbn0gZGVmYXVsdDogZmFsc2Ugd2hldGhlciBsb2cgd2Fybi9lcnJvciBvciBub3RcbiAqIEBjb25zdHJ1Y3RvclxuICovXG52YXIgSlNFbmNyeXB0ID0gZnVuY3Rpb24gKG9wdGlvbnMpIHtcbiAgb3B0aW9ucyA9IG9wdGlvbnMgfHwge307XG4gIHRoaXMuZGVmYXVsdF9rZXlfc2l6ZSA9IHBhcnNlSW50KG9wdGlvbnMuZGVmYXVsdF9rZXlfc2l6ZSkgfHwgMTAyNDtcbiAgdGhpcy5kZWZhdWx0X3B1YmxpY19leHBvbmVudCA9IG9wdGlvbnMuZGVmYXVsdF9wdWJsaWNfZXhwb25lbnQgfHwgJzAxMDAwMSc7IC8vNjU1MzcgZGVmYXVsdCBvcGVuc3NsIHB1YmxpYyBleHBvbmVudCBmb3IgcnNhIGtleSB0eXBlXG4gIHRoaXMubG9nID0gb3B0aW9ucy5sb2cgfHwgZmFsc2U7XG4gIC8vIFRoZSBwcml2YXRlIGFuZCBwdWJsaWMga2V5LlxuICB0aGlzLmtleSA9IG51bGw7XG59O1xuXG4vKipcbiAqIE1ldGhvZCB0byBzZXQgdGhlIHJzYSBrZXkgcGFyYW1ldGVyIChvbmUgbWV0aG9kIGlzIGVub3VnaCB0byBzZXQgYm90aCB0aGUgcHVibGljXG4gKiBhbmQgdGhlIHByaXZhdGUga2V5LCBzaW5jZSB0aGUgcHJpdmF0ZSBrZXkgY29udGFpbnMgdGhlIHB1YmxpYyBrZXkgcGFyYW1lbnRlcnMpXG4gKiBMb2cgYSB3YXJuaW5nIGlmIGxvZ3MgYXJlIGVuYWJsZWRcbiAqIEBwYXJhbSB7T2JqZWN0fHN0cmluZ30ga2V5IHRoZSBwZW0gZW5jb2RlZCBzdHJpbmcgb3IgYW4gb2JqZWN0ICh3aXRoIG9yIHdpdGhvdXQgaGVhZGVyL2Zvb3RlcilcbiAqIEBwdWJsaWNcbiAqL1xuSlNFbmNyeXB0LnByb3RvdHlwZS5zZXRLZXkgPSBmdW5jdGlvbiAoa2V5KSB7XG4gIGlmICh0aGlzLmxvZyAmJiB0aGlzLmtleSkge1xuICAgIGNvbnNvbGUud2FybignQSBrZXkgd2FzIGFscmVhZHkgc2V0LCBvdmVycmlkaW5nIGV4aXN0aW5nLicpO1xuICB9XG4gIHRoaXMua2V5ID0gbmV3IEpTRW5jcnlwdFJTQUtleShrZXkpO1xufTtcblxuLyoqXG4gKiBQcm94eSBtZXRob2QgZm9yIHNldEtleSwgZm9yIGFwaSBjb21wYXRpYmlsaXR5XG4gKiBAc2VlIHNldEtleVxuICogQHB1YmxpY1xuICovXG5KU0VuY3J5cHQucHJvdG90eXBlLnNldFByaXZhdGVLZXkgPSBmdW5jdGlvbiAocHJpdmtleSkge1xuICAvLyBDcmVhdGUgdGhlIGtleS5cbiAgdGhpcy5zZXRLZXkocHJpdmtleSk7XG59O1xuXG4vKipcbiAqIFByb3h5IG1ldGhvZCBmb3Igc2V0S2V5LCBmb3IgYXBpIGNvbXBhdGliaWxpdHlcbiAqIEBzZWUgc2V0S2V5XG4gKiBAcHVibGljXG4gKi9cbkpTRW5jcnlwdC5wcm90b3R5cGUuc2V0UHVibGljS2V5ID0gZnVuY3Rpb24gKHB1YmtleSkge1xuICAvLyBTZXRzIHRoZSBwdWJsaWMga2V5LlxuICB0aGlzLnNldEtleShwdWJrZXkpO1xufTtcblxuLyoqXG4gKiBQcm94eSBtZXRob2QgZm9yIFJTQUtleSBvYmplY3QncyBkZWNyeXB0LCBkZWNyeXB0IHRoZSBzdHJpbmcgdXNpbmcgdGhlIHByaXZhdGVcbiAqIGNvbXBvbmVudHMgb2YgdGhlIHJzYSBrZXkgb2JqZWN0LiBOb3RlIHRoYXQgaWYgdGhlIG9iamVjdCB3YXMgbm90IHNldCB3aWxsIGJlIGNyZWF0ZWRcbiAqIG9uIHRoZSBmbHkgKGJ5IHRoZSBnZXRLZXkgbWV0aG9kKSB1c2luZyB0aGUgcGFyYW1ldGVycyBwYXNzZWQgaW4gdGhlIEpTRW5jcnlwdCBjb25zdHJ1Y3RvclxuICogQHBhcmFtIHtzdHJpbmd9IHN0cmluZyBiYXNlNjQgZW5jb2RlZCBjcnlwdGVkIHN0cmluZyB0byBkZWNyeXB0XG4gKiBAcmV0dXJuIHtzdHJpbmd9IHRoZSBkZWNyeXB0ZWQgc3RyaW5nXG4gKiBAcHVibGljXG4gKi9cbkpTRW5jcnlwdC5wcm90b3R5cGUuZGVjcnlwdCA9IGZ1bmN0aW9uIChzdHJpbmcpIHtcbiAgLy8gUmV0dXJuIHRoZSBkZWNyeXB0ZWQgc3RyaW5nLlxuICB0cnkge1xuICAgIHJldHVybiB0aGlzLmdldEtleSgpLmRlY3J5cHQoYjY0dG9oZXgoc3RyaW5nKSk7XG4gIH1cbiAgY2F0Y2ggKGV4KSB7XG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG59O1xuXG4vKipcbiAqIFByb3h5IG1ldGhvZCBmb3IgUlNBS2V5IG9iamVjdCdzIGVuY3J5cHQsIGVuY3J5cHQgdGhlIHN0cmluZyB1c2luZyB0aGUgcHVibGljXG4gKiBjb21wb25lbnRzIG9mIHRoZSByc2Ega2V5IG9iamVjdC4gTm90ZSB0aGF0IGlmIHRoZSBvYmplY3Qgd2FzIG5vdCBzZXQgd2lsbCBiZSBjcmVhdGVkXG4gKiBvbiB0aGUgZmx5IChieSB0aGUgZ2V0S2V5IG1ldGhvZCkgdXNpbmcgdGhlIHBhcmFtZXRlcnMgcGFzc2VkIGluIHRoZSBKU0VuY3J5cHQgY29uc3RydWN0b3JcbiAqIEBwYXJhbSB7c3RyaW5nfSBzdHJpbmcgdGhlIHN0cmluZyB0byBlbmNyeXB0XG4gKiBAcmV0dXJuIHtzdHJpbmd9IHRoZSBlbmNyeXB0ZWQgc3RyaW5nIGVuY29kZWQgaW4gYmFzZTY0XG4gKiBAcHVibGljXG4gKi9cbkpTRW5jcnlwdC5wcm90b3R5cGUuZW5jcnlwdCA9IGZ1bmN0aW9uIChzdHJpbmcpIHtcbiAgLy8gUmV0dXJuIHRoZSBlbmNyeXB0ZWQgc3RyaW5nLlxuICB0cnkge1xuICAgIHJldHVybiBoZXgyYjY0KHRoaXMuZ2V0S2V5KCkuZW5jcnlwdChzdHJpbmcpKTtcbiAgfVxuICBjYXRjaCAoZXgpIHtcbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cbn07XG5cbi8qKlxuICogR2V0dGVyIGZvciB0aGUgY3VycmVudCBKU0VuY3J5cHRSU0FLZXkgb2JqZWN0LiBJZiBpdCBkb2Vzbid0IGV4aXN0cyBhIG5ldyBvYmplY3RcbiAqIHdpbGwgYmUgY3JlYXRlZCBhbmQgcmV0dXJuZWRcbiAqIEBwYXJhbSB7Y2FsbGJhY2t9IFtjYl0gdGhlIGNhbGxiYWNrIHRvIGJlIGNhbGxlZCBpZiB3ZSB3YW50IHRoZSBrZXkgdG8gYmUgZ2VuZXJhdGVkXG4gKiBpbiBhbiBhc3luYyBmYXNoaW9uXG4gKiBAcmV0dXJucyB7SlNFbmNyeXB0UlNBS2V5fSB0aGUgSlNFbmNyeXB0UlNBS2V5IG9iamVjdFxuICogQHB1YmxpY1xuICovXG5KU0VuY3J5cHQucHJvdG90eXBlLmdldEtleSA9IGZ1bmN0aW9uIChjYikge1xuICAvLyBPbmx5IGNyZWF0ZSBuZXcgaWYgaXQgZG9lcyBub3QgZXhpc3QuXG4gIGlmICghdGhpcy5rZXkpIHtcbiAgICAvLyBHZXQgYSBuZXcgcHJpdmF0ZSBrZXkuXG4gICAgdGhpcy5rZXkgPSBuZXcgSlNFbmNyeXB0UlNBS2V5KCk7XG4gICAgaWYgKGNiICYmIHt9LnRvU3RyaW5nLmNhbGwoY2IpID09PSAnW29iamVjdCBGdW5jdGlvbl0nKSB7XG4gICAgICB0aGlzLmtleS5nZW5lcmF0ZUFzeW5jKHRoaXMuZGVmYXVsdF9rZXlfc2l6ZSwgdGhpcy5kZWZhdWx0X3B1YmxpY19leHBvbmVudCwgY2IpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICAvLyBHZW5lcmF0ZSB0aGUga2V5LlxuICAgIHRoaXMua2V5LmdlbmVyYXRlKHRoaXMuZGVmYXVsdF9rZXlfc2l6ZSwgdGhpcy5kZWZhdWx0X3B1YmxpY19leHBvbmVudCk7XG4gIH1cbiAgcmV0dXJuIHRoaXMua2V5O1xufTtcblxuLyoqXG4gKiBSZXR1cm5zIHRoZSBwZW0gZW5jb2RlZCByZXByZXNlbnRhdGlvbiBvZiB0aGUgcHJpdmF0ZSBrZXlcbiAqIElmIHRoZSBrZXkgZG9lc24ndCBleGlzdHMgYSBuZXcga2V5IHdpbGwgYmUgY3JlYXRlZFxuICogQHJldHVybnMge3N0cmluZ30gcGVtIGVuY29kZWQgcmVwcmVzZW50YXRpb24gb2YgdGhlIHByaXZhdGUga2V5IFdJVEggaGVhZGVyIGFuZCBmb290ZXJcbiAqIEBwdWJsaWNcbiAqL1xuSlNFbmNyeXB0LnByb3RvdHlwZS5nZXRQcml2YXRlS2V5ID0gZnVuY3Rpb24gKCkge1xuICAvLyBSZXR1cm4gdGhlIHByaXZhdGUgcmVwcmVzZW50YXRpb24gb2YgdGhpcyBrZXkuXG4gIHJldHVybiB0aGlzLmdldEtleSgpLmdldFByaXZhdGVLZXkoKTtcbn07XG5cbi8qKlxuICogUmV0dXJucyB0aGUgcGVtIGVuY29kZWQgcmVwcmVzZW50YXRpb24gb2YgdGhlIHByaXZhdGUga2V5XG4gKiBJZiB0aGUga2V5IGRvZXNuJ3QgZXhpc3RzIGEgbmV3IGtleSB3aWxsIGJlIGNyZWF0ZWRcbiAqIEByZXR1cm5zIHtzdHJpbmd9IHBlbSBlbmNvZGVkIHJlcHJlc2VudGF0aW9uIG9mIHRoZSBwcml2YXRlIGtleSBXSVRIT1VUIGhlYWRlciBhbmQgZm9vdGVyXG4gKiBAcHVibGljXG4gKi9cbkpTRW5jcnlwdC5wcm90b3R5cGUuZ2V0UHJpdmF0ZUtleUI2NCA9IGZ1bmN0aW9uICgpIHtcbiAgLy8gUmV0dXJuIHRoZSBwcml2YXRlIHJlcHJlc2VudGF0aW9uIG9mIHRoaXMga2V5LlxuICByZXR1cm4gdGhpcy5nZXRLZXkoKS5nZXRQcml2YXRlQmFzZUtleUI2NCgpO1xufTtcblxuXG4vKipcbiAqIFJldHVybnMgdGhlIHBlbSBlbmNvZGVkIHJlcHJlc2VudGF0aW9uIG9mIHRoZSBwdWJsaWMga2V5XG4gKiBJZiB0aGUga2V5IGRvZXNuJ3QgZXhpc3RzIGEgbmV3IGtleSB3aWxsIGJlIGNyZWF0ZWRcbiAqIEByZXR1cm5zIHtzdHJpbmd9IHBlbSBlbmNvZGVkIHJlcHJlc2VudGF0aW9uIG9mIHRoZSBwdWJsaWMga2V5IFdJVEggaGVhZGVyIGFuZCBmb290ZXJcbiAqIEBwdWJsaWNcbiAqL1xuSlNFbmNyeXB0LnByb3RvdHlwZS5nZXRQdWJsaWNLZXkgPSBmdW5jdGlvbiAoKSB7XG4gIC8vIFJldHVybiB0aGUgcHJpdmF0ZSByZXByZXNlbnRhdGlvbiBvZiB0aGlzIGtleS5cbiAgcmV0dXJuIHRoaXMuZ2V0S2V5KCkuZ2V0UHVibGljS2V5KCk7XG59O1xuXG4vKipcbiAqIFJldHVybnMgdGhlIHBlbSBlbmNvZGVkIHJlcHJlc2VudGF0aW9uIG9mIHRoZSBwdWJsaWMga2V5XG4gKiBJZiB0aGUga2V5IGRvZXNuJ3QgZXhpc3RzIGEgbmV3IGtleSB3aWxsIGJlIGNyZWF0ZWRcbiAqIEByZXR1cm5zIHtzdHJpbmd9IHBlbSBlbmNvZGVkIHJlcHJlc2VudGF0aW9uIG9mIHRoZSBwdWJsaWMga2V5IFdJVEhPVVQgaGVhZGVyIGFuZCBmb290ZXJcbiAqIEBwdWJsaWNcbiAqL1xuSlNFbmNyeXB0LnByb3RvdHlwZS5nZXRQdWJsaWNLZXlCNjQgPSBmdW5jdGlvbiAoKSB7XG4gIC8vIFJldHVybiB0aGUgcHJpdmF0ZSByZXByZXNlbnRhdGlvbiBvZiB0aGlzIGtleS5cbiAgcmV0dXJuIHRoaXMuZ2V0S2V5KCkuZ2V0UHVibGljQmFzZUtleUI2NCgpO1xufTtcblxuXG4gIEpTRW5jcnlwdC52ZXJzaW9uID0gJzIuMy4xJztcbiAgZXhwb3J0cy5KU0VuY3J5cHQgPSBKU0VuY3J5cHQ7XG59KTsiXX0=
