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
              MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAshErgcyhp4w9ih+WmBIV\
              Adqk9uHN0xSANpdb8QJWMYzqPptgbdjWRJsV7lR7h6nCSICcZLjT8BNd50Xen8/G\
              XJZoZERSeEASjTRzMF9DIXbLM+9mc4EuDdwFJUMbICrtWRB8zvaWMP3Sl436hquN\
              T5ZjnC7Kiz8uoCMkFThLIBpH9IP6USJuw/ikAFXoXwXPZJSTIfb2REIKpfqq4zAZ\
              tkmH+NNT+qokhSmsQmIdkdEH64svdR1eV7ggcaOFIbFSmHSRy3Ck/41upJt5d58Q\
              Wdfe25kUhCm0kljoVhexUYNKeoiTrLn/XvABmkJt4C0VGO3WqMtYocehcBSg4yEO\
              bQIDAQAB\
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJkZXYvanMvYXBwbGljYXRpb24uanMiLCJkZXYvanMvY29uc3RhbnRzLmpzIiwibm9kZV9tb2R1bGVzL2pzZW5jcnlwdC9iaW4vanNlbmNyeXB0LmpzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBO0FDQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDNURBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDdEJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBIiwiZmlsZSI6ImdlbmVyYXRlZC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzQ29udGVudCI6WyIoZnVuY3Rpb24gZSh0LG4scil7ZnVuY3Rpb24gcyhvLHUpe2lmKCFuW29dKXtpZighdFtvXSl7dmFyIGE9dHlwZW9mIHJlcXVpcmU9PVwiZnVuY3Rpb25cIiYmcmVxdWlyZTtpZighdSYmYSlyZXR1cm4gYShvLCEwKTtpZihpKXJldHVybiBpKG8sITApO3ZhciBmPW5ldyBFcnJvcihcIkNhbm5vdCBmaW5kIG1vZHVsZSAnXCIrbytcIidcIik7dGhyb3cgZi5jb2RlPVwiTU9EVUxFX05PVF9GT1VORFwiLGZ9dmFyIGw9bltvXT17ZXhwb3J0czp7fX07dFtvXVswXS5jYWxsKGwuZXhwb3J0cyxmdW5jdGlvbihlKXt2YXIgbj10W29dWzFdW2VdO3JldHVybiBzKG4/bjplKX0sbCxsLmV4cG9ydHMsZSx0LG4scil9cmV0dXJuIG5bb10uZXhwb3J0c312YXIgaT10eXBlb2YgcmVxdWlyZT09XCJmdW5jdGlvblwiJiZyZXF1aXJlO2Zvcih2YXIgbz0wO288ci5sZW5ndGg7bysrKXMocltvXSk7cmV0dXJuIHN9KSIsIi8qanNoaW50IG11bHRpc3RyOiB0cnVlICovXHJcbkpTRW5jcnlwdCA9IHJlcXVpcmUoJ2pzZW5jcnlwdCcpLkpTRW5jcnlwdDtcclxuQ29uc3RhbnRzID0gcmVxdWlyZSgnLi9jb25zdGFudHMnKTtcclxuXHJcbmZ1bmN0aW9uIGVuY3J5cHRLZXlWYWx1ZVBhaXIocGFpcil7XHJcbiAgdmFyIGNyeXB0ID0gbmV3IEpTRW5jcnlwdCgpO1xyXG4gIGNyeXB0LnNldFB1YmxpY0tleShDb25zdGFudHMucHVibGljX2tleSk7XHJcbiAgZW5jcnlwdGVkX3BhaXIgPSB7XHJcbiAgICBrZXk6IGNyeXB0LmVuY3J5cHQocGFpci5rZXkpLFxyXG4gICAgdmFsdWU6IGNyeXB0LmVuY3J5cHQocGFpci52YWx1ZSlcclxuICB9O1xyXG4gIHJldHVybiBlbmNyeXB0ZWRfcGFpcjtcclxufVxyXG5cclxuZnVuY3Rpb24gc3VibWl0S2V5VmFsdWVQYWlyKGV2ZW50KSB7XHJcbiAgZXZlbnQucHJldmVudERlZmF1bHQoKTtcclxuICBrZXlfZWxlbWVudCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwia2V5XCIpO1xyXG4gIHZhbHVlX2VsZW1lbnQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcInZhbHVlXCIpO1xyXG5cclxuICBpZiAodmFsdWVfZWxlbWVudC52YWx1ZSA9PSBcIlwiKXtcclxuICAgIHZhbHVlX2VsZW1lbnQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcInZhbHVlX3NlbGVjdFwiKTtcclxuICB9XHJcblxyXG4gIHZhciBwYWlyID0ge1xyXG4gICAga2V5IDoga2V5X2VsZW1lbnQudmFsdWUsXHJcbiAgICB2YWx1ZSA6IHZhbHVlX2VsZW1lbnQudmFsdWVcclxuICB9O1xyXG5cclxuICB2YXIgZW5jcnlwdGVkX3BhaXIgPSBlbmNyeXB0S2V5VmFsdWVQYWlyKHBhaXIpO1xyXG5cclxuICBzZW5kKGVuY3J5cHRlZF9wYWlyKTtcclxufVxyXG5cclxuZnVuY3Rpb24gc2VuZChlbmNyeXB0ZWRfcGFpcikge1xyXG4gIHZhciB4aHR0cCA9IG5ldyBYTUxIdHRwUmVxdWVzdCgpO1xyXG4gIHhodHRwLm9ucmVhZHlzdGF0ZWNoYW5nZSA9IGZ1bmN0aW9uKCkge1xyXG4gICAgaWYgKHhodHRwLnJlYWR5U3RhdGUgPT0gNCAmJiB4aHR0cC5zdGF0dXMgPT0gMjAwKSB7XHJcbiAgICAgYWxlcnQoJ1NlbnQgc3VjY2Vzc2Z1bGx5Jyk7XHJcbiAgICB9XHJcbiAgfTtcclxuICB4aHR0cC5vcGVuKFwiUE9TVFwiLCBcIndyaXRlXCIsIHRydWUpO1xyXG4gIHhodHRwLnNldFJlcXVlc3RIZWFkZXIoXCJDb250ZW50LVR5cGVcIiwgXCJhcHBsaWNhdGlvbi9qc29uO2NoYXJzZXQ9VVRGLThcIik7XHJcbiAgeGh0dHAuc2VuZChKU09OLnN0cmluZ2lmeShlbmNyeXB0ZWRfcGFpcikpO1xyXG59XHJcblxyXG53aW5kb3cub25sb2FkID0gZnVuY3Rpb24oKXtcclxuICB2YXIgZm9ybSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwiZm9ybVwiKTtcclxuICBmb3JtLmFkZEV2ZW50TGlzdGVuZXIoJ3N1Ym1pdCcsIHN1Ym1pdEtleVZhbHVlUGFpcik7XHJcbiAgdmFyIGZvcm0gPSBmb3JtLmFwcGVuZENoaWxkKGNyZWF0ZVNlbGVjdCgpKTtcclxufTtcclxuXHJcbmZ1bmN0aW9uIGNyZWF0ZVNlbGVjdCgpe1xyXG4gIHZhciBzZWxlY3QgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KFwic2VsZWN0XCIpO1xyXG4gIHNlbGVjdC5pZCA9IFwidmFsdWVfc2VsZWN0XCI7XHJcbiAgQ29uc3RhbnRzLnZhbHVlX29wdGlvbnMuZm9yRWFjaChmdW5jdGlvbihlbGVtZW50KXtcclxuICAgIHZhciBvcHRpb24gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KFwib3B0aW9uXCIpO1xyXG4gICAgb3B0aW9uLnRleHQgPSBlbGVtZW50O1xyXG4gICAgc2VsZWN0LmFkZChvcHRpb24pO1xyXG4gIH0pXHJcbiAgcmV0dXJuIHNlbGVjdDtcclxufSIsIi8qanNoaW50IG11bHRpc3RyOiB0cnVlICovXHJcblxyXG5tb2R1bGUuZXhwb3J0cyA9IHtcclxuICBwdWJsaWNfa2V5OiBcIi0tLS0tQkVHSU4gUFVCTElDIEtFWS0tLS0tXFxcclxuICAgICAgICAgICAgICBNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXNoRXJnY3locDR3OWloK1dtQklWXFxcclxuICAgICAgICAgICAgICBBZHFrOXVITjB4U0FOcGRiOFFKV01ZenFQcHRnYmRqV1JKc1Y3bFI3aDZuQ1NJQ2NaTGpUOEJOZDUwWGVuOC9HXFxcclxuICAgICAgICAgICAgICBYSlpvWkVSU2VFQVNqVFJ6TUY5RElYYkxNKzltYzRFdURkd0ZKVU1iSUNydFdSQjh6dmFXTVAzU2w0MzZocXVOXFxcclxuICAgICAgICAgICAgICBUNVpqbkM3S2l6OHVvQ01rRlRoTElCcEg5SVA2VVNKdXcvaWtBRlhvWHdYUFpKU1RJZmIyUkVJS3BmcXE0ekFaXFxcclxuICAgICAgICAgICAgICB0a21IK05OVCtxb2toU21zUW1JZGtkRUg2NHN2ZFIxZVY3Z2djYU9GSWJGU21IU1J5M0NrLzQxdXBKdDVkNThRXFxcclxuICAgICAgICAgICAgICBXZGZlMjVrVWhDbTBrbGpvVmhleFVZTktlb2lUckxuL1h2QUJta0p0NEMwVkdPM1dxTXRZb2NlaGNCU2c0eUVPXFxcclxuICAgICAgICAgICAgICBiUUlEQVFBQlxcXHJcbiAgICAgICAgICAgICAgLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tXCIsXHJcbiAgdmFsdWVfb3B0aW9uczogW1xyXG4gICAgMTAxLFxyXG4gICAgMjAxLFxyXG4gICAgMjA1LFxyXG4gICAgMzAxLFxyXG4gICAgNDAxLFxyXG4gICAgNjAxLFxyXG4gICAgNjAyXHJcbiAgXVxyXG59O1xyXG4iLCIvKiEgSlNFbmNyeXB0IHYyLjMuMSB8IGh0dHBzOi8vbnBtY2RuLmNvbS9qc2VuY3J5cHRAMi4zLjEvTElDRU5TRS50eHQgKi9cbihmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSkge1xuICBpZiAodHlwZW9mIGRlZmluZSA9PT0gJ2Z1bmN0aW9uJyAmJiBkZWZpbmUuYW1kKSB7XG4gICAgLy8gQU1EXG4gICAgZGVmaW5lKFsnZXhwb3J0cyddLCBmYWN0b3J5KTtcbiAgfSBlbHNlIGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gJ29iamVjdCcgJiYgdHlwZW9mIGV4cG9ydHMubm9kZU5hbWUgIT09ICdzdHJpbmcnKSB7XG4gICAgLy8gTm9kZSwgQ29tbW9uSlMtbGlrZVxuICAgIGZhY3RvcnkobW9kdWxlLmV4cG9ydHMpO1xuICB9IGVsc2Uge1xuICAgIGZhY3Rvcnkocm9vdCk7XG4gIH1cbn0pKHRoaXMsIGZ1bmN0aW9uIChleHBvcnRzKSB7XG4gIC8vIENvcHlyaWdodCAoYykgMjAwNSAgVG9tIFd1XG4vLyBBbGwgUmlnaHRzIFJlc2VydmVkLlxuLy8gU2VlIFwiTElDRU5TRVwiIGZvciBkZXRhaWxzLlxuXG4vLyBCYXNpYyBKYXZhU2NyaXB0IEJOIGxpYnJhcnkgLSBzdWJzZXQgdXNlZnVsIGZvciBSU0EgZW5jcnlwdGlvbi5cblxuLy8gQml0cyBwZXIgZGlnaXRcbnZhciBkYml0cztcblxuLy8gSmF2YVNjcmlwdCBlbmdpbmUgYW5hbHlzaXNcbnZhciBjYW5hcnkgPSAweGRlYWRiZWVmY2FmZTtcbnZhciBqX2xtID0gKChjYW5hcnkmMHhmZmZmZmYpPT0weGVmY2FmZSk7XG5cbi8vIChwdWJsaWMpIENvbnN0cnVjdG9yXG5mdW5jdGlvbiBCaWdJbnRlZ2VyKGEsYixjKSB7XG4gIGlmKGEgIT0gbnVsbClcbiAgICBpZihcIm51bWJlclwiID09IHR5cGVvZiBhKSB0aGlzLmZyb21OdW1iZXIoYSxiLGMpO1xuICAgIGVsc2UgaWYoYiA9PSBudWxsICYmIFwic3RyaW5nXCIgIT0gdHlwZW9mIGEpIHRoaXMuZnJvbVN0cmluZyhhLDI1Nik7XG4gICAgZWxzZSB0aGlzLmZyb21TdHJpbmcoYSxiKTtcbn1cblxuLy8gcmV0dXJuIG5ldywgdW5zZXQgQmlnSW50ZWdlclxuZnVuY3Rpb24gbmJpKCkgeyByZXR1cm4gbmV3IEJpZ0ludGVnZXIobnVsbCk7IH1cblxuLy8gYW06IENvbXB1dGUgd19qICs9ICh4KnRoaXNfaSksIHByb3BhZ2F0ZSBjYXJyaWVzLFxuLy8gYyBpcyBpbml0aWFsIGNhcnJ5LCByZXR1cm5zIGZpbmFsIGNhcnJ5LlxuLy8gYyA8IDMqZHZhbHVlLCB4IDwgMipkdmFsdWUsIHRoaXNfaSA8IGR2YWx1ZVxuLy8gV2UgbmVlZCB0byBzZWxlY3QgdGhlIGZhc3Rlc3Qgb25lIHRoYXQgd29ya3MgaW4gdGhpcyBlbnZpcm9ubWVudC5cblxuLy8gYW0xOiB1c2UgYSBzaW5nbGUgbXVsdCBhbmQgZGl2aWRlIHRvIGdldCB0aGUgaGlnaCBiaXRzLFxuLy8gbWF4IGRpZ2l0IGJpdHMgc2hvdWxkIGJlIDI2IGJlY2F1c2Vcbi8vIG1heCBpbnRlcm5hbCB2YWx1ZSA9IDIqZHZhbHVlXjItMipkdmFsdWUgKDwgMl41MylcbmZ1bmN0aW9uIGFtMShpLHgsdyxqLGMsbikge1xuICB3aGlsZSgtLW4gPj0gMCkge1xuICAgIHZhciB2ID0geCp0aGlzW2krK10rd1tqXStjO1xuICAgIGMgPSBNYXRoLmZsb29yKHYvMHg0MDAwMDAwKTtcbiAgICB3W2orK10gPSB2JjB4M2ZmZmZmZjtcbiAgfVxuICByZXR1cm4gYztcbn1cbi8vIGFtMiBhdm9pZHMgYSBiaWcgbXVsdC1hbmQtZXh0cmFjdCBjb21wbGV0ZWx5LlxuLy8gTWF4IGRpZ2l0IGJpdHMgc2hvdWxkIGJlIDw9IDMwIGJlY2F1c2Ugd2UgZG8gYml0d2lzZSBvcHNcbi8vIG9uIHZhbHVlcyB1cCB0byAyKmhkdmFsdWVeMi1oZHZhbHVlLTEgKDwgMl4zMSlcbmZ1bmN0aW9uIGFtMihpLHgsdyxqLGMsbikge1xuICB2YXIgeGwgPSB4JjB4N2ZmZiwgeGggPSB4Pj4xNTtcbiAgd2hpbGUoLS1uID49IDApIHtcbiAgICB2YXIgbCA9IHRoaXNbaV0mMHg3ZmZmO1xuICAgIHZhciBoID0gdGhpc1tpKytdPj4xNTtcbiAgICB2YXIgbSA9IHhoKmwraCp4bDtcbiAgICBsID0geGwqbCsoKG0mMHg3ZmZmKTw8MTUpK3dbal0rKGMmMHgzZmZmZmZmZik7XG4gICAgYyA9IChsPj4+MzApKyhtPj4+MTUpK3hoKmgrKGM+Pj4zMCk7XG4gICAgd1tqKytdID0gbCYweDNmZmZmZmZmO1xuICB9XG4gIHJldHVybiBjO1xufVxuLy8gQWx0ZXJuYXRlbHksIHNldCBtYXggZGlnaXQgYml0cyB0byAyOCBzaW5jZSBzb21lXG4vLyBicm93c2VycyBzbG93IGRvd24gd2hlbiBkZWFsaW5nIHdpdGggMzItYml0IG51bWJlcnMuXG5mdW5jdGlvbiBhbTMoaSx4LHcsaixjLG4pIHtcbiAgdmFyIHhsID0geCYweDNmZmYsIHhoID0geD4+MTQ7XG4gIHdoaWxlKC0tbiA+PSAwKSB7XG4gICAgdmFyIGwgPSB0aGlzW2ldJjB4M2ZmZjtcbiAgICB2YXIgaCA9IHRoaXNbaSsrXT4+MTQ7XG4gICAgdmFyIG0gPSB4aCpsK2gqeGw7XG4gICAgbCA9IHhsKmwrKChtJjB4M2ZmZik8PDE0KSt3W2pdK2M7XG4gICAgYyA9IChsPj4yOCkrKG0+PjE0KSt4aCpoO1xuICAgIHdbaisrXSA9IGwmMHhmZmZmZmZmO1xuICB9XG4gIHJldHVybiBjO1xufVxuaWYoal9sbSAmJiAobmF2aWdhdG9yLmFwcE5hbWUgPT0gXCJNaWNyb3NvZnQgSW50ZXJuZXQgRXhwbG9yZXJcIikpIHtcbiAgQmlnSW50ZWdlci5wcm90b3R5cGUuYW0gPSBhbTI7XG4gIGRiaXRzID0gMzA7XG59XG5lbHNlIGlmKGpfbG0gJiYgKG5hdmlnYXRvci5hcHBOYW1lICE9IFwiTmV0c2NhcGVcIikpIHtcbiAgQmlnSW50ZWdlci5wcm90b3R5cGUuYW0gPSBhbTE7XG4gIGRiaXRzID0gMjY7XG59XG5lbHNlIHsgLy8gTW96aWxsYS9OZXRzY2FwZSBzZWVtcyB0byBwcmVmZXIgYW0zXG4gIEJpZ0ludGVnZXIucHJvdG90eXBlLmFtID0gYW0zO1xuICBkYml0cyA9IDI4O1xufVxuXG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5EQiA9IGRiaXRzO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuRE0gPSAoKDE8PGRiaXRzKS0xKTtcbkJpZ0ludGVnZXIucHJvdG90eXBlLkRWID0gKDE8PGRiaXRzKTtcblxudmFyIEJJX0ZQID0gNTI7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5GViA9IE1hdGgucG93KDIsQklfRlApO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuRjEgPSBCSV9GUC1kYml0cztcbkJpZ0ludGVnZXIucHJvdG90eXBlLkYyID0gMipkYml0cy1CSV9GUDtcblxuLy8gRGlnaXQgY29udmVyc2lvbnNcbnZhciBCSV9STSA9IFwiMDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6XCI7XG52YXIgQklfUkMgPSBuZXcgQXJyYXkoKTtcbnZhciBycix2djtcbnJyID0gXCIwXCIuY2hhckNvZGVBdCgwKTtcbmZvcih2diA9IDA7IHZ2IDw9IDk7ICsrdnYpIEJJX1JDW3JyKytdID0gdnY7XG5yciA9IFwiYVwiLmNoYXJDb2RlQXQoMCk7XG5mb3IodnYgPSAxMDsgdnYgPCAzNjsgKyt2dikgQklfUkNbcnIrK10gPSB2djtcbnJyID0gXCJBXCIuY2hhckNvZGVBdCgwKTtcbmZvcih2diA9IDEwOyB2diA8IDM2OyArK3Z2KSBCSV9SQ1tycisrXSA9IHZ2O1xuXG5mdW5jdGlvbiBpbnQyY2hhcihuKSB7IHJldHVybiBCSV9STS5jaGFyQXQobik7IH1cbmZ1bmN0aW9uIGludEF0KHMsaSkge1xuICB2YXIgYyA9IEJJX1JDW3MuY2hhckNvZGVBdChpKV07XG4gIHJldHVybiAoYz09bnVsbCk/LTE6Yztcbn1cblxuLy8gKHByb3RlY3RlZCkgY29weSB0aGlzIHRvIHJcbmZ1bmN0aW9uIGJucENvcHlUbyhyKSB7XG4gIGZvcih2YXIgaSA9IHRoaXMudC0xOyBpID49IDA7IC0taSkgcltpXSA9IHRoaXNbaV07XG4gIHIudCA9IHRoaXMudDtcbiAgci5zID0gdGhpcy5zO1xufVxuXG4vLyAocHJvdGVjdGVkKSBzZXQgZnJvbSBpbnRlZ2VyIHZhbHVlIHgsIC1EViA8PSB4IDwgRFZcbmZ1bmN0aW9uIGJucEZyb21JbnQoeCkge1xuICB0aGlzLnQgPSAxO1xuICB0aGlzLnMgPSAoeDwwKT8tMTowO1xuICBpZih4ID4gMCkgdGhpc1swXSA9IHg7XG4gIGVsc2UgaWYoeCA8IC0xKSB0aGlzWzBdID0geCt0aGlzLkRWO1xuICBlbHNlIHRoaXMudCA9IDA7XG59XG5cbi8vIHJldHVybiBiaWdpbnQgaW5pdGlhbGl6ZWQgdG8gdmFsdWVcbmZ1bmN0aW9uIG5idihpKSB7IHZhciByID0gbmJpKCk7IHIuZnJvbUludChpKTsgcmV0dXJuIHI7IH1cblxuLy8gKHByb3RlY3RlZCkgc2V0IGZyb20gc3RyaW5nIGFuZCByYWRpeFxuZnVuY3Rpb24gYm5wRnJvbVN0cmluZyhzLGIpIHtcbiAgdmFyIGs7XG4gIGlmKGIgPT0gMTYpIGsgPSA0O1xuICBlbHNlIGlmKGIgPT0gOCkgayA9IDM7XG4gIGVsc2UgaWYoYiA9PSAyNTYpIGsgPSA4OyAvLyBieXRlIGFycmF5XG4gIGVsc2UgaWYoYiA9PSAyKSBrID0gMTtcbiAgZWxzZSBpZihiID09IDMyKSBrID0gNTtcbiAgZWxzZSBpZihiID09IDQpIGsgPSAyO1xuICBlbHNlIHsgdGhpcy5mcm9tUmFkaXgocyxiKTsgcmV0dXJuOyB9XG4gIHRoaXMudCA9IDA7XG4gIHRoaXMucyA9IDA7XG4gIHZhciBpID0gcy5sZW5ndGgsIG1pID0gZmFsc2UsIHNoID0gMDtcbiAgd2hpbGUoLS1pID49IDApIHtcbiAgICB2YXIgeCA9IChrPT04KT9zW2ldJjB4ZmY6aW50QXQocyxpKTtcbiAgICBpZih4IDwgMCkge1xuICAgICAgaWYocy5jaGFyQXQoaSkgPT0gXCItXCIpIG1pID0gdHJ1ZTtcbiAgICAgIGNvbnRpbnVlO1xuICAgIH1cbiAgICBtaSA9IGZhbHNlO1xuICAgIGlmKHNoID09IDApXG4gICAgICB0aGlzW3RoaXMudCsrXSA9IHg7XG4gICAgZWxzZSBpZihzaCtrID4gdGhpcy5EQikge1xuICAgICAgdGhpc1t0aGlzLnQtMV0gfD0gKHgmKCgxPDwodGhpcy5EQi1zaCkpLTEpKTw8c2g7XG4gICAgICB0aGlzW3RoaXMudCsrXSA9ICh4Pj4odGhpcy5EQi1zaCkpO1xuICAgIH1cbiAgICBlbHNlXG4gICAgICB0aGlzW3RoaXMudC0xXSB8PSB4PDxzaDtcbiAgICBzaCArPSBrO1xuICAgIGlmKHNoID49IHRoaXMuREIpIHNoIC09IHRoaXMuREI7XG4gIH1cbiAgaWYoayA9PSA4ICYmIChzWzBdJjB4ODApICE9IDApIHtcbiAgICB0aGlzLnMgPSAtMTtcbiAgICBpZihzaCA+IDApIHRoaXNbdGhpcy50LTFdIHw9ICgoMTw8KHRoaXMuREItc2gpKS0xKTw8c2g7XG4gIH1cbiAgdGhpcy5jbGFtcCgpO1xuICBpZihtaSkgQmlnSW50ZWdlci5aRVJPLnN1YlRvKHRoaXMsdGhpcyk7XG59XG5cbi8vIChwcm90ZWN0ZWQpIGNsYW1wIG9mZiBleGNlc3MgaGlnaCB3b3Jkc1xuZnVuY3Rpb24gYm5wQ2xhbXAoKSB7XG4gIHZhciBjID0gdGhpcy5zJnRoaXMuRE07XG4gIHdoaWxlKHRoaXMudCA+IDAgJiYgdGhpc1t0aGlzLnQtMV0gPT0gYykgLS10aGlzLnQ7XG59XG5cbi8vIChwdWJsaWMpIHJldHVybiBzdHJpbmcgcmVwcmVzZW50YXRpb24gaW4gZ2l2ZW4gcmFkaXhcbmZ1bmN0aW9uIGJuVG9TdHJpbmcoYikge1xuICBpZih0aGlzLnMgPCAwKSByZXR1cm4gXCItXCIrdGhpcy5uZWdhdGUoKS50b1N0cmluZyhiKTtcbiAgdmFyIGs7XG4gIGlmKGIgPT0gMTYpIGsgPSA0O1xuICBlbHNlIGlmKGIgPT0gOCkgayA9IDM7XG4gIGVsc2UgaWYoYiA9PSAyKSBrID0gMTtcbiAgZWxzZSBpZihiID09IDMyKSBrID0gNTtcbiAgZWxzZSBpZihiID09IDQpIGsgPSAyO1xuICBlbHNlIHJldHVybiB0aGlzLnRvUmFkaXgoYik7XG4gIHZhciBrbSA9ICgxPDxrKS0xLCBkLCBtID0gZmFsc2UsIHIgPSBcIlwiLCBpID0gdGhpcy50O1xuICB2YXIgcCA9IHRoaXMuREItKGkqdGhpcy5EQiklaztcbiAgaWYoaS0tID4gMCkge1xuICAgIGlmKHAgPCB0aGlzLkRCICYmIChkID0gdGhpc1tpXT4+cCkgPiAwKSB7IG0gPSB0cnVlOyByID0gaW50MmNoYXIoZCk7IH1cbiAgICB3aGlsZShpID49IDApIHtcbiAgICAgIGlmKHAgPCBrKSB7XG4gICAgICAgIGQgPSAodGhpc1tpXSYoKDE8PHApLTEpKTw8KGstcCk7XG4gICAgICAgIGQgfD0gdGhpc1stLWldPj4ocCs9dGhpcy5EQi1rKTtcbiAgICAgIH1cbiAgICAgIGVsc2Uge1xuICAgICAgICBkID0gKHRoaXNbaV0+PihwLT1rKSkma207XG4gICAgICAgIGlmKHAgPD0gMCkgeyBwICs9IHRoaXMuREI7IC0taTsgfVxuICAgICAgfVxuICAgICAgaWYoZCA+IDApIG0gPSB0cnVlO1xuICAgICAgaWYobSkgciArPSBpbnQyY2hhcihkKTtcbiAgICB9XG4gIH1cbiAgcmV0dXJuIG0/cjpcIjBcIjtcbn1cblxuLy8gKHB1YmxpYykgLXRoaXNcbmZ1bmN0aW9uIGJuTmVnYXRlKCkgeyB2YXIgciA9IG5iaSgpOyBCaWdJbnRlZ2VyLlpFUk8uc3ViVG8odGhpcyxyKTsgcmV0dXJuIHI7IH1cblxuLy8gKHB1YmxpYykgfHRoaXN8XG5mdW5jdGlvbiBibkFicygpIHsgcmV0dXJuICh0aGlzLnM8MCk/dGhpcy5uZWdhdGUoKTp0aGlzOyB9XG5cbi8vIChwdWJsaWMpIHJldHVybiArIGlmIHRoaXMgPiBhLCAtIGlmIHRoaXMgPCBhLCAwIGlmIGVxdWFsXG5mdW5jdGlvbiBibkNvbXBhcmVUbyhhKSB7XG4gIHZhciByID0gdGhpcy5zLWEucztcbiAgaWYociAhPSAwKSByZXR1cm4gcjtcbiAgdmFyIGkgPSB0aGlzLnQ7XG4gIHIgPSBpLWEudDtcbiAgaWYociAhPSAwKSByZXR1cm4gKHRoaXMuczwwKT8tcjpyO1xuICB3aGlsZSgtLWkgPj0gMCkgaWYoKHI9dGhpc1tpXS1hW2ldKSAhPSAwKSByZXR1cm4gcjtcbiAgcmV0dXJuIDA7XG59XG5cbi8vIHJldHVybnMgYml0IGxlbmd0aCBvZiB0aGUgaW50ZWdlciB4XG5mdW5jdGlvbiBuYml0cyh4KSB7XG4gIHZhciByID0gMSwgdDtcbiAgaWYoKHQ9eD4+PjE2KSAhPSAwKSB7IHggPSB0OyByICs9IDE2OyB9XG4gIGlmKCh0PXg+PjgpICE9IDApIHsgeCA9IHQ7IHIgKz0gODsgfVxuICBpZigodD14Pj40KSAhPSAwKSB7IHggPSB0OyByICs9IDQ7IH1cbiAgaWYoKHQ9eD4+MikgIT0gMCkgeyB4ID0gdDsgciArPSAyOyB9XG4gIGlmKCh0PXg+PjEpICE9IDApIHsgeCA9IHQ7IHIgKz0gMTsgfVxuICByZXR1cm4gcjtcbn1cblxuLy8gKHB1YmxpYykgcmV0dXJuIHRoZSBudW1iZXIgb2YgYml0cyBpbiBcInRoaXNcIlxuZnVuY3Rpb24gYm5CaXRMZW5ndGgoKSB7XG4gIGlmKHRoaXMudCA8PSAwKSByZXR1cm4gMDtcbiAgcmV0dXJuIHRoaXMuREIqKHRoaXMudC0xKStuYml0cyh0aGlzW3RoaXMudC0xXV4odGhpcy5zJnRoaXMuRE0pKTtcbn1cblxuLy8gKHByb3RlY3RlZCkgciA9IHRoaXMgPDwgbipEQlxuZnVuY3Rpb24gYm5wRExTaGlmdFRvKG4scikge1xuICB2YXIgaTtcbiAgZm9yKGkgPSB0aGlzLnQtMTsgaSA+PSAwOyAtLWkpIHJbaStuXSA9IHRoaXNbaV07XG4gIGZvcihpID0gbi0xOyBpID49IDA7IC0taSkgcltpXSA9IDA7XG4gIHIudCA9IHRoaXMudCtuO1xuICByLnMgPSB0aGlzLnM7XG59XG5cbi8vIChwcm90ZWN0ZWQpIHIgPSB0aGlzID4+IG4qREJcbmZ1bmN0aW9uIGJucERSU2hpZnRUbyhuLHIpIHtcbiAgZm9yKHZhciBpID0gbjsgaSA8IHRoaXMudDsgKytpKSByW2ktbl0gPSB0aGlzW2ldO1xuICByLnQgPSBNYXRoLm1heCh0aGlzLnQtbiwwKTtcbiAgci5zID0gdGhpcy5zO1xufVxuXG4vLyAocHJvdGVjdGVkKSByID0gdGhpcyA8PCBuXG5mdW5jdGlvbiBibnBMU2hpZnRUbyhuLHIpIHtcbiAgdmFyIGJzID0gbiV0aGlzLkRCO1xuICB2YXIgY2JzID0gdGhpcy5EQi1icztcbiAgdmFyIGJtID0gKDE8PGNicyktMTtcbiAgdmFyIGRzID0gTWF0aC5mbG9vcihuL3RoaXMuREIpLCBjID0gKHRoaXMuczw8YnMpJnRoaXMuRE0sIGk7XG4gIGZvcihpID0gdGhpcy50LTE7IGkgPj0gMDsgLS1pKSB7XG4gICAgcltpK2RzKzFdID0gKHRoaXNbaV0+PmNicyl8YztcbiAgICBjID0gKHRoaXNbaV0mYm0pPDxicztcbiAgfVxuICBmb3IoaSA9IGRzLTE7IGkgPj0gMDsgLS1pKSByW2ldID0gMDtcbiAgcltkc10gPSBjO1xuICByLnQgPSB0aGlzLnQrZHMrMTtcbiAgci5zID0gdGhpcy5zO1xuICByLmNsYW1wKCk7XG59XG5cbi8vIChwcm90ZWN0ZWQpIHIgPSB0aGlzID4+IG5cbmZ1bmN0aW9uIGJucFJTaGlmdFRvKG4scikge1xuICByLnMgPSB0aGlzLnM7XG4gIHZhciBkcyA9IE1hdGguZmxvb3Iobi90aGlzLkRCKTtcbiAgaWYoZHMgPj0gdGhpcy50KSB7IHIudCA9IDA7IHJldHVybjsgfVxuICB2YXIgYnMgPSBuJXRoaXMuREI7XG4gIHZhciBjYnMgPSB0aGlzLkRCLWJzO1xuICB2YXIgYm0gPSAoMTw8YnMpLTE7XG4gIHJbMF0gPSB0aGlzW2RzXT4+YnM7XG4gIGZvcih2YXIgaSA9IGRzKzE7IGkgPCB0aGlzLnQ7ICsraSkge1xuICAgIHJbaS1kcy0xXSB8PSAodGhpc1tpXSZibSk8PGNicztcbiAgICByW2ktZHNdID0gdGhpc1tpXT4+YnM7XG4gIH1cbiAgaWYoYnMgPiAwKSByW3RoaXMudC1kcy0xXSB8PSAodGhpcy5zJmJtKTw8Y2JzO1xuICByLnQgPSB0aGlzLnQtZHM7XG4gIHIuY2xhbXAoKTtcbn1cblxuLy8gKHByb3RlY3RlZCkgciA9IHRoaXMgLSBhXG5mdW5jdGlvbiBibnBTdWJUbyhhLHIpIHtcbiAgdmFyIGkgPSAwLCBjID0gMCwgbSA9IE1hdGgubWluKGEudCx0aGlzLnQpO1xuICB3aGlsZShpIDwgbSkge1xuICAgIGMgKz0gdGhpc1tpXS1hW2ldO1xuICAgIHJbaSsrXSA9IGMmdGhpcy5ETTtcbiAgICBjID4+PSB0aGlzLkRCO1xuICB9XG4gIGlmKGEudCA8IHRoaXMudCkge1xuICAgIGMgLT0gYS5zO1xuICAgIHdoaWxlKGkgPCB0aGlzLnQpIHtcbiAgICAgIGMgKz0gdGhpc1tpXTtcbiAgICAgIHJbaSsrXSA9IGMmdGhpcy5ETTtcbiAgICAgIGMgPj49IHRoaXMuREI7XG4gICAgfVxuICAgIGMgKz0gdGhpcy5zO1xuICB9XG4gIGVsc2Uge1xuICAgIGMgKz0gdGhpcy5zO1xuICAgIHdoaWxlKGkgPCBhLnQpIHtcbiAgICAgIGMgLT0gYVtpXTtcbiAgICAgIHJbaSsrXSA9IGMmdGhpcy5ETTtcbiAgICAgIGMgPj49IHRoaXMuREI7XG4gICAgfVxuICAgIGMgLT0gYS5zO1xuICB9XG4gIHIucyA9IChjPDApPy0xOjA7XG4gIGlmKGMgPCAtMSkgcltpKytdID0gdGhpcy5EVitjO1xuICBlbHNlIGlmKGMgPiAwKSByW2krK10gPSBjO1xuICByLnQgPSBpO1xuICByLmNsYW1wKCk7XG59XG5cbi8vIChwcm90ZWN0ZWQpIHIgPSB0aGlzICogYSwgciAhPSB0aGlzLGEgKEhBQyAxNC4xMilcbi8vIFwidGhpc1wiIHNob3VsZCBiZSB0aGUgbGFyZ2VyIG9uZSBpZiBhcHByb3ByaWF0ZS5cbmZ1bmN0aW9uIGJucE11bHRpcGx5VG8oYSxyKSB7XG4gIHZhciB4ID0gdGhpcy5hYnMoKSwgeSA9IGEuYWJzKCk7XG4gIHZhciBpID0geC50O1xuICByLnQgPSBpK3kudDtcbiAgd2hpbGUoLS1pID49IDApIHJbaV0gPSAwO1xuICBmb3IoaSA9IDA7IGkgPCB5LnQ7ICsraSkgcltpK3gudF0gPSB4LmFtKDAseVtpXSxyLGksMCx4LnQpO1xuICByLnMgPSAwO1xuICByLmNsYW1wKCk7XG4gIGlmKHRoaXMucyAhPSBhLnMpIEJpZ0ludGVnZXIuWkVSTy5zdWJUbyhyLHIpO1xufVxuXG4vLyAocHJvdGVjdGVkKSByID0gdGhpc14yLCByICE9IHRoaXMgKEhBQyAxNC4xNilcbmZ1bmN0aW9uIGJucFNxdWFyZVRvKHIpIHtcbiAgdmFyIHggPSB0aGlzLmFicygpO1xuICB2YXIgaSA9IHIudCA9IDIqeC50O1xuICB3aGlsZSgtLWkgPj0gMCkgcltpXSA9IDA7XG4gIGZvcihpID0gMDsgaSA8IHgudC0xOyArK2kpIHtcbiAgICB2YXIgYyA9IHguYW0oaSx4W2ldLHIsMippLDAsMSk7XG4gICAgaWYoKHJbaSt4LnRdKz14LmFtKGkrMSwyKnhbaV0sciwyKmkrMSxjLHgudC1pLTEpKSA+PSB4LkRWKSB7XG4gICAgICByW2kreC50XSAtPSB4LkRWO1xuICAgICAgcltpK3gudCsxXSA9IDE7XG4gICAgfVxuICB9XG4gIGlmKHIudCA+IDApIHJbci50LTFdICs9IHguYW0oaSx4W2ldLHIsMippLDAsMSk7XG4gIHIucyA9IDA7XG4gIHIuY2xhbXAoKTtcbn1cblxuLy8gKHByb3RlY3RlZCkgZGl2aWRlIHRoaXMgYnkgbSwgcXVvdGllbnQgYW5kIHJlbWFpbmRlciB0byBxLCByIChIQUMgMTQuMjApXG4vLyByICE9IHEsIHRoaXMgIT0gbS4gIHEgb3IgciBtYXkgYmUgbnVsbC5cbmZ1bmN0aW9uIGJucERpdlJlbVRvKG0scSxyKSB7XG4gIHZhciBwbSA9IG0uYWJzKCk7XG4gIGlmKHBtLnQgPD0gMCkgcmV0dXJuO1xuICB2YXIgcHQgPSB0aGlzLmFicygpO1xuICBpZihwdC50IDwgcG0udCkge1xuICAgIGlmKHEgIT0gbnVsbCkgcS5mcm9tSW50KDApO1xuICAgIGlmKHIgIT0gbnVsbCkgdGhpcy5jb3B5VG8ocik7XG4gICAgcmV0dXJuO1xuICB9XG4gIGlmKHIgPT0gbnVsbCkgciA9IG5iaSgpO1xuICB2YXIgeSA9IG5iaSgpLCB0cyA9IHRoaXMucywgbXMgPSBtLnM7XG4gIHZhciBuc2ggPSB0aGlzLkRCLW5iaXRzKHBtW3BtLnQtMV0pO1x0Ly8gbm9ybWFsaXplIG1vZHVsdXNcbiAgaWYobnNoID4gMCkgeyBwbS5sU2hpZnRUbyhuc2gseSk7IHB0LmxTaGlmdFRvKG5zaCxyKTsgfVxuICBlbHNlIHsgcG0uY29weVRvKHkpOyBwdC5jb3B5VG8ocik7IH1cbiAgdmFyIHlzID0geS50O1xuICB2YXIgeTAgPSB5W3lzLTFdO1xuICBpZih5MCA9PSAwKSByZXR1cm47XG4gIHZhciB5dCA9IHkwKigxPDx0aGlzLkYxKSsoKHlzPjEpP3lbeXMtMl0+PnRoaXMuRjI6MCk7XG4gIHZhciBkMSA9IHRoaXMuRlYveXQsIGQyID0gKDE8PHRoaXMuRjEpL3l0LCBlID0gMTw8dGhpcy5GMjtcbiAgdmFyIGkgPSByLnQsIGogPSBpLXlzLCB0ID0gKHE9PW51bGwpP25iaSgpOnE7XG4gIHkuZGxTaGlmdFRvKGosdCk7XG4gIGlmKHIuY29tcGFyZVRvKHQpID49IDApIHtcbiAgICByW3IudCsrXSA9IDE7XG4gICAgci5zdWJUbyh0LHIpO1xuICB9XG4gIEJpZ0ludGVnZXIuT05FLmRsU2hpZnRUbyh5cyx0KTtcbiAgdC5zdWJUbyh5LHkpO1x0Ly8gXCJuZWdhdGl2ZVwiIHkgc28gd2UgY2FuIHJlcGxhY2Ugc3ViIHdpdGggYW0gbGF0ZXJcbiAgd2hpbGUoeS50IDwgeXMpIHlbeS50KytdID0gMDtcbiAgd2hpbGUoLS1qID49IDApIHtcbiAgICAvLyBFc3RpbWF0ZSBxdW90aWVudCBkaWdpdFxuICAgIHZhciBxZCA9IChyWy0taV09PXkwKT90aGlzLkRNOk1hdGguZmxvb3IocltpXSpkMSsocltpLTFdK2UpKmQyKTtcbiAgICBpZigocltpXSs9eS5hbSgwLHFkLHIsaiwwLHlzKSkgPCBxZCkge1x0Ly8gVHJ5IGl0IG91dFxuICAgICAgeS5kbFNoaWZ0VG8oaix0KTtcbiAgICAgIHIuc3ViVG8odCxyKTtcbiAgICAgIHdoaWxlKHJbaV0gPCAtLXFkKSByLnN1YlRvKHQscik7XG4gICAgfVxuICB9XG4gIGlmKHEgIT0gbnVsbCkge1xuICAgIHIuZHJTaGlmdFRvKHlzLHEpO1xuICAgIGlmKHRzICE9IG1zKSBCaWdJbnRlZ2VyLlpFUk8uc3ViVG8ocSxxKTtcbiAgfVxuICByLnQgPSB5cztcbiAgci5jbGFtcCgpO1xuICBpZihuc2ggPiAwKSByLnJTaGlmdFRvKG5zaCxyKTtcdC8vIERlbm9ybWFsaXplIHJlbWFpbmRlclxuICBpZih0cyA8IDApIEJpZ0ludGVnZXIuWkVSTy5zdWJUbyhyLHIpO1xufVxuXG4vLyAocHVibGljKSB0aGlzIG1vZCBhXG5mdW5jdGlvbiBibk1vZChhKSB7XG4gIHZhciByID0gbmJpKCk7XG4gIHRoaXMuYWJzKCkuZGl2UmVtVG8oYSxudWxsLHIpO1xuICBpZih0aGlzLnMgPCAwICYmIHIuY29tcGFyZVRvKEJpZ0ludGVnZXIuWkVSTykgPiAwKSBhLnN1YlRvKHIscik7XG4gIHJldHVybiByO1xufVxuXG4vLyBNb2R1bGFyIHJlZHVjdGlvbiB1c2luZyBcImNsYXNzaWNcIiBhbGdvcml0aG1cbmZ1bmN0aW9uIENsYXNzaWMobSkgeyB0aGlzLm0gPSBtOyB9XG5mdW5jdGlvbiBjQ29udmVydCh4KSB7XG4gIGlmKHgucyA8IDAgfHwgeC5jb21wYXJlVG8odGhpcy5tKSA+PSAwKSByZXR1cm4geC5tb2QodGhpcy5tKTtcbiAgZWxzZSByZXR1cm4geDtcbn1cbmZ1bmN0aW9uIGNSZXZlcnQoeCkgeyByZXR1cm4geDsgfVxuZnVuY3Rpb24gY1JlZHVjZSh4KSB7IHguZGl2UmVtVG8odGhpcy5tLG51bGwseCk7IH1cbmZ1bmN0aW9uIGNNdWxUbyh4LHkscikgeyB4Lm11bHRpcGx5VG8oeSxyKTsgdGhpcy5yZWR1Y2Uocik7IH1cbmZ1bmN0aW9uIGNTcXJUbyh4LHIpIHsgeC5zcXVhcmVUbyhyKTsgdGhpcy5yZWR1Y2Uocik7IH1cblxuQ2xhc3NpYy5wcm90b3R5cGUuY29udmVydCA9IGNDb252ZXJ0O1xuQ2xhc3NpYy5wcm90b3R5cGUucmV2ZXJ0ID0gY1JldmVydDtcbkNsYXNzaWMucHJvdG90eXBlLnJlZHVjZSA9IGNSZWR1Y2U7XG5DbGFzc2ljLnByb3RvdHlwZS5tdWxUbyA9IGNNdWxUbztcbkNsYXNzaWMucHJvdG90eXBlLnNxclRvID0gY1NxclRvO1xuXG4vLyAocHJvdGVjdGVkKSByZXR1cm4gXCItMS90aGlzICUgMl5EQlwiOyB1c2VmdWwgZm9yIE1vbnQuIHJlZHVjdGlvblxuLy8ganVzdGlmaWNhdGlvbjpcbi8vICAgICAgICAgeHkgPT0gMSAobW9kIG0pXG4vLyAgICAgICAgIHh5ID0gIDEra21cbi8vICAgeHkoMi14eSkgPSAoMStrbSkoMS1rbSlcbi8vIHhbeSgyLXh5KV0gPSAxLWteMm1eMlxuLy8geFt5KDIteHkpXSA9PSAxIChtb2QgbV4yKVxuLy8gaWYgeSBpcyAxL3ggbW9kIG0sIHRoZW4geSgyLXh5KSBpcyAxL3ggbW9kIG1eMlxuLy8gc2hvdWxkIHJlZHVjZSB4IGFuZCB5KDIteHkpIGJ5IG1eMiBhdCBlYWNoIHN0ZXAgdG8ga2VlcCBzaXplIGJvdW5kZWQuXG4vLyBKUyBtdWx0aXBseSBcIm92ZXJmbG93c1wiIGRpZmZlcmVudGx5IGZyb20gQy9DKyssIHNvIGNhcmUgaXMgbmVlZGVkIGhlcmUuXG5mdW5jdGlvbiBibnBJbnZEaWdpdCgpIHtcbiAgaWYodGhpcy50IDwgMSkgcmV0dXJuIDA7XG4gIHZhciB4ID0gdGhpc1swXTtcbiAgaWYoKHgmMSkgPT0gMCkgcmV0dXJuIDA7XG4gIHZhciB5ID0geCYzO1x0XHQvLyB5ID09IDEveCBtb2QgMl4yXG4gIHkgPSAoeSooMi0oeCYweGYpKnkpKSYweGY7XHQvLyB5ID09IDEveCBtb2QgMl40XG4gIHkgPSAoeSooMi0oeCYweGZmKSp5KSkmMHhmZjtcdC8vIHkgPT0gMS94IG1vZCAyXjhcbiAgeSA9ICh5KigyLSgoKHgmMHhmZmZmKSp5KSYweGZmZmYpKSkmMHhmZmZmO1x0Ly8geSA9PSAxL3ggbW9kIDJeMTZcbiAgLy8gbGFzdCBzdGVwIC0gY2FsY3VsYXRlIGludmVyc2UgbW9kIERWIGRpcmVjdGx5O1xuICAvLyBhc3N1bWVzIDE2IDwgREIgPD0gMzIgYW5kIGFzc3VtZXMgYWJpbGl0eSB0byBoYW5kbGUgNDgtYml0IGludHNcbiAgeSA9ICh5KigyLXgqeSV0aGlzLkRWKSkldGhpcy5EVjtcdFx0Ly8geSA9PSAxL3ggbW9kIDJeZGJpdHNcbiAgLy8gd2UgcmVhbGx5IHdhbnQgdGhlIG5lZ2F0aXZlIGludmVyc2UsIGFuZCAtRFYgPCB5IDwgRFZcbiAgcmV0dXJuICh5PjApP3RoaXMuRFYteToteTtcbn1cblxuLy8gTW9udGdvbWVyeSByZWR1Y3Rpb25cbmZ1bmN0aW9uIE1vbnRnb21lcnkobSkge1xuICB0aGlzLm0gPSBtO1xuICB0aGlzLm1wID0gbS5pbnZEaWdpdCgpO1xuICB0aGlzLm1wbCA9IHRoaXMubXAmMHg3ZmZmO1xuICB0aGlzLm1waCA9IHRoaXMubXA+PjE1O1xuICB0aGlzLnVtID0gKDE8PChtLkRCLTE1KSktMTtcbiAgdGhpcy5tdDIgPSAyKm0udDtcbn1cblxuLy8geFIgbW9kIG1cbmZ1bmN0aW9uIG1vbnRDb252ZXJ0KHgpIHtcbiAgdmFyIHIgPSBuYmkoKTtcbiAgeC5hYnMoKS5kbFNoaWZ0VG8odGhpcy5tLnQscik7XG4gIHIuZGl2UmVtVG8odGhpcy5tLG51bGwscik7XG4gIGlmKHgucyA8IDAgJiYgci5jb21wYXJlVG8oQmlnSW50ZWdlci5aRVJPKSA+IDApIHRoaXMubS5zdWJUbyhyLHIpO1xuICByZXR1cm4gcjtcbn1cblxuLy8geC9SIG1vZCBtXG5mdW5jdGlvbiBtb250UmV2ZXJ0KHgpIHtcbiAgdmFyIHIgPSBuYmkoKTtcbiAgeC5jb3B5VG8ocik7XG4gIHRoaXMucmVkdWNlKHIpO1xuICByZXR1cm4gcjtcbn1cblxuLy8geCA9IHgvUiBtb2QgbSAoSEFDIDE0LjMyKVxuZnVuY3Rpb24gbW9udFJlZHVjZSh4KSB7XG4gIHdoaWxlKHgudCA8PSB0aGlzLm10MilcdC8vIHBhZCB4IHNvIGFtIGhhcyBlbm91Z2ggcm9vbSBsYXRlclxuICAgIHhbeC50KytdID0gMDtcbiAgZm9yKHZhciBpID0gMDsgaSA8IHRoaXMubS50OyArK2kpIHtcbiAgICAvLyBmYXN0ZXIgd2F5IG9mIGNhbGN1bGF0aW5nIHUwID0geFtpXSptcCBtb2QgRFZcbiAgICB2YXIgaiA9IHhbaV0mMHg3ZmZmO1xuICAgIHZhciB1MCA9IChqKnRoaXMubXBsKygoKGoqdGhpcy5tcGgrKHhbaV0+PjE1KSp0aGlzLm1wbCkmdGhpcy51bSk8PDE1KSkmeC5ETTtcbiAgICAvLyB1c2UgYW0gdG8gY29tYmluZSB0aGUgbXVsdGlwbHktc2hpZnQtYWRkIGludG8gb25lIGNhbGxcbiAgICBqID0gaSt0aGlzLm0udDtcbiAgICB4W2pdICs9IHRoaXMubS5hbSgwLHUwLHgsaSwwLHRoaXMubS50KTtcbiAgICAvLyBwcm9wYWdhdGUgY2FycnlcbiAgICB3aGlsZSh4W2pdID49IHguRFYpIHsgeFtqXSAtPSB4LkRWOyB4Wysral0rKzsgfVxuICB9XG4gIHguY2xhbXAoKTtcbiAgeC5kclNoaWZ0VG8odGhpcy5tLnQseCk7XG4gIGlmKHguY29tcGFyZVRvKHRoaXMubSkgPj0gMCkgeC5zdWJUbyh0aGlzLm0seCk7XG59XG5cbi8vIHIgPSBcInheMi9SIG1vZCBtXCI7IHggIT0gclxuZnVuY3Rpb24gbW9udFNxclRvKHgscikgeyB4LnNxdWFyZVRvKHIpOyB0aGlzLnJlZHVjZShyKTsgfVxuXG4vLyByID0gXCJ4eS9SIG1vZCBtXCI7IHgseSAhPSByXG5mdW5jdGlvbiBtb250TXVsVG8oeCx5LHIpIHsgeC5tdWx0aXBseVRvKHkscik7IHRoaXMucmVkdWNlKHIpOyB9XG5cbk1vbnRnb21lcnkucHJvdG90eXBlLmNvbnZlcnQgPSBtb250Q29udmVydDtcbk1vbnRnb21lcnkucHJvdG90eXBlLnJldmVydCA9IG1vbnRSZXZlcnQ7XG5Nb250Z29tZXJ5LnByb3RvdHlwZS5yZWR1Y2UgPSBtb250UmVkdWNlO1xuTW9udGdvbWVyeS5wcm90b3R5cGUubXVsVG8gPSBtb250TXVsVG87XG5Nb250Z29tZXJ5LnByb3RvdHlwZS5zcXJUbyA9IG1vbnRTcXJUbztcblxuLy8gKHByb3RlY3RlZCkgdHJ1ZSBpZmYgdGhpcyBpcyBldmVuXG5mdW5jdGlvbiBibnBJc0V2ZW4oKSB7IHJldHVybiAoKHRoaXMudD4wKT8odGhpc1swXSYxKTp0aGlzLnMpID09IDA7IH1cblxuLy8gKHByb3RlY3RlZCkgdGhpc15lLCBlIDwgMl4zMiwgZG9pbmcgc3FyIGFuZCBtdWwgd2l0aCBcInJcIiAoSEFDIDE0Ljc5KVxuZnVuY3Rpb24gYm5wRXhwKGUseikge1xuICBpZihlID4gMHhmZmZmZmZmZiB8fCBlIDwgMSkgcmV0dXJuIEJpZ0ludGVnZXIuT05FO1xuICB2YXIgciA9IG5iaSgpLCByMiA9IG5iaSgpLCBnID0gei5jb252ZXJ0KHRoaXMpLCBpID0gbmJpdHMoZSktMTtcbiAgZy5jb3B5VG8ocik7XG4gIHdoaWxlKC0taSA+PSAwKSB7XG4gICAgei5zcXJUbyhyLHIyKTtcbiAgICBpZigoZSYoMTw8aSkpID4gMCkgei5tdWxUbyhyMixnLHIpO1xuICAgIGVsc2UgeyB2YXIgdCA9IHI7IHIgPSByMjsgcjIgPSB0OyB9XG4gIH1cbiAgcmV0dXJuIHoucmV2ZXJ0KHIpO1xufVxuXG4vLyAocHVibGljKSB0aGlzXmUgJSBtLCAwIDw9IGUgPCAyXjMyXG5mdW5jdGlvbiBibk1vZFBvd0ludChlLG0pIHtcbiAgdmFyIHo7XG4gIGlmKGUgPCAyNTYgfHwgbS5pc0V2ZW4oKSkgeiA9IG5ldyBDbGFzc2ljKG0pOyBlbHNlIHogPSBuZXcgTW9udGdvbWVyeShtKTtcbiAgcmV0dXJuIHRoaXMuZXhwKGUseik7XG59XG5cbi8vIHByb3RlY3RlZFxuQmlnSW50ZWdlci5wcm90b3R5cGUuY29weVRvID0gYm5wQ29weVRvO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZnJvbUludCA9IGJucEZyb21JbnQ7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5mcm9tU3RyaW5nID0gYm5wRnJvbVN0cmluZztcbkJpZ0ludGVnZXIucHJvdG90eXBlLmNsYW1wID0gYm5wQ2xhbXA7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5kbFNoaWZ0VG8gPSBibnBETFNoaWZ0VG87XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5kclNoaWZ0VG8gPSBibnBEUlNoaWZ0VG87XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5sU2hpZnRUbyA9IGJucExTaGlmdFRvO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuclNoaWZ0VG8gPSBibnBSU2hpZnRUbztcbkJpZ0ludGVnZXIucHJvdG90eXBlLnN1YlRvID0gYm5wU3ViVG87XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5tdWx0aXBseVRvID0gYm5wTXVsdGlwbHlUbztcbkJpZ0ludGVnZXIucHJvdG90eXBlLnNxdWFyZVRvID0gYm5wU3F1YXJlVG87XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5kaXZSZW1UbyA9IGJucERpdlJlbVRvO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuaW52RGlnaXQgPSBibnBJbnZEaWdpdDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmlzRXZlbiA9IGJucElzRXZlbjtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmV4cCA9IGJucEV4cDtcblxuLy8gcHVibGljXG5CaWdJbnRlZ2VyLnByb3RvdHlwZS50b1N0cmluZyA9IGJuVG9TdHJpbmc7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5uZWdhdGUgPSBibk5lZ2F0ZTtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmFicyA9IGJuQWJzO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuY29tcGFyZVRvID0gYm5Db21wYXJlVG87XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5iaXRMZW5ndGggPSBibkJpdExlbmd0aDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLm1vZCA9IGJuTW9kO1xuQmlnSW50ZWdlci5wcm90b3R5cGUubW9kUG93SW50ID0gYm5Nb2RQb3dJbnQ7XG5cbi8vIFwiY29uc3RhbnRzXCJcbkJpZ0ludGVnZXIuWkVSTyA9IG5idigwKTtcbkJpZ0ludGVnZXIuT05FID0gbmJ2KDEpO1xuXG4vLyBDb3B5cmlnaHQgKGMpIDIwMDUtMjAwOSAgVG9tIFd1XG4vLyBBbGwgUmlnaHRzIFJlc2VydmVkLlxuLy8gU2VlIFwiTElDRU5TRVwiIGZvciBkZXRhaWxzLlxuXG4vLyBFeHRlbmRlZCBKYXZhU2NyaXB0IEJOIGZ1bmN0aW9ucywgcmVxdWlyZWQgZm9yIFJTQSBwcml2YXRlIG9wcy5cblxuLy8gVmVyc2lvbiAxLjE6IG5ldyBCaWdJbnRlZ2VyKFwiMFwiLCAxMCkgcmV0dXJucyBcInByb3BlclwiIHplcm9cbi8vIFZlcnNpb24gMS4yOiBzcXVhcmUoKSBBUEksIGlzUHJvYmFibGVQcmltZSBmaXhcblxuLy8gKHB1YmxpYylcbmZ1bmN0aW9uIGJuQ2xvbmUoKSB7IHZhciByID0gbmJpKCk7IHRoaXMuY29weVRvKHIpOyByZXR1cm4gcjsgfVxuXG4vLyAocHVibGljKSByZXR1cm4gdmFsdWUgYXMgaW50ZWdlclxuZnVuY3Rpb24gYm5JbnRWYWx1ZSgpIHtcbiAgaWYodGhpcy5zIDwgMCkge1xuICAgIGlmKHRoaXMudCA9PSAxKSByZXR1cm4gdGhpc1swXS10aGlzLkRWO1xuICAgIGVsc2UgaWYodGhpcy50ID09IDApIHJldHVybiAtMTtcbiAgfVxuICBlbHNlIGlmKHRoaXMudCA9PSAxKSByZXR1cm4gdGhpc1swXTtcbiAgZWxzZSBpZih0aGlzLnQgPT0gMCkgcmV0dXJuIDA7XG4gIC8vIGFzc3VtZXMgMTYgPCBEQiA8IDMyXG4gIHJldHVybiAoKHRoaXNbMV0mKCgxPDwoMzItdGhpcy5EQikpLTEpKTw8dGhpcy5EQil8dGhpc1swXTtcbn1cblxuLy8gKHB1YmxpYykgcmV0dXJuIHZhbHVlIGFzIGJ5dGVcbmZ1bmN0aW9uIGJuQnl0ZVZhbHVlKCkgeyByZXR1cm4gKHRoaXMudD09MCk/dGhpcy5zOih0aGlzWzBdPDwyNCk+PjI0OyB9XG5cbi8vIChwdWJsaWMpIHJldHVybiB2YWx1ZSBhcyBzaG9ydCAoYXNzdW1lcyBEQj49MTYpXG5mdW5jdGlvbiBiblNob3J0VmFsdWUoKSB7IHJldHVybiAodGhpcy50PT0wKT90aGlzLnM6KHRoaXNbMF08PDE2KT4+MTY7IH1cblxuLy8gKHByb3RlY3RlZCkgcmV0dXJuIHggcy50LiByXnggPCBEVlxuZnVuY3Rpb24gYm5wQ2h1bmtTaXplKHIpIHsgcmV0dXJuIE1hdGguZmxvb3IoTWF0aC5MTjIqdGhpcy5EQi9NYXRoLmxvZyhyKSk7IH1cblxuLy8gKHB1YmxpYykgMCBpZiB0aGlzID09IDAsIDEgaWYgdGhpcyA+IDBcbmZ1bmN0aW9uIGJuU2lnTnVtKCkge1xuICBpZih0aGlzLnMgPCAwKSByZXR1cm4gLTE7XG4gIGVsc2UgaWYodGhpcy50IDw9IDAgfHwgKHRoaXMudCA9PSAxICYmIHRoaXNbMF0gPD0gMCkpIHJldHVybiAwO1xuICBlbHNlIHJldHVybiAxO1xufVxuXG4vLyAocHJvdGVjdGVkKSBjb252ZXJ0IHRvIHJhZGl4IHN0cmluZ1xuZnVuY3Rpb24gYm5wVG9SYWRpeChiKSB7XG4gIGlmKGIgPT0gbnVsbCkgYiA9IDEwO1xuICBpZih0aGlzLnNpZ251bSgpID09IDAgfHwgYiA8IDIgfHwgYiA+IDM2KSByZXR1cm4gXCIwXCI7XG4gIHZhciBjcyA9IHRoaXMuY2h1bmtTaXplKGIpO1xuICB2YXIgYSA9IE1hdGgucG93KGIsY3MpO1xuICB2YXIgZCA9IG5idihhKSwgeSA9IG5iaSgpLCB6ID0gbmJpKCksIHIgPSBcIlwiO1xuICB0aGlzLmRpdlJlbVRvKGQseSx6KTtcbiAgd2hpbGUoeS5zaWdudW0oKSA+IDApIHtcbiAgICByID0gKGErei5pbnRWYWx1ZSgpKS50b1N0cmluZyhiKS5zdWJzdHIoMSkgKyByO1xuICAgIHkuZGl2UmVtVG8oZCx5LHopO1xuICB9XG4gIHJldHVybiB6LmludFZhbHVlKCkudG9TdHJpbmcoYikgKyByO1xufVxuXG4vLyAocHJvdGVjdGVkKSBjb252ZXJ0IGZyb20gcmFkaXggc3RyaW5nXG5mdW5jdGlvbiBibnBGcm9tUmFkaXgocyxiKSB7XG4gIHRoaXMuZnJvbUludCgwKTtcbiAgaWYoYiA9PSBudWxsKSBiID0gMTA7XG4gIHZhciBjcyA9IHRoaXMuY2h1bmtTaXplKGIpO1xuICB2YXIgZCA9IE1hdGgucG93KGIsY3MpLCBtaSA9IGZhbHNlLCBqID0gMCwgdyA9IDA7XG4gIGZvcih2YXIgaSA9IDA7IGkgPCBzLmxlbmd0aDsgKytpKSB7XG4gICAgdmFyIHggPSBpbnRBdChzLGkpO1xuICAgIGlmKHggPCAwKSB7XG4gICAgICBpZihzLmNoYXJBdChpKSA9PSBcIi1cIiAmJiB0aGlzLnNpZ251bSgpID09IDApIG1pID0gdHJ1ZTtcbiAgICAgIGNvbnRpbnVlO1xuICAgIH1cbiAgICB3ID0gYip3K3g7XG4gICAgaWYoKytqID49IGNzKSB7XG4gICAgICB0aGlzLmRNdWx0aXBseShkKTtcbiAgICAgIHRoaXMuZEFkZE9mZnNldCh3LDApO1xuICAgICAgaiA9IDA7XG4gICAgICB3ID0gMDtcbiAgICB9XG4gIH1cbiAgaWYoaiA+IDApIHtcbiAgICB0aGlzLmRNdWx0aXBseShNYXRoLnBvdyhiLGopKTtcbiAgICB0aGlzLmRBZGRPZmZzZXQodywwKTtcbiAgfVxuICBpZihtaSkgQmlnSW50ZWdlci5aRVJPLnN1YlRvKHRoaXMsdGhpcyk7XG59XG5cbi8vIChwcm90ZWN0ZWQpIGFsdGVybmF0ZSBjb25zdHJ1Y3RvclxuZnVuY3Rpb24gYm5wRnJvbU51bWJlcihhLGIsYykge1xuICBpZihcIm51bWJlclwiID09IHR5cGVvZiBiKSB7XG4gICAgLy8gbmV3IEJpZ0ludGVnZXIoaW50LGludCxSTkcpXG4gICAgaWYoYSA8IDIpIHRoaXMuZnJvbUludCgxKTtcbiAgICBlbHNlIHtcbiAgICAgIHRoaXMuZnJvbU51bWJlcihhLGMpO1xuICAgICAgaWYoIXRoaXMudGVzdEJpdChhLTEpKVx0Ly8gZm9yY2UgTVNCIHNldFxuICAgICAgICB0aGlzLmJpdHdpc2VUbyhCaWdJbnRlZ2VyLk9ORS5zaGlmdExlZnQoYS0xKSxvcF9vcix0aGlzKTtcbiAgICAgIGlmKHRoaXMuaXNFdmVuKCkpIHRoaXMuZEFkZE9mZnNldCgxLDApOyAvLyBmb3JjZSBvZGRcbiAgICAgIHdoaWxlKCF0aGlzLmlzUHJvYmFibGVQcmltZShiKSkge1xuICAgICAgICB0aGlzLmRBZGRPZmZzZXQoMiwwKTtcbiAgICAgICAgaWYodGhpcy5iaXRMZW5ndGgoKSA+IGEpIHRoaXMuc3ViVG8oQmlnSW50ZWdlci5PTkUuc2hpZnRMZWZ0KGEtMSksdGhpcyk7XG4gICAgICB9XG4gICAgfVxuICB9XG4gIGVsc2Uge1xuICAgIC8vIG5ldyBCaWdJbnRlZ2VyKGludCxSTkcpXG4gICAgdmFyIHggPSBuZXcgQXJyYXkoKSwgdCA9IGEmNztcbiAgICB4Lmxlbmd0aCA9IChhPj4zKSsxO1xuICAgIGIubmV4dEJ5dGVzKHgpO1xuICAgIGlmKHQgPiAwKSB4WzBdICY9ICgoMTw8dCktMSk7IGVsc2UgeFswXSA9IDA7XG4gICAgdGhpcy5mcm9tU3RyaW5nKHgsMjU2KTtcbiAgfVxufVxuXG4vLyAocHVibGljKSBjb252ZXJ0IHRvIGJpZ2VuZGlhbiBieXRlIGFycmF5XG5mdW5jdGlvbiBiblRvQnl0ZUFycmF5KCkge1xuICB2YXIgaSA9IHRoaXMudCwgciA9IG5ldyBBcnJheSgpO1xuICByWzBdID0gdGhpcy5zO1xuICB2YXIgcCA9IHRoaXMuREItKGkqdGhpcy5EQiklOCwgZCwgayA9IDA7XG4gIGlmKGktLSA+IDApIHtcbiAgICBpZihwIDwgdGhpcy5EQiAmJiAoZCA9IHRoaXNbaV0+PnApICE9ICh0aGlzLnMmdGhpcy5ETSk+PnApXG4gICAgICByW2srK10gPSBkfCh0aGlzLnM8PCh0aGlzLkRCLXApKTtcbiAgICB3aGlsZShpID49IDApIHtcbiAgICAgIGlmKHAgPCA4KSB7XG4gICAgICAgIGQgPSAodGhpc1tpXSYoKDE8PHApLTEpKTw8KDgtcCk7XG4gICAgICAgIGQgfD0gdGhpc1stLWldPj4ocCs9dGhpcy5EQi04KTtcbiAgICAgIH1cbiAgICAgIGVsc2Uge1xuICAgICAgICBkID0gKHRoaXNbaV0+PihwLT04KSkmMHhmZjtcbiAgICAgICAgaWYocCA8PSAwKSB7IHAgKz0gdGhpcy5EQjsgLS1pOyB9XG4gICAgICB9XG4gICAgICBpZigoZCYweDgwKSAhPSAwKSBkIHw9IC0yNTY7XG4gICAgICBpZihrID09IDAgJiYgKHRoaXMucyYweDgwKSAhPSAoZCYweDgwKSkgKytrO1xuICAgICAgaWYoayA+IDAgfHwgZCAhPSB0aGlzLnMpIHJbaysrXSA9IGQ7XG4gICAgfVxuICB9XG4gIHJldHVybiByO1xufVxuXG5mdW5jdGlvbiBibkVxdWFscyhhKSB7IHJldHVybih0aGlzLmNvbXBhcmVUbyhhKT09MCk7IH1cbmZ1bmN0aW9uIGJuTWluKGEpIHsgcmV0dXJuKHRoaXMuY29tcGFyZVRvKGEpPDApP3RoaXM6YTsgfVxuZnVuY3Rpb24gYm5NYXgoYSkgeyByZXR1cm4odGhpcy5jb21wYXJlVG8oYSk+MCk/dGhpczphOyB9XG5cbi8vIChwcm90ZWN0ZWQpIHIgPSB0aGlzIG9wIGEgKGJpdHdpc2UpXG5mdW5jdGlvbiBibnBCaXR3aXNlVG8oYSxvcCxyKSB7XG4gIHZhciBpLCBmLCBtID0gTWF0aC5taW4oYS50LHRoaXMudCk7XG4gIGZvcihpID0gMDsgaSA8IG07ICsraSkgcltpXSA9IG9wKHRoaXNbaV0sYVtpXSk7XG4gIGlmKGEudCA8IHRoaXMudCkge1xuICAgIGYgPSBhLnMmdGhpcy5ETTtcbiAgICBmb3IoaSA9IG07IGkgPCB0aGlzLnQ7ICsraSkgcltpXSA9IG9wKHRoaXNbaV0sZik7XG4gICAgci50ID0gdGhpcy50O1xuICB9XG4gIGVsc2Uge1xuICAgIGYgPSB0aGlzLnMmdGhpcy5ETTtcbiAgICBmb3IoaSA9IG07IGkgPCBhLnQ7ICsraSkgcltpXSA9IG9wKGYsYVtpXSk7XG4gICAgci50ID0gYS50O1xuICB9XG4gIHIucyA9IG9wKHRoaXMucyxhLnMpO1xuICByLmNsYW1wKCk7XG59XG5cbi8vIChwdWJsaWMpIHRoaXMgJiBhXG5mdW5jdGlvbiBvcF9hbmQoeCx5KSB7IHJldHVybiB4Jnk7IH1cbmZ1bmN0aW9uIGJuQW5kKGEpIHsgdmFyIHIgPSBuYmkoKTsgdGhpcy5iaXR3aXNlVG8oYSxvcF9hbmQscik7IHJldHVybiByOyB9XG5cbi8vIChwdWJsaWMpIHRoaXMgfCBhXG5mdW5jdGlvbiBvcF9vcih4LHkpIHsgcmV0dXJuIHh8eTsgfVxuZnVuY3Rpb24gYm5PcihhKSB7IHZhciByID0gbmJpKCk7IHRoaXMuYml0d2lzZVRvKGEsb3Bfb3Iscik7IHJldHVybiByOyB9XG5cbi8vIChwdWJsaWMpIHRoaXMgXiBhXG5mdW5jdGlvbiBvcF94b3IoeCx5KSB7IHJldHVybiB4Xnk7IH1cbmZ1bmN0aW9uIGJuWG9yKGEpIHsgdmFyIHIgPSBuYmkoKTsgdGhpcy5iaXR3aXNlVG8oYSxvcF94b3Iscik7IHJldHVybiByOyB9XG5cbi8vIChwdWJsaWMpIHRoaXMgJiB+YVxuZnVuY3Rpb24gb3BfYW5kbm90KHgseSkgeyByZXR1cm4geCZ+eTsgfVxuZnVuY3Rpb24gYm5BbmROb3QoYSkgeyB2YXIgciA9IG5iaSgpOyB0aGlzLmJpdHdpc2VUbyhhLG9wX2FuZG5vdCxyKTsgcmV0dXJuIHI7IH1cblxuLy8gKHB1YmxpYykgfnRoaXNcbmZ1bmN0aW9uIGJuTm90KCkge1xuICB2YXIgciA9IG5iaSgpO1xuICBmb3IodmFyIGkgPSAwOyBpIDwgdGhpcy50OyArK2kpIHJbaV0gPSB0aGlzLkRNJn50aGlzW2ldO1xuICByLnQgPSB0aGlzLnQ7XG4gIHIucyA9IH50aGlzLnM7XG4gIHJldHVybiByO1xufVxuXG4vLyAocHVibGljKSB0aGlzIDw8IG5cbmZ1bmN0aW9uIGJuU2hpZnRMZWZ0KG4pIHtcbiAgdmFyIHIgPSBuYmkoKTtcbiAgaWYobiA8IDApIHRoaXMuclNoaWZ0VG8oLW4scik7IGVsc2UgdGhpcy5sU2hpZnRUbyhuLHIpO1xuICByZXR1cm4gcjtcbn1cblxuLy8gKHB1YmxpYykgdGhpcyA+PiBuXG5mdW5jdGlvbiBiblNoaWZ0UmlnaHQobikge1xuICB2YXIgciA9IG5iaSgpO1xuICBpZihuIDwgMCkgdGhpcy5sU2hpZnRUbygtbixyKTsgZWxzZSB0aGlzLnJTaGlmdFRvKG4scik7XG4gIHJldHVybiByO1xufVxuXG4vLyByZXR1cm4gaW5kZXggb2YgbG93ZXN0IDEtYml0IGluIHgsIHggPCAyXjMxXG5mdW5jdGlvbiBsYml0KHgpIHtcbiAgaWYoeCA9PSAwKSByZXR1cm4gLTE7XG4gIHZhciByID0gMDtcbiAgaWYoKHgmMHhmZmZmKSA9PSAwKSB7IHggPj49IDE2OyByICs9IDE2OyB9XG4gIGlmKCh4JjB4ZmYpID09IDApIHsgeCA+Pj0gODsgciArPSA4OyB9XG4gIGlmKCh4JjB4ZikgPT0gMCkgeyB4ID4+PSA0OyByICs9IDQ7IH1cbiAgaWYoKHgmMykgPT0gMCkgeyB4ID4+PSAyOyByICs9IDI7IH1cbiAgaWYoKHgmMSkgPT0gMCkgKytyO1xuICByZXR1cm4gcjtcbn1cblxuLy8gKHB1YmxpYykgcmV0dXJucyBpbmRleCBvZiBsb3dlc3QgMS1iaXQgKG9yIC0xIGlmIG5vbmUpXG5mdW5jdGlvbiBibkdldExvd2VzdFNldEJpdCgpIHtcbiAgZm9yKHZhciBpID0gMDsgaSA8IHRoaXMudDsgKytpKVxuICAgIGlmKHRoaXNbaV0gIT0gMCkgcmV0dXJuIGkqdGhpcy5EQitsYml0KHRoaXNbaV0pO1xuICBpZih0aGlzLnMgPCAwKSByZXR1cm4gdGhpcy50KnRoaXMuREI7XG4gIHJldHVybiAtMTtcbn1cblxuLy8gcmV0dXJuIG51bWJlciBvZiAxIGJpdHMgaW4geFxuZnVuY3Rpb24gY2JpdCh4KSB7XG4gIHZhciByID0gMDtcbiAgd2hpbGUoeCAhPSAwKSB7IHggJj0geC0xOyArK3I7IH1cbiAgcmV0dXJuIHI7XG59XG5cbi8vIChwdWJsaWMpIHJldHVybiBudW1iZXIgb2Ygc2V0IGJpdHNcbmZ1bmN0aW9uIGJuQml0Q291bnQoKSB7XG4gIHZhciByID0gMCwgeCA9IHRoaXMucyZ0aGlzLkRNO1xuICBmb3IodmFyIGkgPSAwOyBpIDwgdGhpcy50OyArK2kpIHIgKz0gY2JpdCh0aGlzW2ldXngpO1xuICByZXR1cm4gcjtcbn1cblxuLy8gKHB1YmxpYykgdHJ1ZSBpZmYgbnRoIGJpdCBpcyBzZXRcbmZ1bmN0aW9uIGJuVGVzdEJpdChuKSB7XG4gIHZhciBqID0gTWF0aC5mbG9vcihuL3RoaXMuREIpO1xuICBpZihqID49IHRoaXMudCkgcmV0dXJuKHRoaXMucyE9MCk7XG4gIHJldHVybigodGhpc1tqXSYoMTw8KG4ldGhpcy5EQikpKSE9MCk7XG59XG5cbi8vIChwcm90ZWN0ZWQpIHRoaXMgb3AgKDE8PG4pXG5mdW5jdGlvbiBibnBDaGFuZ2VCaXQobixvcCkge1xuICB2YXIgciA9IEJpZ0ludGVnZXIuT05FLnNoaWZ0TGVmdChuKTtcbiAgdGhpcy5iaXR3aXNlVG8ocixvcCxyKTtcbiAgcmV0dXJuIHI7XG59XG5cbi8vIChwdWJsaWMpIHRoaXMgfCAoMTw8bilcbmZ1bmN0aW9uIGJuU2V0Qml0KG4pIHsgcmV0dXJuIHRoaXMuY2hhbmdlQml0KG4sb3Bfb3IpOyB9XG5cbi8vIChwdWJsaWMpIHRoaXMgJiB+KDE8PG4pXG5mdW5jdGlvbiBibkNsZWFyQml0KG4pIHsgcmV0dXJuIHRoaXMuY2hhbmdlQml0KG4sb3BfYW5kbm90KTsgfVxuXG4vLyAocHVibGljKSB0aGlzIF4gKDE8PG4pXG5mdW5jdGlvbiBibkZsaXBCaXQobikgeyByZXR1cm4gdGhpcy5jaGFuZ2VCaXQobixvcF94b3IpOyB9XG5cbi8vIChwcm90ZWN0ZWQpIHIgPSB0aGlzICsgYVxuZnVuY3Rpb24gYm5wQWRkVG8oYSxyKSB7XG4gIHZhciBpID0gMCwgYyA9IDAsIG0gPSBNYXRoLm1pbihhLnQsdGhpcy50KTtcbiAgd2hpbGUoaSA8IG0pIHtcbiAgICBjICs9IHRoaXNbaV0rYVtpXTtcbiAgICByW2krK10gPSBjJnRoaXMuRE07XG4gICAgYyA+Pj0gdGhpcy5EQjtcbiAgfVxuICBpZihhLnQgPCB0aGlzLnQpIHtcbiAgICBjICs9IGEucztcbiAgICB3aGlsZShpIDwgdGhpcy50KSB7XG4gICAgICBjICs9IHRoaXNbaV07XG4gICAgICByW2krK10gPSBjJnRoaXMuRE07XG4gICAgICBjID4+PSB0aGlzLkRCO1xuICAgIH1cbiAgICBjICs9IHRoaXMucztcbiAgfVxuICBlbHNlIHtcbiAgICBjICs9IHRoaXMucztcbiAgICB3aGlsZShpIDwgYS50KSB7XG4gICAgICBjICs9IGFbaV07XG4gICAgICByW2krK10gPSBjJnRoaXMuRE07XG4gICAgICBjID4+PSB0aGlzLkRCO1xuICAgIH1cbiAgICBjICs9IGEucztcbiAgfVxuICByLnMgPSAoYzwwKT8tMTowO1xuICBpZihjID4gMCkgcltpKytdID0gYztcbiAgZWxzZSBpZihjIDwgLTEpIHJbaSsrXSA9IHRoaXMuRFYrYztcbiAgci50ID0gaTtcbiAgci5jbGFtcCgpO1xufVxuXG4vLyAocHVibGljKSB0aGlzICsgYVxuZnVuY3Rpb24gYm5BZGQoYSkgeyB2YXIgciA9IG5iaSgpOyB0aGlzLmFkZFRvKGEscik7IHJldHVybiByOyB9XG5cbi8vIChwdWJsaWMpIHRoaXMgLSBhXG5mdW5jdGlvbiBiblN1YnRyYWN0KGEpIHsgdmFyIHIgPSBuYmkoKTsgdGhpcy5zdWJUbyhhLHIpOyByZXR1cm4gcjsgfVxuXG4vLyAocHVibGljKSB0aGlzICogYVxuZnVuY3Rpb24gYm5NdWx0aXBseShhKSB7IHZhciByID0gbmJpKCk7IHRoaXMubXVsdGlwbHlUbyhhLHIpOyByZXR1cm4gcjsgfVxuXG4vLyAocHVibGljKSB0aGlzXjJcbmZ1bmN0aW9uIGJuU3F1YXJlKCkgeyB2YXIgciA9IG5iaSgpOyB0aGlzLnNxdWFyZVRvKHIpOyByZXR1cm4gcjsgfVxuXG4vLyAocHVibGljKSB0aGlzIC8gYVxuZnVuY3Rpb24gYm5EaXZpZGUoYSkgeyB2YXIgciA9IG5iaSgpOyB0aGlzLmRpdlJlbVRvKGEscixudWxsKTsgcmV0dXJuIHI7IH1cblxuLy8gKHB1YmxpYykgdGhpcyAlIGFcbmZ1bmN0aW9uIGJuUmVtYWluZGVyKGEpIHsgdmFyIHIgPSBuYmkoKTsgdGhpcy5kaXZSZW1UbyhhLG51bGwscik7IHJldHVybiByOyB9XG5cbi8vIChwdWJsaWMpIFt0aGlzL2EsdGhpcyVhXVxuZnVuY3Rpb24gYm5EaXZpZGVBbmRSZW1haW5kZXIoYSkge1xuICB2YXIgcSA9IG5iaSgpLCByID0gbmJpKCk7XG4gIHRoaXMuZGl2UmVtVG8oYSxxLHIpO1xuICByZXR1cm4gbmV3IEFycmF5KHEscik7XG59XG5cbi8vIChwcm90ZWN0ZWQpIHRoaXMgKj0gbiwgdGhpcyA+PSAwLCAxIDwgbiA8IERWXG5mdW5jdGlvbiBibnBETXVsdGlwbHkobikge1xuICB0aGlzW3RoaXMudF0gPSB0aGlzLmFtKDAsbi0xLHRoaXMsMCwwLHRoaXMudCk7XG4gICsrdGhpcy50O1xuICB0aGlzLmNsYW1wKCk7XG59XG5cbi8vIChwcm90ZWN0ZWQpIHRoaXMgKz0gbiA8PCB3IHdvcmRzLCB0aGlzID49IDBcbmZ1bmN0aW9uIGJucERBZGRPZmZzZXQobix3KSB7XG4gIGlmKG4gPT0gMCkgcmV0dXJuO1xuICB3aGlsZSh0aGlzLnQgPD0gdykgdGhpc1t0aGlzLnQrK10gPSAwO1xuICB0aGlzW3ddICs9IG47XG4gIHdoaWxlKHRoaXNbd10gPj0gdGhpcy5EVikge1xuICAgIHRoaXNbd10gLT0gdGhpcy5EVjtcbiAgICBpZigrK3cgPj0gdGhpcy50KSB0aGlzW3RoaXMudCsrXSA9IDA7XG4gICAgKyt0aGlzW3ddO1xuICB9XG59XG5cbi8vIEEgXCJudWxsXCIgcmVkdWNlclxuZnVuY3Rpb24gTnVsbEV4cCgpIHt9XG5mdW5jdGlvbiBuTm9wKHgpIHsgcmV0dXJuIHg7IH1cbmZ1bmN0aW9uIG5NdWxUbyh4LHkscikgeyB4Lm11bHRpcGx5VG8oeSxyKTsgfVxuZnVuY3Rpb24gblNxclRvKHgscikgeyB4LnNxdWFyZVRvKHIpOyB9XG5cbk51bGxFeHAucHJvdG90eXBlLmNvbnZlcnQgPSBuTm9wO1xuTnVsbEV4cC5wcm90b3R5cGUucmV2ZXJ0ID0gbk5vcDtcbk51bGxFeHAucHJvdG90eXBlLm11bFRvID0gbk11bFRvO1xuTnVsbEV4cC5wcm90b3R5cGUuc3FyVG8gPSBuU3FyVG87XG5cbi8vIChwdWJsaWMpIHRoaXNeZVxuZnVuY3Rpb24gYm5Qb3coZSkgeyByZXR1cm4gdGhpcy5leHAoZSxuZXcgTnVsbEV4cCgpKTsgfVxuXG4vLyAocHJvdGVjdGVkKSByID0gbG93ZXIgbiB3b3JkcyBvZiBcInRoaXMgKiBhXCIsIGEudCA8PSBuXG4vLyBcInRoaXNcIiBzaG91bGQgYmUgdGhlIGxhcmdlciBvbmUgaWYgYXBwcm9wcmlhdGUuXG5mdW5jdGlvbiBibnBNdWx0aXBseUxvd2VyVG8oYSxuLHIpIHtcbiAgdmFyIGkgPSBNYXRoLm1pbih0aGlzLnQrYS50LG4pO1xuICByLnMgPSAwOyAvLyBhc3N1bWVzIGEsdGhpcyA+PSAwXG4gIHIudCA9IGk7XG4gIHdoaWxlKGkgPiAwKSByWy0taV0gPSAwO1xuICB2YXIgajtcbiAgZm9yKGogPSByLnQtdGhpcy50OyBpIDwgajsgKytpKSByW2krdGhpcy50XSA9IHRoaXMuYW0oMCxhW2ldLHIsaSwwLHRoaXMudCk7XG4gIGZvcihqID0gTWF0aC5taW4oYS50LG4pOyBpIDwgajsgKytpKSB0aGlzLmFtKDAsYVtpXSxyLGksMCxuLWkpO1xuICByLmNsYW1wKCk7XG59XG5cbi8vIChwcm90ZWN0ZWQpIHIgPSBcInRoaXMgKiBhXCIgd2l0aG91dCBsb3dlciBuIHdvcmRzLCBuID4gMFxuLy8gXCJ0aGlzXCIgc2hvdWxkIGJlIHRoZSBsYXJnZXIgb25lIGlmIGFwcHJvcHJpYXRlLlxuZnVuY3Rpb24gYm5wTXVsdGlwbHlVcHBlclRvKGEsbixyKSB7XG4gIC0tbjtcbiAgdmFyIGkgPSByLnQgPSB0aGlzLnQrYS50LW47XG4gIHIucyA9IDA7IC8vIGFzc3VtZXMgYSx0aGlzID49IDBcbiAgd2hpbGUoLS1pID49IDApIHJbaV0gPSAwO1xuICBmb3IoaSA9IE1hdGgubWF4KG4tdGhpcy50LDApOyBpIDwgYS50OyArK2kpXG4gICAgclt0aGlzLnQraS1uXSA9IHRoaXMuYW0obi1pLGFbaV0sciwwLDAsdGhpcy50K2ktbik7XG4gIHIuY2xhbXAoKTtcbiAgci5kclNoaWZ0VG8oMSxyKTtcbn1cblxuLy8gQmFycmV0dCBtb2R1bGFyIHJlZHVjdGlvblxuZnVuY3Rpb24gQmFycmV0dChtKSB7XG4gIC8vIHNldHVwIEJhcnJldHRcbiAgdGhpcy5yMiA9IG5iaSgpO1xuICB0aGlzLnEzID0gbmJpKCk7XG4gIEJpZ0ludGVnZXIuT05FLmRsU2hpZnRUbygyKm0udCx0aGlzLnIyKTtcbiAgdGhpcy5tdSA9IHRoaXMucjIuZGl2aWRlKG0pO1xuICB0aGlzLm0gPSBtO1xufVxuXG5mdW5jdGlvbiBiYXJyZXR0Q29udmVydCh4KSB7XG4gIGlmKHgucyA8IDAgfHwgeC50ID4gMip0aGlzLm0udCkgcmV0dXJuIHgubW9kKHRoaXMubSk7XG4gIGVsc2UgaWYoeC5jb21wYXJlVG8odGhpcy5tKSA8IDApIHJldHVybiB4O1xuICBlbHNlIHsgdmFyIHIgPSBuYmkoKTsgeC5jb3B5VG8ocik7IHRoaXMucmVkdWNlKHIpOyByZXR1cm4gcjsgfVxufVxuXG5mdW5jdGlvbiBiYXJyZXR0UmV2ZXJ0KHgpIHsgcmV0dXJuIHg7IH1cblxuLy8geCA9IHggbW9kIG0gKEhBQyAxNC40MilcbmZ1bmN0aW9uIGJhcnJldHRSZWR1Y2UoeCkge1xuICB4LmRyU2hpZnRUbyh0aGlzLm0udC0xLHRoaXMucjIpO1xuICBpZih4LnQgPiB0aGlzLm0udCsxKSB7IHgudCA9IHRoaXMubS50KzE7IHguY2xhbXAoKTsgfVxuICB0aGlzLm11Lm11bHRpcGx5VXBwZXJUbyh0aGlzLnIyLHRoaXMubS50KzEsdGhpcy5xMyk7XG4gIHRoaXMubS5tdWx0aXBseUxvd2VyVG8odGhpcy5xMyx0aGlzLm0udCsxLHRoaXMucjIpO1xuICB3aGlsZSh4LmNvbXBhcmVUbyh0aGlzLnIyKSA8IDApIHguZEFkZE9mZnNldCgxLHRoaXMubS50KzEpO1xuICB4LnN1YlRvKHRoaXMucjIseCk7XG4gIHdoaWxlKHguY29tcGFyZVRvKHRoaXMubSkgPj0gMCkgeC5zdWJUbyh0aGlzLm0seCk7XG59XG5cbi8vIHIgPSB4XjIgbW9kIG07IHggIT0gclxuZnVuY3Rpb24gYmFycmV0dFNxclRvKHgscikgeyB4LnNxdWFyZVRvKHIpOyB0aGlzLnJlZHVjZShyKTsgfVxuXG4vLyByID0geCp5IG1vZCBtOyB4LHkgIT0gclxuZnVuY3Rpb24gYmFycmV0dE11bFRvKHgseSxyKSB7IHgubXVsdGlwbHlUbyh5LHIpOyB0aGlzLnJlZHVjZShyKTsgfVxuXG5CYXJyZXR0LnByb3RvdHlwZS5jb252ZXJ0ID0gYmFycmV0dENvbnZlcnQ7XG5CYXJyZXR0LnByb3RvdHlwZS5yZXZlcnQgPSBiYXJyZXR0UmV2ZXJ0O1xuQmFycmV0dC5wcm90b3R5cGUucmVkdWNlID0gYmFycmV0dFJlZHVjZTtcbkJhcnJldHQucHJvdG90eXBlLm11bFRvID0gYmFycmV0dE11bFRvO1xuQmFycmV0dC5wcm90b3R5cGUuc3FyVG8gPSBiYXJyZXR0U3FyVG87XG5cbi8vIChwdWJsaWMpIHRoaXNeZSAlIG0gKEhBQyAxNC44NSlcbmZ1bmN0aW9uIGJuTW9kUG93KGUsbSkge1xuICB2YXIgaSA9IGUuYml0TGVuZ3RoKCksIGssIHIgPSBuYnYoMSksIHo7XG4gIGlmKGkgPD0gMCkgcmV0dXJuIHI7XG4gIGVsc2UgaWYoaSA8IDE4KSBrID0gMTtcbiAgZWxzZSBpZihpIDwgNDgpIGsgPSAzO1xuICBlbHNlIGlmKGkgPCAxNDQpIGsgPSA0O1xuICBlbHNlIGlmKGkgPCA3NjgpIGsgPSA1O1xuICBlbHNlIGsgPSA2O1xuICBpZihpIDwgOClcbiAgICB6ID0gbmV3IENsYXNzaWMobSk7XG4gIGVsc2UgaWYobS5pc0V2ZW4oKSlcbiAgICB6ID0gbmV3IEJhcnJldHQobSk7XG4gIGVsc2VcbiAgICB6ID0gbmV3IE1vbnRnb21lcnkobSk7XG5cbiAgLy8gcHJlY29tcHV0YXRpb25cbiAgdmFyIGcgPSBuZXcgQXJyYXkoKSwgbiA9IDMsIGsxID0gay0xLCBrbSA9ICgxPDxrKS0xO1xuICBnWzFdID0gei5jb252ZXJ0KHRoaXMpO1xuICBpZihrID4gMSkge1xuICAgIHZhciBnMiA9IG5iaSgpO1xuICAgIHouc3FyVG8oZ1sxXSxnMik7XG4gICAgd2hpbGUobiA8PSBrbSkge1xuICAgICAgZ1tuXSA9IG5iaSgpO1xuICAgICAgei5tdWxUbyhnMixnW24tMl0sZ1tuXSk7XG4gICAgICBuICs9IDI7XG4gICAgfVxuICB9XG5cbiAgdmFyIGogPSBlLnQtMSwgdywgaXMxID0gdHJ1ZSwgcjIgPSBuYmkoKSwgdDtcbiAgaSA9IG5iaXRzKGVbal0pLTE7XG4gIHdoaWxlKGogPj0gMCkge1xuICAgIGlmKGkgPj0gazEpIHcgPSAoZVtqXT4+KGktazEpKSZrbTtcbiAgICBlbHNlIHtcbiAgICAgIHcgPSAoZVtqXSYoKDE8PChpKzEpKS0xKSk8PChrMS1pKTtcbiAgICAgIGlmKGogPiAwKSB3IHw9IGVbai0xXT4+KHRoaXMuREIraS1rMSk7XG4gICAgfVxuXG4gICAgbiA9IGs7XG4gICAgd2hpbGUoKHcmMSkgPT0gMCkgeyB3ID4+PSAxOyAtLW47IH1cbiAgICBpZigoaSAtPSBuKSA8IDApIHsgaSArPSB0aGlzLkRCOyAtLWo7IH1cbiAgICBpZihpczEpIHtcdC8vIHJldCA9PSAxLCBkb24ndCBib3RoZXIgc3F1YXJpbmcgb3IgbXVsdGlwbHlpbmcgaXRcbiAgICAgIGdbd10uY29weVRvKHIpO1xuICAgICAgaXMxID0gZmFsc2U7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgd2hpbGUobiA+IDEpIHsgei5zcXJUbyhyLHIyKTsgei5zcXJUbyhyMixyKTsgbiAtPSAyOyB9XG4gICAgICBpZihuID4gMCkgei5zcXJUbyhyLHIyKTsgZWxzZSB7IHQgPSByOyByID0gcjI7IHIyID0gdDsgfVxuICAgICAgei5tdWxUbyhyMixnW3ddLHIpO1xuICAgIH1cblxuICAgIHdoaWxlKGogPj0gMCAmJiAoZVtqXSYoMTw8aSkpID09IDApIHtcbiAgICAgIHouc3FyVG8ocixyMik7IHQgPSByOyByID0gcjI7IHIyID0gdDtcbiAgICAgIGlmKC0taSA8IDApIHsgaSA9IHRoaXMuREItMTsgLS1qOyB9XG4gICAgfVxuICB9XG4gIHJldHVybiB6LnJldmVydChyKTtcbn1cblxuLy8gKHB1YmxpYykgZ2NkKHRoaXMsYSkgKEhBQyAxNC41NClcbmZ1bmN0aW9uIGJuR0NEKGEpIHtcbiAgdmFyIHggPSAodGhpcy5zPDApP3RoaXMubmVnYXRlKCk6dGhpcy5jbG9uZSgpO1xuICB2YXIgeSA9IChhLnM8MCk/YS5uZWdhdGUoKTphLmNsb25lKCk7XG4gIGlmKHguY29tcGFyZVRvKHkpIDwgMCkgeyB2YXIgdCA9IHg7IHggPSB5OyB5ID0gdDsgfVxuICB2YXIgaSA9IHguZ2V0TG93ZXN0U2V0Qml0KCksIGcgPSB5LmdldExvd2VzdFNldEJpdCgpO1xuICBpZihnIDwgMCkgcmV0dXJuIHg7XG4gIGlmKGkgPCBnKSBnID0gaTtcbiAgaWYoZyA+IDApIHtcbiAgICB4LnJTaGlmdFRvKGcseCk7XG4gICAgeS5yU2hpZnRUbyhnLHkpO1xuICB9XG4gIHdoaWxlKHguc2lnbnVtKCkgPiAwKSB7XG4gICAgaWYoKGkgPSB4LmdldExvd2VzdFNldEJpdCgpKSA+IDApIHguclNoaWZ0VG8oaSx4KTtcbiAgICBpZigoaSA9IHkuZ2V0TG93ZXN0U2V0Qml0KCkpID4gMCkgeS5yU2hpZnRUbyhpLHkpO1xuICAgIGlmKHguY29tcGFyZVRvKHkpID49IDApIHtcbiAgICAgIHguc3ViVG8oeSx4KTtcbiAgICAgIHguclNoaWZ0VG8oMSx4KTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICB5LnN1YlRvKHgseSk7XG4gICAgICB5LnJTaGlmdFRvKDEseSk7XG4gICAgfVxuICB9XG4gIGlmKGcgPiAwKSB5LmxTaGlmdFRvKGcseSk7XG4gIHJldHVybiB5O1xufVxuXG4vLyAocHJvdGVjdGVkKSB0aGlzICUgbiwgbiA8IDJeMjZcbmZ1bmN0aW9uIGJucE1vZEludChuKSB7XG4gIGlmKG4gPD0gMCkgcmV0dXJuIDA7XG4gIHZhciBkID0gdGhpcy5EViVuLCByID0gKHRoaXMuczwwKT9uLTE6MDtcbiAgaWYodGhpcy50ID4gMClcbiAgICBpZihkID09IDApIHIgPSB0aGlzWzBdJW47XG4gICAgZWxzZSBmb3IodmFyIGkgPSB0aGlzLnQtMTsgaSA+PSAwOyAtLWkpIHIgPSAoZCpyK3RoaXNbaV0pJW47XG4gIHJldHVybiByO1xufVxuXG4vLyAocHVibGljKSAxL3RoaXMgJSBtIChIQUMgMTQuNjEpXG5mdW5jdGlvbiBibk1vZEludmVyc2UobSkge1xuICB2YXIgYWMgPSBtLmlzRXZlbigpO1xuICBpZigodGhpcy5pc0V2ZW4oKSAmJiBhYykgfHwgbS5zaWdudW0oKSA9PSAwKSByZXR1cm4gQmlnSW50ZWdlci5aRVJPO1xuICB2YXIgdSA9IG0uY2xvbmUoKSwgdiA9IHRoaXMuY2xvbmUoKTtcbiAgdmFyIGEgPSBuYnYoMSksIGIgPSBuYnYoMCksIGMgPSBuYnYoMCksIGQgPSBuYnYoMSk7XG4gIHdoaWxlKHUuc2lnbnVtKCkgIT0gMCkge1xuICAgIHdoaWxlKHUuaXNFdmVuKCkpIHtcbiAgICAgIHUuclNoaWZ0VG8oMSx1KTtcbiAgICAgIGlmKGFjKSB7XG4gICAgICAgIGlmKCFhLmlzRXZlbigpIHx8ICFiLmlzRXZlbigpKSB7IGEuYWRkVG8odGhpcyxhKTsgYi5zdWJUbyhtLGIpOyB9XG4gICAgICAgIGEuclNoaWZ0VG8oMSxhKTtcbiAgICAgIH1cbiAgICAgIGVsc2UgaWYoIWIuaXNFdmVuKCkpIGIuc3ViVG8obSxiKTtcbiAgICAgIGIuclNoaWZ0VG8oMSxiKTtcbiAgICB9XG4gICAgd2hpbGUodi5pc0V2ZW4oKSkge1xuICAgICAgdi5yU2hpZnRUbygxLHYpO1xuICAgICAgaWYoYWMpIHtcbiAgICAgICAgaWYoIWMuaXNFdmVuKCkgfHwgIWQuaXNFdmVuKCkpIHsgYy5hZGRUbyh0aGlzLGMpOyBkLnN1YlRvKG0sZCk7IH1cbiAgICAgICAgYy5yU2hpZnRUbygxLGMpO1xuICAgICAgfVxuICAgICAgZWxzZSBpZighZC5pc0V2ZW4oKSkgZC5zdWJUbyhtLGQpO1xuICAgICAgZC5yU2hpZnRUbygxLGQpO1xuICAgIH1cbiAgICBpZih1LmNvbXBhcmVUbyh2KSA+PSAwKSB7XG4gICAgICB1LnN1YlRvKHYsdSk7XG4gICAgICBpZihhYykgYS5zdWJUbyhjLGEpO1xuICAgICAgYi5zdWJUbyhkLGIpO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgIHYuc3ViVG8odSx2KTtcbiAgICAgIGlmKGFjKSBjLnN1YlRvKGEsYyk7XG4gICAgICBkLnN1YlRvKGIsZCk7XG4gICAgfVxuICB9XG4gIGlmKHYuY29tcGFyZVRvKEJpZ0ludGVnZXIuT05FKSAhPSAwKSByZXR1cm4gQmlnSW50ZWdlci5aRVJPO1xuICBpZihkLmNvbXBhcmVUbyhtKSA+PSAwKSByZXR1cm4gZC5zdWJ0cmFjdChtKTtcbiAgaWYoZC5zaWdudW0oKSA8IDApIGQuYWRkVG8obSxkKTsgZWxzZSByZXR1cm4gZDtcbiAgaWYoZC5zaWdudW0oKSA8IDApIHJldHVybiBkLmFkZChtKTsgZWxzZSByZXR1cm4gZDtcbn1cblxudmFyIGxvd3ByaW1lcyA9IFsyLDMsNSw3LDExLDEzLDE3LDE5LDIzLDI5LDMxLDM3LDQxLDQzLDQ3LDUzLDU5LDYxLDY3LDcxLDczLDc5LDgzLDg5LDk3LDEwMSwxMDMsMTA3LDEwOSwxMTMsMTI3LDEzMSwxMzcsMTM5LDE0OSwxNTEsMTU3LDE2MywxNjcsMTczLDE3OSwxODEsMTkxLDE5MywxOTcsMTk5LDIxMSwyMjMsMjI3LDIyOSwyMzMsMjM5LDI0MSwyNTEsMjU3LDI2MywyNjksMjcxLDI3NywyODEsMjgzLDI5MywzMDcsMzExLDMxMywzMTcsMzMxLDMzNywzNDcsMzQ5LDM1MywzNTksMzY3LDM3MywzNzksMzgzLDM4OSwzOTcsNDAxLDQwOSw0MTksNDIxLDQzMSw0MzMsNDM5LDQ0Myw0NDksNDU3LDQ2MSw0NjMsNDY3LDQ3OSw0ODcsNDkxLDQ5OSw1MDMsNTA5LDUyMSw1MjMsNTQxLDU0Nyw1NTcsNTYzLDU2OSw1NzEsNTc3LDU4Nyw1OTMsNTk5LDYwMSw2MDcsNjEzLDYxNyw2MTksNjMxLDY0MSw2NDMsNjQ3LDY1Myw2NTksNjYxLDY3Myw2NzcsNjgzLDY5MSw3MDEsNzA5LDcxOSw3MjcsNzMzLDczOSw3NDMsNzUxLDc1Nyw3NjEsNzY5LDc3Myw3ODcsNzk3LDgwOSw4MTEsODIxLDgyMyw4MjcsODI5LDgzOSw4NTMsODU3LDg1OSw4NjMsODc3LDg4MSw4ODMsODg3LDkwNyw5MTEsOTE5LDkyOSw5MzcsOTQxLDk0Nyw5NTMsOTY3LDk3MSw5NzcsOTgzLDk5MSw5OTddO1xudmFyIGxwbGltID0gKDE8PDI2KS9sb3dwcmltZXNbbG93cHJpbWVzLmxlbmd0aC0xXTtcblxuLy8gKHB1YmxpYykgdGVzdCBwcmltYWxpdHkgd2l0aCBjZXJ0YWludHkgPj0gMS0uNV50XG5mdW5jdGlvbiBibklzUHJvYmFibGVQcmltZSh0KSB7XG4gIHZhciBpLCB4ID0gdGhpcy5hYnMoKTtcbiAgaWYoeC50ID09IDEgJiYgeFswXSA8PSBsb3dwcmltZXNbbG93cHJpbWVzLmxlbmd0aC0xXSkge1xuICAgIGZvcihpID0gMDsgaSA8IGxvd3ByaW1lcy5sZW5ndGg7ICsraSlcbiAgICAgIGlmKHhbMF0gPT0gbG93cHJpbWVzW2ldKSByZXR1cm4gdHJ1ZTtcbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cbiAgaWYoeC5pc0V2ZW4oKSkgcmV0dXJuIGZhbHNlO1xuICBpID0gMTtcbiAgd2hpbGUoaSA8IGxvd3ByaW1lcy5sZW5ndGgpIHtcbiAgICB2YXIgbSA9IGxvd3ByaW1lc1tpXSwgaiA9IGkrMTtcbiAgICB3aGlsZShqIDwgbG93cHJpbWVzLmxlbmd0aCAmJiBtIDwgbHBsaW0pIG0gKj0gbG93cHJpbWVzW2orK107XG4gICAgbSA9IHgubW9kSW50KG0pO1xuICAgIHdoaWxlKGkgPCBqKSBpZihtJWxvd3ByaW1lc1tpKytdID09IDApIHJldHVybiBmYWxzZTtcbiAgfVxuICByZXR1cm4geC5taWxsZXJSYWJpbih0KTtcbn1cblxuLy8gKHByb3RlY3RlZCkgdHJ1ZSBpZiBwcm9iYWJseSBwcmltZSAoSEFDIDQuMjQsIE1pbGxlci1SYWJpbilcbmZ1bmN0aW9uIGJucE1pbGxlclJhYmluKHQpIHtcbiAgdmFyIG4xID0gdGhpcy5zdWJ0cmFjdChCaWdJbnRlZ2VyLk9ORSk7XG4gIHZhciBrID0gbjEuZ2V0TG93ZXN0U2V0Qml0KCk7XG4gIGlmKGsgPD0gMCkgcmV0dXJuIGZhbHNlO1xuICB2YXIgciA9IG4xLnNoaWZ0UmlnaHQoayk7XG4gIHQgPSAodCsxKT4+MTtcbiAgaWYodCA+IGxvd3ByaW1lcy5sZW5ndGgpIHQgPSBsb3dwcmltZXMubGVuZ3RoO1xuICB2YXIgYSA9IG5iaSgpO1xuICBmb3IodmFyIGkgPSAwOyBpIDwgdDsgKytpKSB7XG4gICAgLy9QaWNrIGJhc2VzIGF0IHJhbmRvbSwgaW5zdGVhZCBvZiBzdGFydGluZyBhdCAyXG4gICAgYS5mcm9tSW50KGxvd3ByaW1lc1tNYXRoLmZsb29yKE1hdGgucmFuZG9tKCkqbG93cHJpbWVzLmxlbmd0aCldKTtcbiAgICB2YXIgeSA9IGEubW9kUG93KHIsdGhpcyk7XG4gICAgaWYoeS5jb21wYXJlVG8oQmlnSW50ZWdlci5PTkUpICE9IDAgJiYgeS5jb21wYXJlVG8objEpICE9IDApIHtcbiAgICAgIHZhciBqID0gMTtcbiAgICAgIHdoaWxlKGorKyA8IGsgJiYgeS5jb21wYXJlVG8objEpICE9IDApIHtcbiAgICAgICAgeSA9IHkubW9kUG93SW50KDIsdGhpcyk7XG4gICAgICAgIGlmKHkuY29tcGFyZVRvKEJpZ0ludGVnZXIuT05FKSA9PSAwKSByZXR1cm4gZmFsc2U7XG4gICAgICB9XG4gICAgICBpZih5LmNvbXBhcmVUbyhuMSkgIT0gMCkgcmV0dXJuIGZhbHNlO1xuICAgIH1cbiAgfVxuICByZXR1cm4gdHJ1ZTtcbn1cblxuLy8gcHJvdGVjdGVkXG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5jaHVua1NpemUgPSBibnBDaHVua1NpemU7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS50b1JhZGl4ID0gYm5wVG9SYWRpeDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmZyb21SYWRpeCA9IGJucEZyb21SYWRpeDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmZyb21OdW1iZXIgPSBibnBGcm9tTnVtYmVyO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuYml0d2lzZVRvID0gYm5wQml0d2lzZVRvO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuY2hhbmdlQml0ID0gYm5wQ2hhbmdlQml0O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuYWRkVG8gPSBibnBBZGRUbztcbkJpZ0ludGVnZXIucHJvdG90eXBlLmRNdWx0aXBseSA9IGJucERNdWx0aXBseTtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmRBZGRPZmZzZXQgPSBibnBEQWRkT2Zmc2V0O1xuQmlnSW50ZWdlci5wcm90b3R5cGUubXVsdGlwbHlMb3dlclRvID0gYm5wTXVsdGlwbHlMb3dlclRvO1xuQmlnSW50ZWdlci5wcm90b3R5cGUubXVsdGlwbHlVcHBlclRvID0gYm5wTXVsdGlwbHlVcHBlclRvO1xuQmlnSW50ZWdlci5wcm90b3R5cGUubW9kSW50ID0gYm5wTW9kSW50O1xuQmlnSW50ZWdlci5wcm90b3R5cGUubWlsbGVyUmFiaW4gPSBibnBNaWxsZXJSYWJpbjtcblxuLy8gcHVibGljXG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5jbG9uZSA9IGJuQ2xvbmU7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5pbnRWYWx1ZSA9IGJuSW50VmFsdWU7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5ieXRlVmFsdWUgPSBibkJ5dGVWYWx1ZTtcbkJpZ0ludGVnZXIucHJvdG90eXBlLnNob3J0VmFsdWUgPSBiblNob3J0VmFsdWU7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5zaWdudW0gPSBiblNpZ051bTtcbkJpZ0ludGVnZXIucHJvdG90eXBlLnRvQnl0ZUFycmF5ID0gYm5Ub0J5dGVBcnJheTtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmVxdWFscyA9IGJuRXF1YWxzO1xuQmlnSW50ZWdlci5wcm90b3R5cGUubWluID0gYm5NaW47XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5tYXggPSBibk1heDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmFuZCA9IGJuQW5kO1xuQmlnSW50ZWdlci5wcm90b3R5cGUub3IgPSBibk9yO1xuQmlnSW50ZWdlci5wcm90b3R5cGUueG9yID0gYm5Yb3I7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5hbmROb3QgPSBibkFuZE5vdDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLm5vdCA9IGJuTm90O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuc2hpZnRMZWZ0ID0gYm5TaGlmdExlZnQ7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5zaGlmdFJpZ2h0ID0gYm5TaGlmdFJpZ2h0O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZ2V0TG93ZXN0U2V0Qml0ID0gYm5HZXRMb3dlc3RTZXRCaXQ7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5iaXRDb3VudCA9IGJuQml0Q291bnQ7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS50ZXN0Qml0ID0gYm5UZXN0Qml0O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuc2V0Qml0ID0gYm5TZXRCaXQ7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5jbGVhckJpdCA9IGJuQ2xlYXJCaXQ7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5mbGlwQml0ID0gYm5GbGlwQml0O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuYWRkID0gYm5BZGQ7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5zdWJ0cmFjdCA9IGJuU3VidHJhY3Q7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5tdWx0aXBseSA9IGJuTXVsdGlwbHk7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5kaXZpZGUgPSBibkRpdmlkZTtcbkJpZ0ludGVnZXIucHJvdG90eXBlLnJlbWFpbmRlciA9IGJuUmVtYWluZGVyO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZGl2aWRlQW5kUmVtYWluZGVyID0gYm5EaXZpZGVBbmRSZW1haW5kZXI7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5tb2RQb3cgPSBibk1vZFBvdztcbkJpZ0ludGVnZXIucHJvdG90eXBlLm1vZEludmVyc2UgPSBibk1vZEludmVyc2U7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5wb3cgPSBiblBvdztcbkJpZ0ludGVnZXIucHJvdG90eXBlLmdjZCA9IGJuR0NEO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuaXNQcm9iYWJsZVByaW1lID0gYm5Jc1Byb2JhYmxlUHJpbWU7XG5cbi8vIEpTQk4tc3BlY2lmaWMgZXh0ZW5zaW9uXG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5zcXVhcmUgPSBiblNxdWFyZTtcblxuLy8gQmlnSW50ZWdlciBpbnRlcmZhY2VzIG5vdCBpbXBsZW1lbnRlZCBpbiBqc2JuOlxuXG4vLyBCaWdJbnRlZ2VyKGludCBzaWdudW0sIGJ5dGVbXSBtYWduaXR1ZGUpXG4vLyBkb3VibGUgZG91YmxlVmFsdWUoKVxuLy8gZmxvYXQgZmxvYXRWYWx1ZSgpXG4vLyBpbnQgaGFzaENvZGUoKVxuLy8gbG9uZyBsb25nVmFsdWUoKVxuLy8gc3RhdGljIEJpZ0ludGVnZXIgdmFsdWVPZihsb25nIHZhbClcblxuLy8gcHJuZzQuanMgLSB1c2VzIEFyY2ZvdXIgYXMgYSBQUk5HXG5cbmZ1bmN0aW9uIEFyY2ZvdXIoKSB7XG4gIHRoaXMuaSA9IDA7XG4gIHRoaXMuaiA9IDA7XG4gIHRoaXMuUyA9IG5ldyBBcnJheSgpO1xufVxuXG4vLyBJbml0aWFsaXplIGFyY2ZvdXIgY29udGV4dCBmcm9tIGtleSwgYW4gYXJyYXkgb2YgaW50cywgZWFjaCBmcm9tIFswLi4yNTVdXG5mdW5jdGlvbiBBUkM0aW5pdChrZXkpIHtcbiAgdmFyIGksIGosIHQ7XG4gIGZvcihpID0gMDsgaSA8IDI1NjsgKytpKVxuICAgIHRoaXMuU1tpXSA9IGk7XG4gIGogPSAwO1xuICBmb3IoaSA9IDA7IGkgPCAyNTY7ICsraSkge1xuICAgIGogPSAoaiArIHRoaXMuU1tpXSArIGtleVtpICUga2V5Lmxlbmd0aF0pICYgMjU1O1xuICAgIHQgPSB0aGlzLlNbaV07XG4gICAgdGhpcy5TW2ldID0gdGhpcy5TW2pdO1xuICAgIHRoaXMuU1tqXSA9IHQ7XG4gIH1cbiAgdGhpcy5pID0gMDtcbiAgdGhpcy5qID0gMDtcbn1cblxuZnVuY3Rpb24gQVJDNG5leHQoKSB7XG4gIHZhciB0O1xuICB0aGlzLmkgPSAodGhpcy5pICsgMSkgJiAyNTU7XG4gIHRoaXMuaiA9ICh0aGlzLmogKyB0aGlzLlNbdGhpcy5pXSkgJiAyNTU7XG4gIHQgPSB0aGlzLlNbdGhpcy5pXTtcbiAgdGhpcy5TW3RoaXMuaV0gPSB0aGlzLlNbdGhpcy5qXTtcbiAgdGhpcy5TW3RoaXMual0gPSB0O1xuICByZXR1cm4gdGhpcy5TWyh0ICsgdGhpcy5TW3RoaXMuaV0pICYgMjU1XTtcbn1cblxuQXJjZm91ci5wcm90b3R5cGUuaW5pdCA9IEFSQzRpbml0O1xuQXJjZm91ci5wcm90b3R5cGUubmV4dCA9IEFSQzRuZXh0O1xuXG4vLyBQbHVnIGluIHlvdXIgUk5HIGNvbnN0cnVjdG9yIGhlcmVcbmZ1bmN0aW9uIHBybmdfbmV3c3RhdGUoKSB7XG4gIHJldHVybiBuZXcgQXJjZm91cigpO1xufVxuXG4vLyBQb29sIHNpemUgbXVzdCBiZSBhIG11bHRpcGxlIG9mIDQgYW5kIGdyZWF0ZXIgdGhhbiAzMi5cbi8vIEFuIGFycmF5IG9mIGJ5dGVzIHRoZSBzaXplIG9mIHRoZSBwb29sIHdpbGwgYmUgcGFzc2VkIHRvIGluaXQoKVxudmFyIHJuZ19wc2l6ZSA9IDI1NjtcblxuLy8gUmFuZG9tIG51bWJlciBnZW5lcmF0b3IgLSByZXF1aXJlcyBhIFBSTkcgYmFja2VuZCwgZS5nLiBwcm5nNC5qc1xudmFyIHJuZ19zdGF0ZTtcbnZhciBybmdfcG9vbDtcbnZhciBybmdfcHB0cjtcblxuLy8gSW5pdGlhbGl6ZSB0aGUgcG9vbCB3aXRoIGp1bmsgaWYgbmVlZGVkLlxuaWYocm5nX3Bvb2wgPT0gbnVsbCkge1xuICBybmdfcG9vbCA9IG5ldyBBcnJheSgpO1xuICBybmdfcHB0ciA9IDA7XG4gIHZhciB0O1xuICBpZih3aW5kb3cuY3J5cHRvICYmIHdpbmRvdy5jcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKSB7XG4gICAgLy8gRXh0cmFjdCBlbnRyb3B5ICgyMDQ4IGJpdHMpIGZyb20gUk5HIGlmIGF2YWlsYWJsZVxuICAgIHZhciB6ID0gbmV3IFVpbnQzMkFycmF5KDI1Nik7XG4gICAgd2luZG93LmNyeXB0by5nZXRSYW5kb21WYWx1ZXMoeik7XG4gICAgZm9yICh0ID0gMDsgdCA8IHoubGVuZ3RoOyArK3QpXG4gICAgICBybmdfcG9vbFtybmdfcHB0cisrXSA9IHpbdF0gJiAyNTU7XG4gIH1cblxuICAvLyBVc2UgbW91c2UgZXZlbnRzIGZvciBlbnRyb3B5LCBpZiB3ZSBkbyBub3QgaGF2ZSBlbm91Z2ggZW50cm9weSBieSB0aGUgdGltZVxuICAvLyB3ZSBuZWVkIGl0LCBlbnRyb3B5IHdpbGwgYmUgZ2VuZXJhdGVkIGJ5IE1hdGgucmFuZG9tLlxuICB2YXIgb25Nb3VzZU1vdmVMaXN0ZW5lciA9IGZ1bmN0aW9uKGV2KSB7XG4gICAgdGhpcy5jb3VudCA9IHRoaXMuY291bnQgfHwgMDtcbiAgICBpZiAodGhpcy5jb3VudCA+PSAyNTYgfHwgcm5nX3BwdHIgPj0gcm5nX3BzaXplKSB7XG4gICAgICBpZiAod2luZG93LnJlbW92ZUV2ZW50TGlzdGVuZXIpXG4gICAgICAgIHdpbmRvdy5yZW1vdmVFdmVudExpc3RlbmVyKFwibW91c2Vtb3ZlXCIsIG9uTW91c2VNb3ZlTGlzdGVuZXIsIGZhbHNlKTtcbiAgICAgIGVsc2UgaWYgKHdpbmRvdy5kZXRhY2hFdmVudClcbiAgICAgICAgd2luZG93LmRldGFjaEV2ZW50KFwib25tb3VzZW1vdmVcIiwgb25Nb3VzZU1vdmVMaXN0ZW5lcik7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIHRyeSB7XG4gICAgICB2YXIgbW91c2VDb29yZGluYXRlcyA9IGV2LnggKyBldi55O1xuICAgICAgcm5nX3Bvb2xbcm5nX3BwdHIrK10gPSBtb3VzZUNvb3JkaW5hdGVzICYgMjU1O1xuICAgICAgdGhpcy5jb3VudCArPSAxO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIC8vIFNvbWV0aW1lcyBGaXJlZm94IHdpbGwgZGVueSBwZXJtaXNzaW9uIHRvIGFjY2VzcyBldmVudCBwcm9wZXJ0aWVzIGZvciBzb21lIHJlYXNvbi4gSWdub3JlLlxuICAgIH1cbiAgfTtcbiAgaWYgKHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKVxuICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKFwibW91c2Vtb3ZlXCIsIG9uTW91c2VNb3ZlTGlzdGVuZXIsIGZhbHNlKTtcbiAgZWxzZSBpZiAod2luZG93LmF0dGFjaEV2ZW50KVxuICAgIHdpbmRvdy5hdHRhY2hFdmVudChcIm9ubW91c2Vtb3ZlXCIsIG9uTW91c2VNb3ZlTGlzdGVuZXIpO1xuXG59XG5cbmZ1bmN0aW9uIHJuZ19nZXRfYnl0ZSgpIHtcbiAgaWYocm5nX3N0YXRlID09IG51bGwpIHtcbiAgICBybmdfc3RhdGUgPSBwcm5nX25ld3N0YXRlKCk7XG4gICAgLy8gQXQgdGhpcyBwb2ludCwgd2UgbWF5IG5vdCBoYXZlIGNvbGxlY3RlZCBlbm91Z2ggZW50cm9weS4gIElmIG5vdCwgZmFsbCBiYWNrIHRvIE1hdGgucmFuZG9tXG4gICAgd2hpbGUgKHJuZ19wcHRyIDwgcm5nX3BzaXplKSB7XG4gICAgICB2YXIgcmFuZG9tID0gTWF0aC5mbG9vcig2NTUzNiAqIE1hdGgucmFuZG9tKCkpO1xuICAgICAgcm5nX3Bvb2xbcm5nX3BwdHIrK10gPSByYW5kb20gJiAyNTU7XG4gICAgfVxuICAgIHJuZ19zdGF0ZS5pbml0KHJuZ19wb29sKTtcbiAgICBmb3Iocm5nX3BwdHIgPSAwOyBybmdfcHB0ciA8IHJuZ19wb29sLmxlbmd0aDsgKytybmdfcHB0cilcbiAgICAgIHJuZ19wb29sW3JuZ19wcHRyXSA9IDA7XG4gICAgcm5nX3BwdHIgPSAwO1xuICB9XG4gIC8vIFRPRE86IGFsbG93IHJlc2VlZGluZyBhZnRlciBmaXJzdCByZXF1ZXN0XG4gIHJldHVybiBybmdfc3RhdGUubmV4dCgpO1xufVxuXG5mdW5jdGlvbiBybmdfZ2V0X2J5dGVzKGJhKSB7XG4gIHZhciBpO1xuICBmb3IoaSA9IDA7IGkgPCBiYS5sZW5ndGg7ICsraSkgYmFbaV0gPSBybmdfZ2V0X2J5dGUoKTtcbn1cblxuZnVuY3Rpb24gU2VjdXJlUmFuZG9tKCkge31cblxuU2VjdXJlUmFuZG9tLnByb3RvdHlwZS5uZXh0Qnl0ZXMgPSBybmdfZ2V0X2J5dGVzO1xuXG4vLyBEZXBlbmRzIG9uIGpzYm4uanMgYW5kIHJuZy5qc1xuXG4vLyBWZXJzaW9uIDEuMTogc3VwcG9ydCB1dGYtOCBlbmNvZGluZyBpbiBwa2NzMXBhZDJcblxuLy8gY29udmVydCBhIChoZXgpIHN0cmluZyB0byBhIGJpZ251bSBvYmplY3RcbmZ1bmN0aW9uIHBhcnNlQmlnSW50KHN0cixyKSB7XG4gIHJldHVybiBuZXcgQmlnSW50ZWdlcihzdHIscik7XG59XG5cbmZ1bmN0aW9uIGxpbmVicmsocyxuKSB7XG4gIHZhciByZXQgPSBcIlwiO1xuICB2YXIgaSA9IDA7XG4gIHdoaWxlKGkgKyBuIDwgcy5sZW5ndGgpIHtcbiAgICByZXQgKz0gcy5zdWJzdHJpbmcoaSxpK24pICsgXCJcXG5cIjtcbiAgICBpICs9IG47XG4gIH1cbiAgcmV0dXJuIHJldCArIHMuc3Vic3RyaW5nKGkscy5sZW5ndGgpO1xufVxuXG5mdW5jdGlvbiBieXRlMkhleChiKSB7XG4gIGlmKGIgPCAweDEwKVxuICAgIHJldHVybiBcIjBcIiArIGIudG9TdHJpbmcoMTYpO1xuICBlbHNlXG4gICAgcmV0dXJuIGIudG9TdHJpbmcoMTYpO1xufVxuXG4vLyBQS0NTIzEgKHR5cGUgMiwgcmFuZG9tKSBwYWQgaW5wdXQgc3RyaW5nIHMgdG8gbiBieXRlcywgYW5kIHJldHVybiBhIGJpZ2ludFxuZnVuY3Rpb24gcGtjczFwYWQyKHMsbikge1xuICBpZihuIDwgcy5sZW5ndGggKyAxMSkgeyAvLyBUT0RPOiBmaXggZm9yIHV0Zi04XG4gICAgY29uc29sZS5lcnJvcihcIk1lc3NhZ2UgdG9vIGxvbmcgZm9yIFJTQVwiKTtcbiAgICByZXR1cm4gbnVsbDtcbiAgfVxuICB2YXIgYmEgPSBuZXcgQXJyYXkoKTtcbiAgdmFyIGkgPSBzLmxlbmd0aCAtIDE7XG4gIHdoaWxlKGkgPj0gMCAmJiBuID4gMCkge1xuICAgIHZhciBjID0gcy5jaGFyQ29kZUF0KGktLSk7XG4gICAgaWYoYyA8IDEyOCkgeyAvLyBlbmNvZGUgdXNpbmcgdXRmLThcbiAgICAgIGJhWy0tbl0gPSBjO1xuICAgIH1cbiAgICBlbHNlIGlmKChjID4gMTI3KSAmJiAoYyA8IDIwNDgpKSB7XG4gICAgICBiYVstLW5dID0gKGMgJiA2MykgfCAxMjg7XG4gICAgICBiYVstLW5dID0gKGMgPj4gNikgfCAxOTI7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgYmFbLS1uXSA9IChjICYgNjMpIHwgMTI4O1xuICAgICAgYmFbLS1uXSA9ICgoYyA+PiA2KSAmIDYzKSB8IDEyODtcbiAgICAgIGJhWy0tbl0gPSAoYyA+PiAxMikgfCAyMjQ7XG4gICAgfVxuICB9XG4gIGJhWy0tbl0gPSAwO1xuICB2YXIgcm5nID0gbmV3IFNlY3VyZVJhbmRvbSgpO1xuICB2YXIgeCA9IG5ldyBBcnJheSgpO1xuICB3aGlsZShuID4gMikgeyAvLyByYW5kb20gbm9uLXplcm8gcGFkXG4gICAgeFswXSA9IDA7XG4gICAgd2hpbGUoeFswXSA9PSAwKSBybmcubmV4dEJ5dGVzKHgpO1xuICAgIGJhWy0tbl0gPSB4WzBdO1xuICB9XG4gIGJhWy0tbl0gPSAyO1xuICBiYVstLW5dID0gMDtcbiAgcmV0dXJuIG5ldyBCaWdJbnRlZ2VyKGJhKTtcbn1cblxuLy8gXCJlbXB0eVwiIFJTQSBrZXkgY29uc3RydWN0b3JcbmZ1bmN0aW9uIFJTQUtleSgpIHtcbiAgdGhpcy5uID0gbnVsbDtcbiAgdGhpcy5lID0gMDtcbiAgdGhpcy5kID0gbnVsbDtcbiAgdGhpcy5wID0gbnVsbDtcbiAgdGhpcy5xID0gbnVsbDtcbiAgdGhpcy5kbXAxID0gbnVsbDtcbiAgdGhpcy5kbXExID0gbnVsbDtcbiAgdGhpcy5jb2VmZiA9IG51bGw7XG59XG5cbi8vIFNldCB0aGUgcHVibGljIGtleSBmaWVsZHMgTiBhbmQgZSBmcm9tIGhleCBzdHJpbmdzXG5mdW5jdGlvbiBSU0FTZXRQdWJsaWMoTixFKSB7XG4gIGlmKE4gIT0gbnVsbCAmJiBFICE9IG51bGwgJiYgTi5sZW5ndGggPiAwICYmIEUubGVuZ3RoID4gMCkge1xuICAgIHRoaXMubiA9IHBhcnNlQmlnSW50KE4sMTYpO1xuICAgIHRoaXMuZSA9IHBhcnNlSW50KEUsMTYpO1xuICB9XG4gIGVsc2VcbiAgICBjb25zb2xlLmVycm9yKFwiSW52YWxpZCBSU0EgcHVibGljIGtleVwiKTtcbn1cblxuLy8gUGVyZm9ybSByYXcgcHVibGljIG9wZXJhdGlvbiBvbiBcInhcIjogcmV0dXJuIHheZSAobW9kIG4pXG5mdW5jdGlvbiBSU0FEb1B1YmxpYyh4KSB7XG4gIHJldHVybiB4Lm1vZFBvd0ludCh0aGlzLmUsIHRoaXMubik7XG59XG5cbi8vIFJldHVybiB0aGUgUEtDUyMxIFJTQSBlbmNyeXB0aW9uIG9mIFwidGV4dFwiIGFzIGFuIGV2ZW4tbGVuZ3RoIGhleCBzdHJpbmdcbmZ1bmN0aW9uIFJTQUVuY3J5cHQodGV4dCkge1xuICB2YXIgbSA9IHBrY3MxcGFkMih0ZXh0LCh0aGlzLm4uYml0TGVuZ3RoKCkrNyk+PjMpO1xuICBpZihtID09IG51bGwpIHJldHVybiBudWxsO1xuICB2YXIgYyA9IHRoaXMuZG9QdWJsaWMobSk7XG4gIGlmKGMgPT0gbnVsbCkgcmV0dXJuIG51bGw7XG4gIHZhciBoID0gYy50b1N0cmluZygxNik7XG4gIGlmKChoLmxlbmd0aCAmIDEpID09IDApIHJldHVybiBoOyBlbHNlIHJldHVybiBcIjBcIiArIGg7XG59XG5cbi8vIFJldHVybiB0aGUgUEtDUyMxIFJTQSBlbmNyeXB0aW9uIG9mIFwidGV4dFwiIGFzIGEgQmFzZTY0LWVuY29kZWQgc3RyaW5nXG4vL2Z1bmN0aW9uIFJTQUVuY3J5cHRCNjQodGV4dCkge1xuLy8gIHZhciBoID0gdGhpcy5lbmNyeXB0KHRleHQpO1xuLy8gIGlmKGgpIHJldHVybiBoZXgyYjY0KGgpOyBlbHNlIHJldHVybiBudWxsO1xuLy99XG5cbi8vIHByb3RlY3RlZFxuUlNBS2V5LnByb3RvdHlwZS5kb1B1YmxpYyA9IFJTQURvUHVibGljO1xuXG4vLyBwdWJsaWNcblJTQUtleS5wcm90b3R5cGUuc2V0UHVibGljID0gUlNBU2V0UHVibGljO1xuUlNBS2V5LnByb3RvdHlwZS5lbmNyeXB0ID0gUlNBRW5jcnlwdDtcbi8vUlNBS2V5LnByb3RvdHlwZS5lbmNyeXB0X2I2NCA9IFJTQUVuY3J5cHRCNjQ7XG5cbi8vIERlcGVuZHMgb24gcnNhLmpzIGFuZCBqc2JuMi5qc1xuXG4vLyBWZXJzaW9uIDEuMTogc3VwcG9ydCB1dGYtOCBkZWNvZGluZyBpbiBwa2NzMXVucGFkMlxuXG4vLyBVbmRvIFBLQ1MjMSAodHlwZSAyLCByYW5kb20pIHBhZGRpbmcgYW5kLCBpZiB2YWxpZCwgcmV0dXJuIHRoZSBwbGFpbnRleHRcbmZ1bmN0aW9uIHBrY3MxdW5wYWQyKGQsbikge1xuICB2YXIgYiA9IGQudG9CeXRlQXJyYXkoKTtcbiAgdmFyIGkgPSAwO1xuICB3aGlsZShpIDwgYi5sZW5ndGggJiYgYltpXSA9PSAwKSArK2k7XG4gIGlmKGIubGVuZ3RoLWkgIT0gbi0xIHx8IGJbaV0gIT0gMilcbiAgICByZXR1cm4gbnVsbDtcbiAgKytpO1xuICB3aGlsZShiW2ldICE9IDApXG4gICAgaWYoKytpID49IGIubGVuZ3RoKSByZXR1cm4gbnVsbDtcbiAgdmFyIHJldCA9IFwiXCI7XG4gIHdoaWxlKCsraSA8IGIubGVuZ3RoKSB7XG4gICAgdmFyIGMgPSBiW2ldICYgMjU1O1xuICAgIGlmKGMgPCAxMjgpIHsgLy8gdXRmLTggZGVjb2RlXG4gICAgICByZXQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShjKTtcbiAgICB9XG4gICAgZWxzZSBpZigoYyA+IDE5MSkgJiYgKGMgPCAyMjQpKSB7XG4gICAgICByZXQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSgoKGMgJiAzMSkgPDwgNikgfCAoYltpKzFdICYgNjMpKTtcbiAgICAgICsraTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICByZXQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSgoKGMgJiAxNSkgPDwgMTIpIHwgKChiW2krMV0gJiA2MykgPDwgNikgfCAoYltpKzJdICYgNjMpKTtcbiAgICAgIGkgKz0gMjtcbiAgICB9XG4gIH1cbiAgcmV0dXJuIHJldDtcbn1cblxuLy8gU2V0IHRoZSBwcml2YXRlIGtleSBmaWVsZHMgTiwgZSwgYW5kIGQgZnJvbSBoZXggc3RyaW5nc1xuZnVuY3Rpb24gUlNBU2V0UHJpdmF0ZShOLEUsRCkge1xuICBpZihOICE9IG51bGwgJiYgRSAhPSBudWxsICYmIE4ubGVuZ3RoID4gMCAmJiBFLmxlbmd0aCA+IDApIHtcbiAgICB0aGlzLm4gPSBwYXJzZUJpZ0ludChOLDE2KTtcbiAgICB0aGlzLmUgPSBwYXJzZUludChFLDE2KTtcbiAgICB0aGlzLmQgPSBwYXJzZUJpZ0ludChELDE2KTtcbiAgfVxuICBlbHNlXG4gICAgY29uc29sZS5lcnJvcihcIkludmFsaWQgUlNBIHByaXZhdGUga2V5XCIpO1xufVxuXG4vLyBTZXQgdGhlIHByaXZhdGUga2V5IGZpZWxkcyBOLCBlLCBkIGFuZCBDUlQgcGFyYW1zIGZyb20gaGV4IHN0cmluZ3NcbmZ1bmN0aW9uIFJTQVNldFByaXZhdGVFeChOLEUsRCxQLFEsRFAsRFEsQykge1xuICBpZihOICE9IG51bGwgJiYgRSAhPSBudWxsICYmIE4ubGVuZ3RoID4gMCAmJiBFLmxlbmd0aCA+IDApIHtcbiAgICB0aGlzLm4gPSBwYXJzZUJpZ0ludChOLDE2KTtcbiAgICB0aGlzLmUgPSBwYXJzZUludChFLDE2KTtcbiAgICB0aGlzLmQgPSBwYXJzZUJpZ0ludChELDE2KTtcbiAgICB0aGlzLnAgPSBwYXJzZUJpZ0ludChQLDE2KTtcbiAgICB0aGlzLnEgPSBwYXJzZUJpZ0ludChRLDE2KTtcbiAgICB0aGlzLmRtcDEgPSBwYXJzZUJpZ0ludChEUCwxNik7XG4gICAgdGhpcy5kbXExID0gcGFyc2VCaWdJbnQoRFEsMTYpO1xuICAgIHRoaXMuY29lZmYgPSBwYXJzZUJpZ0ludChDLDE2KTtcbiAgfVxuICBlbHNlXG4gICAgY29uc29sZS5lcnJvcihcIkludmFsaWQgUlNBIHByaXZhdGUga2V5XCIpO1xufVxuXG4vLyBHZW5lcmF0ZSBhIG5ldyByYW5kb20gcHJpdmF0ZSBrZXkgQiBiaXRzIGxvbmcsIHVzaW5nIHB1YmxpYyBleHB0IEVcbmZ1bmN0aW9uIFJTQUdlbmVyYXRlKEIsRSkge1xuICB2YXIgcm5nID0gbmV3IFNlY3VyZVJhbmRvbSgpO1xuICB2YXIgcXMgPSBCPj4xO1xuICB0aGlzLmUgPSBwYXJzZUludChFLDE2KTtcbiAgdmFyIGVlID0gbmV3IEJpZ0ludGVnZXIoRSwxNik7XG4gIGZvcig7Oykge1xuICAgIGZvcig7Oykge1xuICAgICAgdGhpcy5wID0gbmV3IEJpZ0ludGVnZXIoQi1xcywxLHJuZyk7XG4gICAgICBpZih0aGlzLnAuc3VidHJhY3QoQmlnSW50ZWdlci5PTkUpLmdjZChlZSkuY29tcGFyZVRvKEJpZ0ludGVnZXIuT05FKSA9PSAwICYmIHRoaXMucC5pc1Byb2JhYmxlUHJpbWUoMTApKSBicmVhaztcbiAgICB9XG4gICAgZm9yKDs7KSB7XG4gICAgICB0aGlzLnEgPSBuZXcgQmlnSW50ZWdlcihxcywxLHJuZyk7XG4gICAgICBpZih0aGlzLnEuc3VidHJhY3QoQmlnSW50ZWdlci5PTkUpLmdjZChlZSkuY29tcGFyZVRvKEJpZ0ludGVnZXIuT05FKSA9PSAwICYmIHRoaXMucS5pc1Byb2JhYmxlUHJpbWUoMTApKSBicmVhaztcbiAgICB9XG4gICAgaWYodGhpcy5wLmNvbXBhcmVUbyh0aGlzLnEpIDw9IDApIHtcbiAgICAgIHZhciB0ID0gdGhpcy5wO1xuICAgICAgdGhpcy5wID0gdGhpcy5xO1xuICAgICAgdGhpcy5xID0gdDtcbiAgICB9XG4gICAgdmFyIHAxID0gdGhpcy5wLnN1YnRyYWN0KEJpZ0ludGVnZXIuT05FKTtcbiAgICB2YXIgcTEgPSB0aGlzLnEuc3VidHJhY3QoQmlnSW50ZWdlci5PTkUpO1xuICAgIHZhciBwaGkgPSBwMS5tdWx0aXBseShxMSk7XG4gICAgaWYocGhpLmdjZChlZSkuY29tcGFyZVRvKEJpZ0ludGVnZXIuT05FKSA9PSAwKSB7XG4gICAgICB0aGlzLm4gPSB0aGlzLnAubXVsdGlwbHkodGhpcy5xKTtcbiAgICAgIHRoaXMuZCA9IGVlLm1vZEludmVyc2UocGhpKTtcbiAgICAgIHRoaXMuZG1wMSA9IHRoaXMuZC5tb2QocDEpO1xuICAgICAgdGhpcy5kbXExID0gdGhpcy5kLm1vZChxMSk7XG4gICAgICB0aGlzLmNvZWZmID0gdGhpcy5xLm1vZEludmVyc2UodGhpcy5wKTtcbiAgICAgIGJyZWFrO1xuICAgIH1cbiAgfVxufVxuXG4vLyBQZXJmb3JtIHJhdyBwcml2YXRlIG9wZXJhdGlvbiBvbiBcInhcIjogcmV0dXJuIHheZCAobW9kIG4pXG5mdW5jdGlvbiBSU0FEb1ByaXZhdGUoeCkge1xuICBpZih0aGlzLnAgPT0gbnVsbCB8fCB0aGlzLnEgPT0gbnVsbClcbiAgICByZXR1cm4geC5tb2RQb3codGhpcy5kLCB0aGlzLm4pO1xuXG4gIC8vIFRPRE86IHJlLWNhbGN1bGF0ZSBhbnkgbWlzc2luZyBDUlQgcGFyYW1zXG4gIHZhciB4cCA9IHgubW9kKHRoaXMucCkubW9kUG93KHRoaXMuZG1wMSwgdGhpcy5wKTtcbiAgdmFyIHhxID0geC5tb2QodGhpcy5xKS5tb2RQb3codGhpcy5kbXExLCB0aGlzLnEpO1xuXG4gIHdoaWxlKHhwLmNvbXBhcmVUbyh4cSkgPCAwKVxuICAgIHhwID0geHAuYWRkKHRoaXMucCk7XG4gIHJldHVybiB4cC5zdWJ0cmFjdCh4cSkubXVsdGlwbHkodGhpcy5jb2VmZikubW9kKHRoaXMucCkubXVsdGlwbHkodGhpcy5xKS5hZGQoeHEpO1xufVxuXG4vLyBSZXR1cm4gdGhlIFBLQ1MjMSBSU0EgZGVjcnlwdGlvbiBvZiBcImN0ZXh0XCIuXG4vLyBcImN0ZXh0XCIgaXMgYW4gZXZlbi1sZW5ndGggaGV4IHN0cmluZyBhbmQgdGhlIG91dHB1dCBpcyBhIHBsYWluIHN0cmluZy5cbmZ1bmN0aW9uIFJTQURlY3J5cHQoY3RleHQpIHtcbiAgdmFyIGMgPSBwYXJzZUJpZ0ludChjdGV4dCwgMTYpO1xuICB2YXIgbSA9IHRoaXMuZG9Qcml2YXRlKGMpO1xuICBpZihtID09IG51bGwpIHJldHVybiBudWxsO1xuICByZXR1cm4gcGtjczF1bnBhZDIobSwgKHRoaXMubi5iaXRMZW5ndGgoKSs3KT4+Myk7XG59XG5cbi8vIFJldHVybiB0aGUgUEtDUyMxIFJTQSBkZWNyeXB0aW9uIG9mIFwiY3RleHRcIi5cbi8vIFwiY3RleHRcIiBpcyBhIEJhc2U2NC1lbmNvZGVkIHN0cmluZyBhbmQgdGhlIG91dHB1dCBpcyBhIHBsYWluIHN0cmluZy5cbi8vZnVuY3Rpb24gUlNBQjY0RGVjcnlwdChjdGV4dCkge1xuLy8gIHZhciBoID0gYjY0dG9oZXgoY3RleHQpO1xuLy8gIGlmKGgpIHJldHVybiB0aGlzLmRlY3J5cHQoaCk7IGVsc2UgcmV0dXJuIG51bGw7XG4vL31cblxuLy8gcHJvdGVjdGVkXG5SU0FLZXkucHJvdG90eXBlLmRvUHJpdmF0ZSA9IFJTQURvUHJpdmF0ZTtcblxuLy8gcHVibGljXG5SU0FLZXkucHJvdG90eXBlLnNldFByaXZhdGUgPSBSU0FTZXRQcml2YXRlO1xuUlNBS2V5LnByb3RvdHlwZS5zZXRQcml2YXRlRXggPSBSU0FTZXRQcml2YXRlRXg7XG5SU0FLZXkucHJvdG90eXBlLmdlbmVyYXRlID0gUlNBR2VuZXJhdGU7XG5SU0FLZXkucHJvdG90eXBlLmRlY3J5cHQgPSBSU0FEZWNyeXB0O1xuLy9SU0FLZXkucHJvdG90eXBlLmI2NF9kZWNyeXB0ID0gUlNBQjY0RGVjcnlwdDtcblxuLy8gQ29weXJpZ2h0IChjKSAyMDExICBLZXZpbiBNIEJ1cm5zIEpyLlxuLy8gQWxsIFJpZ2h0cyBSZXNlcnZlZC5cbi8vIFNlZSBcIkxJQ0VOU0VcIiBmb3IgZGV0YWlscy5cbi8vXG4vLyBFeHRlbnNpb24gdG8ganNibiB3aGljaCBhZGRzIGZhY2lsaXRpZXMgZm9yIGFzeW5jaHJvbm91cyBSU0Ega2V5IGdlbmVyYXRpb25cbi8vIFByaW1hcmlseSBjcmVhdGVkIHRvIGF2b2lkIGV4ZWN1dGlvbiB0aW1lb3V0IG9uIG1vYmlsZSBkZXZpY2VzXG4vL1xuLy8gaHR0cDovL3d3dy1jcy1zdHVkZW50cy5zdGFuZm9yZC5lZHUvfnRqdy9qc2JuL1xuLy9cbi8vIC0tLVxuXG4oZnVuY3Rpb24oKXtcblxuLy8gR2VuZXJhdGUgYSBuZXcgcmFuZG9tIHByaXZhdGUga2V5IEIgYml0cyBsb25nLCB1c2luZyBwdWJsaWMgZXhwdCBFXG52YXIgUlNBR2VuZXJhdGVBc3luYyA9IGZ1bmN0aW9uIChCLCBFLCBjYWxsYmFjaykge1xuICAgIC8vdmFyIHJuZyA9IG5ldyBTZWVkZWRSYW5kb20oKTtcbiAgICB2YXIgcm5nID0gbmV3IFNlY3VyZVJhbmRvbSgpO1xuICAgIHZhciBxcyA9IEIgPj4gMTtcbiAgICB0aGlzLmUgPSBwYXJzZUludChFLCAxNik7XG4gICAgdmFyIGVlID0gbmV3IEJpZ0ludGVnZXIoRSwgMTYpO1xuICAgIHZhciByc2EgPSB0aGlzO1xuICAgIC8vIFRoZXNlIGZ1bmN0aW9ucyBoYXZlIG5vbi1kZXNjcmlwdCBuYW1lcyBiZWNhdXNlIHRoZXkgd2VyZSBvcmlnaW5hbGx5IGZvcig7OykgbG9vcHMuXG4gICAgLy8gSSBkb24ndCBrbm93IGFib3V0IGNyeXB0b2dyYXBoeSB0byBnaXZlIHRoZW0gYmV0dGVyIG5hbWVzIHRoYW4gbG9vcDEtNC5cbiAgICB2YXIgbG9vcDEgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgdmFyIGxvb3A0ID0gZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICBpZiAocnNhLnAuY29tcGFyZVRvKHJzYS5xKSA8PSAwKSB7XG4gICAgICAgICAgICAgICAgdmFyIHQgPSByc2EucDtcbiAgICAgICAgICAgICAgICByc2EucCA9IHJzYS5xO1xuICAgICAgICAgICAgICAgIHJzYS5xID0gdDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHZhciBwMSA9IHJzYS5wLnN1YnRyYWN0KEJpZ0ludGVnZXIuT05FKTtcbiAgICAgICAgICAgIHZhciBxMSA9IHJzYS5xLnN1YnRyYWN0KEJpZ0ludGVnZXIuT05FKTtcbiAgICAgICAgICAgIHZhciBwaGkgPSBwMS5tdWx0aXBseShxMSk7XG4gICAgICAgICAgICBpZiAocGhpLmdjZChlZSkuY29tcGFyZVRvKEJpZ0ludGVnZXIuT05FKSA9PSAwKSB7XG4gICAgICAgICAgICAgICAgcnNhLm4gPSByc2EucC5tdWx0aXBseShyc2EucSk7XG4gICAgICAgICAgICAgICAgcnNhLmQgPSBlZS5tb2RJbnZlcnNlKHBoaSk7XG4gICAgICAgICAgICAgICAgcnNhLmRtcDEgPSByc2EuZC5tb2QocDEpO1xuICAgICAgICAgICAgICAgIHJzYS5kbXExID0gcnNhLmQubW9kKHExKTtcbiAgICAgICAgICAgICAgICByc2EuY29lZmYgPSByc2EucS5tb2RJbnZlcnNlKHJzYS5wKTtcbiAgICAgICAgICAgICAgICBzZXRUaW1lb3V0KGZ1bmN0aW9uKCl7Y2FsbGJhY2soKX0sMCk7IC8vIGVzY2FwZVxuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICBzZXRUaW1lb3V0KGxvb3AxLDApO1xuICAgICAgICAgICAgfVxuICAgICAgICB9O1xuICAgICAgICB2YXIgbG9vcDMgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIHJzYS5xID0gbmJpKCk7XG4gICAgICAgICAgICByc2EucS5mcm9tTnVtYmVyQXN5bmMocXMsIDEsIHJuZywgZnVuY3Rpb24oKXtcbiAgICAgICAgICAgICAgICByc2EucS5zdWJ0cmFjdChCaWdJbnRlZ2VyLk9ORSkuZ2NkYShlZSwgZnVuY3Rpb24ocil7XG4gICAgICAgICAgICAgICAgICAgIGlmIChyLmNvbXBhcmVUbyhCaWdJbnRlZ2VyLk9ORSkgPT0gMCAmJiByc2EucS5pc1Byb2JhYmxlUHJpbWUoMTApKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBzZXRUaW1lb3V0KGxvb3A0LDApO1xuICAgICAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgc2V0VGltZW91dChsb29wMywwKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH07XG4gICAgICAgIHZhciBsb29wMiA9IGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgcnNhLnAgPSBuYmkoKTtcbiAgICAgICAgICAgIHJzYS5wLmZyb21OdW1iZXJBc3luYyhCIC0gcXMsIDEsIHJuZywgZnVuY3Rpb24oKXtcbiAgICAgICAgICAgICAgICByc2EucC5zdWJ0cmFjdChCaWdJbnRlZ2VyLk9ORSkuZ2NkYShlZSwgZnVuY3Rpb24ocil7XG4gICAgICAgICAgICAgICAgICAgIGlmIChyLmNvbXBhcmVUbyhCaWdJbnRlZ2VyLk9ORSkgPT0gMCAmJiByc2EucC5pc1Byb2JhYmxlUHJpbWUoMTApKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBzZXRUaW1lb3V0KGxvb3AzLDApO1xuICAgICAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgc2V0VGltZW91dChsb29wMiwwKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH07XG4gICAgICAgIHNldFRpbWVvdXQobG9vcDIsMCk7XG4gICAgfTtcbiAgICBzZXRUaW1lb3V0KGxvb3AxLDApO1xufTtcblJTQUtleS5wcm90b3R5cGUuZ2VuZXJhdGVBc3luYyA9IFJTQUdlbmVyYXRlQXN5bmM7XG5cbi8vIFB1YmxpYyBBUEkgbWV0aG9kXG52YXIgYm5HQ0RBc3luYyA9IGZ1bmN0aW9uIChhLCBjYWxsYmFjaykge1xuICAgIHZhciB4ID0gKHRoaXMucyA8IDApID8gdGhpcy5uZWdhdGUoKSA6IHRoaXMuY2xvbmUoKTtcbiAgICB2YXIgeSA9IChhLnMgPCAwKSA/IGEubmVnYXRlKCkgOiBhLmNsb25lKCk7XG4gICAgaWYgKHguY29tcGFyZVRvKHkpIDwgMCkge1xuICAgICAgICB2YXIgdCA9IHg7XG4gICAgICAgIHggPSB5O1xuICAgICAgICB5ID0gdDtcbiAgICB9XG4gICAgdmFyIGkgPSB4LmdldExvd2VzdFNldEJpdCgpLFxuICAgICAgICBnID0geS5nZXRMb3dlc3RTZXRCaXQoKTtcbiAgICBpZiAoZyA8IDApIHtcbiAgICAgICAgY2FsbGJhY2soeCk7XG4gICAgICAgIHJldHVybjtcbiAgICB9XG4gICAgaWYgKGkgPCBnKSBnID0gaTtcbiAgICBpZiAoZyA+IDApIHtcbiAgICAgICAgeC5yU2hpZnRUbyhnLCB4KTtcbiAgICAgICAgeS5yU2hpZnRUbyhnLCB5KTtcbiAgICB9XG4gICAgLy8gV29ya2hvcnNlIG9mIHRoZSBhbGdvcml0aG0sIGdldHMgY2FsbGVkIDIwMCAtIDgwMCB0aW1lcyBwZXIgNTEyIGJpdCBrZXlnZW4uXG4gICAgdmFyIGdjZGExID0gZnVuY3Rpb24oKSB7XG4gICAgICAgIGlmICgoaSA9IHguZ2V0TG93ZXN0U2V0Qml0KCkpID4gMCl7IHguclNoaWZ0VG8oaSwgeCk7IH1cbiAgICAgICAgaWYgKChpID0geS5nZXRMb3dlc3RTZXRCaXQoKSkgPiAwKXsgeS5yU2hpZnRUbyhpLCB5KTsgfVxuICAgICAgICBpZiAoeC5jb21wYXJlVG8oeSkgPj0gMCkge1xuICAgICAgICAgICAgeC5zdWJUbyh5LCB4KTtcbiAgICAgICAgICAgIHguclNoaWZ0VG8oMSwgeCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB5LnN1YlRvKHgsIHkpO1xuICAgICAgICAgICAgeS5yU2hpZnRUbygxLCB5KTtcbiAgICAgICAgfVxuICAgICAgICBpZighKHguc2lnbnVtKCkgPiAwKSkge1xuICAgICAgICAgICAgaWYgKGcgPiAwKSB5LmxTaGlmdFRvKGcsIHkpO1xuICAgICAgICAgICAgc2V0VGltZW91dChmdW5jdGlvbigpe2NhbGxiYWNrKHkpfSwwKTsgLy8gZXNjYXBlXG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBzZXRUaW1lb3V0KGdjZGExLDApO1xuICAgICAgICB9XG4gICAgfTtcbiAgICBzZXRUaW1lb3V0KGdjZGExLDEwKTtcbn07XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5nY2RhID0gYm5HQ0RBc3luYztcblxuLy8gKHByb3RlY3RlZCkgYWx0ZXJuYXRlIGNvbnN0cnVjdG9yXG52YXIgYm5wRnJvbU51bWJlckFzeW5jID0gZnVuY3Rpb24gKGEsYixjLGNhbGxiYWNrKSB7XG4gIGlmKFwibnVtYmVyXCIgPT0gdHlwZW9mIGIpIHtcbiAgICBpZihhIDwgMikge1xuICAgICAgICB0aGlzLmZyb21JbnQoMSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHRoaXMuZnJvbU51bWJlcihhLGMpO1xuICAgICAgaWYoIXRoaXMudGVzdEJpdChhLTEpKXtcbiAgICAgICAgdGhpcy5iaXR3aXNlVG8oQmlnSW50ZWdlci5PTkUuc2hpZnRMZWZ0KGEtMSksb3Bfb3IsdGhpcyk7XG4gICAgICB9XG4gICAgICBpZih0aGlzLmlzRXZlbigpKSB7XG4gICAgICAgIHRoaXMuZEFkZE9mZnNldCgxLDApO1xuICAgICAgfVxuICAgICAgdmFyIGJucCA9IHRoaXM7XG4gICAgICB2YXIgYm5wZm4xID0gZnVuY3Rpb24oKXtcbiAgICAgICAgYm5wLmRBZGRPZmZzZXQoMiwwKTtcbiAgICAgICAgaWYoYm5wLmJpdExlbmd0aCgpID4gYSkgYm5wLnN1YlRvKEJpZ0ludGVnZXIuT05FLnNoaWZ0TGVmdChhLTEpLGJucCk7XG4gICAgICAgIGlmKGJucC5pc1Byb2JhYmxlUHJpbWUoYikpIHtcbiAgICAgICAgICAgIHNldFRpbWVvdXQoZnVuY3Rpb24oKXtjYWxsYmFjaygpfSwwKTsgLy8gZXNjYXBlXG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBzZXRUaW1lb3V0KGJucGZuMSwwKTtcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICAgIHNldFRpbWVvdXQoYm5wZm4xLDApO1xuICAgIH1cbiAgfSBlbHNlIHtcbiAgICB2YXIgeCA9IG5ldyBBcnJheSgpLCB0ID0gYSY3O1xuICAgIHgubGVuZ3RoID0gKGE+PjMpKzE7XG4gICAgYi5uZXh0Qnl0ZXMoeCk7XG4gICAgaWYodCA+IDApIHhbMF0gJj0gKCgxPDx0KS0xKTsgZWxzZSB4WzBdID0gMDtcbiAgICB0aGlzLmZyb21TdHJpbmcoeCwyNTYpO1xuICB9XG59O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZnJvbU51bWJlckFzeW5jID0gYm5wRnJvbU51bWJlckFzeW5jO1xuXG59KSgpO1xudmFyIGI2NG1hcD1cIkFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5Ky9cIjtcbnZhciBiNjRwYWQ9XCI9XCI7XG5cbmZ1bmN0aW9uIGhleDJiNjQoaCkge1xuICB2YXIgaTtcbiAgdmFyIGM7XG4gIHZhciByZXQgPSBcIlwiO1xuICBmb3IoaSA9IDA7IGkrMyA8PSBoLmxlbmd0aDsgaSs9Mykge1xuICAgIGMgPSBwYXJzZUludChoLnN1YnN0cmluZyhpLGkrMyksMTYpO1xuICAgIHJldCArPSBiNjRtYXAuY2hhckF0KGMgPj4gNikgKyBiNjRtYXAuY2hhckF0KGMgJiA2Myk7XG4gIH1cbiAgaWYoaSsxID09IGgubGVuZ3RoKSB7XG4gICAgYyA9IHBhcnNlSW50KGguc3Vic3RyaW5nKGksaSsxKSwxNik7XG4gICAgcmV0ICs9IGI2NG1hcC5jaGFyQXQoYyA8PCAyKTtcbiAgfVxuICBlbHNlIGlmKGkrMiA9PSBoLmxlbmd0aCkge1xuICAgIGMgPSBwYXJzZUludChoLnN1YnN0cmluZyhpLGkrMiksMTYpO1xuICAgIHJldCArPSBiNjRtYXAuY2hhckF0KGMgPj4gMikgKyBiNjRtYXAuY2hhckF0KChjICYgMykgPDwgNCk7XG4gIH1cbiAgd2hpbGUoKHJldC5sZW5ndGggJiAzKSA+IDApIHJldCArPSBiNjRwYWQ7XG4gIHJldHVybiByZXQ7XG59XG5cbi8vIGNvbnZlcnQgYSBiYXNlNjQgc3RyaW5nIHRvIGhleFxuZnVuY3Rpb24gYjY0dG9oZXgocykge1xuICB2YXIgcmV0ID0gXCJcIlxuICB2YXIgaTtcbiAgdmFyIGsgPSAwOyAvLyBiNjQgc3RhdGUsIDAtM1xuICB2YXIgc2xvcDtcbiAgZm9yKGkgPSAwOyBpIDwgcy5sZW5ndGg7ICsraSkge1xuICAgIGlmKHMuY2hhckF0KGkpID09IGI2NHBhZCkgYnJlYWs7XG4gICAgdiA9IGI2NG1hcC5pbmRleE9mKHMuY2hhckF0KGkpKTtcbiAgICBpZih2IDwgMCkgY29udGludWU7XG4gICAgaWYoayA9PSAwKSB7XG4gICAgICByZXQgKz0gaW50MmNoYXIodiA+PiAyKTtcbiAgICAgIHNsb3AgPSB2ICYgMztcbiAgICAgIGsgPSAxO1xuICAgIH1cbiAgICBlbHNlIGlmKGsgPT0gMSkge1xuICAgICAgcmV0ICs9IGludDJjaGFyKChzbG9wIDw8IDIpIHwgKHYgPj4gNCkpO1xuICAgICAgc2xvcCA9IHYgJiAweGY7XG4gICAgICBrID0gMjtcbiAgICB9XG4gICAgZWxzZSBpZihrID09IDIpIHtcbiAgICAgIHJldCArPSBpbnQyY2hhcihzbG9wKTtcbiAgICAgIHJldCArPSBpbnQyY2hhcih2ID4+IDIpO1xuICAgICAgc2xvcCA9IHYgJiAzO1xuICAgICAgayA9IDM7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgcmV0ICs9IGludDJjaGFyKChzbG9wIDw8IDIpIHwgKHYgPj4gNCkpO1xuICAgICAgcmV0ICs9IGludDJjaGFyKHYgJiAweGYpO1xuICAgICAgayA9IDA7XG4gICAgfVxuICB9XG4gIGlmKGsgPT0gMSlcbiAgICByZXQgKz0gaW50MmNoYXIoc2xvcCA8PCAyKTtcbiAgcmV0dXJuIHJldDtcbn1cblxuLy8gY29udmVydCBhIGJhc2U2NCBzdHJpbmcgdG8gYSBieXRlL251bWJlciBhcnJheVxuZnVuY3Rpb24gYjY0dG9CQShzKSB7XG4gIC8vcGlnZ3liYWNrIG9uIGI2NHRvaGV4IGZvciBub3csIG9wdGltaXplIGxhdGVyXG4gIHZhciBoID0gYjY0dG9oZXgocyk7XG4gIHZhciBpO1xuICB2YXIgYSA9IG5ldyBBcnJheSgpO1xuICBmb3IoaSA9IDA7IDIqaSA8IGgubGVuZ3RoOyArK2kpIHtcbiAgICBhW2ldID0gcGFyc2VJbnQoaC5zdWJzdHJpbmcoMippLDIqaSsyKSwxNik7XG4gIH1cbiAgcmV0dXJuIGE7XG59XG5cbi8qISBhc24xLTEuMC4yLmpzIChjKSAyMDEzIEtlbmppIFVydXNoaW1hIHwga2p1ci5naXRodWIuY29tL2pzcnNhc2lnbi9saWNlbnNlXG4gKi9cblxudmFyIEpTWCA9IEpTWCB8fCB7fTtcbkpTWC5lbnYgPSBKU1guZW52IHx8IHt9O1xuXG52YXIgTCA9IEpTWCwgT1AgPSBPYmplY3QucHJvdG90eXBlLCBGVU5DVElPTl9UT1NUUklORyA9ICdbb2JqZWN0IEZ1bmN0aW9uXScsQUREID0gW1widG9TdHJpbmdcIiwgXCJ2YWx1ZU9mXCJdO1xuXG5KU1guZW52LnBhcnNlVUEgPSBmdW5jdGlvbihhZ2VudCkge1xuXG4gICAgdmFyIG51bWJlcmlmeSA9IGZ1bmN0aW9uKHMpIHtcbiAgICAgICAgdmFyIGMgPSAwO1xuICAgICAgICByZXR1cm4gcGFyc2VGbG9hdChzLnJlcGxhY2UoL1xcLi9nLCBmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIHJldHVybiAoYysrID09IDEpID8gJycgOiAnLic7XG4gICAgICAgIH0pKTtcbiAgICB9LFxuXG4gICAgbmF2ID0gbmF2aWdhdG9yLFxuICAgIG8gPSB7XG4gICAgICAgIGllOiAwLFxuICAgICAgICBvcGVyYTogMCxcbiAgICAgICAgZ2Vja286IDAsXG4gICAgICAgIHdlYmtpdDogMCxcbiAgICAgICAgY2hyb21lOiAwLFxuICAgICAgICBtb2JpbGU6IG51bGwsXG4gICAgICAgIGFpcjogMCxcbiAgICAgICAgaXBhZDogMCxcbiAgICAgICAgaXBob25lOiAwLFxuICAgICAgICBpcG9kOiAwLFxuICAgICAgICBpb3M6IG51bGwsXG4gICAgICAgIGFuZHJvaWQ6IDAsXG4gICAgICAgIHdlYm9zOiAwLFxuICAgICAgICBjYWphOiBuYXYgJiYgbmF2LmNhamFWZXJzaW9uLFxuICAgICAgICBzZWN1cmU6IGZhbHNlLFxuICAgICAgICBvczogbnVsbFxuXG4gICAgfSxcblxuICAgIHVhID0gYWdlbnQgfHwgKG5hdmlnYXRvciAmJiBuYXZpZ2F0b3IudXNlckFnZW50KSxcbiAgICBsb2MgPSB3aW5kb3cgJiYgd2luZG93LmxvY2F0aW9uLFxuICAgIGhyZWYgPSBsb2MgJiYgbG9jLmhyZWYsXG4gICAgbTtcblxuICAgIG8uc2VjdXJlID0gaHJlZiAmJiAoaHJlZi50b0xvd2VyQ2FzZSgpLmluZGV4T2YoXCJodHRwc1wiKSA9PT0gMCk7XG5cbiAgICBpZiAodWEpIHtcblxuICAgICAgICBpZiAoKC93aW5kb3dzfHdpbjMyL2kpLnRlc3QodWEpKSB7XG4gICAgICAgICAgICBvLm9zID0gJ3dpbmRvd3MnO1xuICAgICAgICB9IGVsc2UgaWYgKCgvbWFjaW50b3NoL2kpLnRlc3QodWEpKSB7XG4gICAgICAgICAgICBvLm9zID0gJ21hY2ludG9zaCc7XG4gICAgICAgIH0gZWxzZSBpZiAoKC9yaGluby9pKS50ZXN0KHVhKSkge1xuICAgICAgICAgICAgby5vcyA9ICdyaGlubyc7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKCgvS0hUTUwvKS50ZXN0KHVhKSkge1xuICAgICAgICAgICAgby53ZWJraXQgPSAxO1xuICAgICAgICB9XG4gICAgICAgIG0gPSB1YS5tYXRjaCgvQXBwbGVXZWJLaXRcXC8oW15cXHNdKikvKTtcbiAgICAgICAgaWYgKG0gJiYgbVsxXSkge1xuICAgICAgICAgICAgby53ZWJraXQgPSBudW1iZXJpZnkobVsxXSk7XG4gICAgICAgICAgICBpZiAoLyBNb2JpbGVcXC8vLnRlc3QodWEpKSB7XG4gICAgICAgICAgICAgICAgby5tb2JpbGUgPSAnQXBwbGUnOyAvLyBpUGhvbmUgb3IgaVBvZCBUb3VjaFxuICAgICAgICAgICAgICAgIG0gPSB1YS5tYXRjaCgvT1MgKFteXFxzXSopLyk7XG4gICAgICAgICAgICAgICAgaWYgKG0gJiYgbVsxXSkge1xuICAgICAgICAgICAgICAgICAgICBtID0gbnVtYmVyaWZ5KG1bMV0ucmVwbGFjZSgnXycsICcuJykpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBvLmlvcyA9IG07XG4gICAgICAgICAgICAgICAgby5pcGFkID0gby5pcG9kID0gby5pcGhvbmUgPSAwO1xuICAgICAgICAgICAgICAgIG0gPSB1YS5tYXRjaCgvaVBhZHxpUG9kfGlQaG9uZS8pO1xuICAgICAgICAgICAgICAgIGlmIChtICYmIG1bMF0pIHtcbiAgICAgICAgICAgICAgICAgICAgb1ttWzBdLnRvTG93ZXJDYXNlKCldID0gby5pb3M7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICBtID0gdWEubWF0Y2goL05va2lhTlteXFwvXSp8QW5kcm9pZCBcXGRcXC5cXGR8d2ViT1NcXC9cXGRcXC5cXGQvKTtcbiAgICAgICAgICAgICAgICBpZiAobSkge1xuICAgICAgICAgICAgICAgICAgICBvLm1vYmlsZSA9IG1bMF07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICgvd2ViT1MvLnRlc3QodWEpKSB7XG4gICAgICAgICAgICAgICAgICAgIG8ubW9iaWxlID0gJ1dlYk9TJztcbiAgICAgICAgICAgICAgICAgICAgbSA9IHVhLm1hdGNoKC93ZWJPU1xcLyhbXlxcc10qKTsvKTtcbiAgICAgICAgICAgICAgICAgICAgaWYgKG0gJiYgbVsxXSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgby53ZWJvcyA9IG51bWJlcmlmeShtWzFdKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoLyBBbmRyb2lkLy50ZXN0KHVhKSkge1xuICAgICAgICAgICAgICAgICAgICBvLm1vYmlsZSA9ICdBbmRyb2lkJztcbiAgICAgICAgICAgICAgICAgICAgbSA9IHVhLm1hdGNoKC9BbmRyb2lkIChbXlxcc10qKTsvKTtcbiAgICAgICAgICAgICAgICAgICAgaWYgKG0gJiYgbVsxXSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgby5hbmRyb2lkID0gbnVtYmVyaWZ5KG1bMV0pO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgbSA9IHVhLm1hdGNoKC9DaHJvbWVcXC8oW15cXHNdKikvKTtcbiAgICAgICAgICAgIGlmIChtICYmIG1bMV0pIHtcbiAgICAgICAgICAgICAgICBvLmNocm9tZSA9IG51bWJlcmlmeShtWzFdKTsgLy8gQ2hyb21lXG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIG0gPSB1YS5tYXRjaCgvQWRvYmVBSVJcXC8oW15cXHNdKikvKTtcbiAgICAgICAgICAgICAgICBpZiAobSkge1xuICAgICAgICAgICAgICAgICAgICBvLmFpciA9IG1bMF07IC8vIEFkb2JlIEFJUiAxLjAgb3IgYmV0dGVyXG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIGlmICghby53ZWJraXQpIHtcbiAgICAgICAgICAgIG0gPSB1YS5tYXRjaCgvT3BlcmFbXFxzXFwvXShbXlxcc10qKS8pO1xuICAgICAgICAgICAgaWYgKG0gJiYgbVsxXSkge1xuICAgICAgICAgICAgICAgIG8ub3BlcmEgPSBudW1iZXJpZnkobVsxXSk7XG4gICAgICAgICAgICAgICAgbSA9IHVhLm1hdGNoKC9WZXJzaW9uXFwvKFteXFxzXSopLyk7XG4gICAgICAgICAgICAgICAgaWYgKG0gJiYgbVsxXSkge1xuICAgICAgICAgICAgICAgICAgICBvLm9wZXJhID0gbnVtYmVyaWZ5KG1bMV0pOyAvLyBvcGVyYSAxMCtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgbSA9IHVhLm1hdGNoKC9PcGVyYSBNaW5pW147XSovKTtcbiAgICAgICAgICAgICAgICBpZiAobSkge1xuICAgICAgICAgICAgICAgICAgICBvLm1vYmlsZSA9IG1bMF07IC8vIGV4OiBPcGVyYSBNaW5pLzIuMC40NTA5LzEzMTZcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGVsc2UgeyAvLyBub3Qgb3BlcmEgb3Igd2Via2l0XG4gICAgICAgICAgICAgICAgbSA9IHVhLm1hdGNoKC9NU0lFXFxzKFteO10qKS8pO1xuICAgICAgICAgICAgICAgIGlmIChtICYmIG1bMV0pIHtcbiAgICAgICAgICAgICAgICAgICAgby5pZSA9IG51bWJlcmlmeShtWzFdKTtcbiAgICAgICAgICAgICAgICB9IGVsc2UgeyAvLyBub3Qgb3BlcmEsIHdlYmtpdCwgb3IgaWVcbiAgICAgICAgICAgICAgICAgICAgbSA9IHVhLm1hdGNoKC9HZWNrb1xcLyhbXlxcc10qKS8pO1xuICAgICAgICAgICAgICAgICAgICBpZiAobSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgby5nZWNrbyA9IDE7IC8vIEdlY2tvIGRldGVjdGVkLCBsb29rIGZvciByZXZpc2lvblxuICAgICAgICAgICAgICAgICAgICAgICAgbSA9IHVhLm1hdGNoKC9ydjooW15cXHNcXCldKikvKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChtICYmIG1bMV0pIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBvLmdlY2tvID0gbnVtYmVyaWZ5KG1bMV0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxuICAgIHJldHVybiBvO1xufTtcblxuSlNYLmVudi51YSA9IEpTWC5lbnYucGFyc2VVQSgpO1xuXG5KU1guaXNGdW5jdGlvbiA9IGZ1bmN0aW9uKG8pIHtcbiAgICByZXR1cm4gKHR5cGVvZiBvID09PSAnZnVuY3Rpb24nKSB8fCBPUC50b1N0cmluZy5hcHBseShvKSA9PT0gRlVOQ1RJT05fVE9TVFJJTkc7XG59O1xuXG5KU1guX0lFRW51bUZpeCA9IChKU1guZW52LnVhLmllKSA/IGZ1bmN0aW9uKHIsIHMpIHtcbiAgICB2YXIgaSwgZm5hbWUsIGY7XG4gICAgZm9yIChpPTA7aTxBREQubGVuZ3RoO2k9aSsxKSB7XG5cbiAgICAgICAgZm5hbWUgPSBBRERbaV07XG4gICAgICAgIGYgPSBzW2ZuYW1lXTtcblxuICAgICAgICBpZiAoTC5pc0Z1bmN0aW9uKGYpICYmIGYhPU9QW2ZuYW1lXSkge1xuICAgICAgICAgICAgcltmbmFtZV09ZjtcbiAgICAgICAgfVxuICAgIH1cbn0gOiBmdW5jdGlvbigpe307XG5cbkpTWC5leHRlbmQgPSBmdW5jdGlvbihzdWJjLCBzdXBlcmMsIG92ZXJyaWRlcykge1xuICAgIGlmICghc3VwZXJjfHwhc3ViYykge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJleHRlbmQgZmFpbGVkLCBwbGVhc2UgY2hlY2sgdGhhdCBcIiArXG4gICAgICAgICAgICAgICAgICAgICAgICBcImFsbCBkZXBlbmRlbmNpZXMgYXJlIGluY2x1ZGVkLlwiKTtcbiAgICB9XG4gICAgdmFyIEYgPSBmdW5jdGlvbigpIHt9LCBpO1xuICAgIEYucHJvdG90eXBlPXN1cGVyYy5wcm90b3R5cGU7XG4gICAgc3ViYy5wcm90b3R5cGU9bmV3IEYoKTtcbiAgICBzdWJjLnByb3RvdHlwZS5jb25zdHJ1Y3Rvcj1zdWJjO1xuICAgIHN1YmMuc3VwZXJjbGFzcz1zdXBlcmMucHJvdG90eXBlO1xuICAgIGlmIChzdXBlcmMucHJvdG90eXBlLmNvbnN0cnVjdG9yID09IE9QLmNvbnN0cnVjdG9yKSB7XG4gICAgICAgIHN1cGVyYy5wcm90b3R5cGUuY29uc3RydWN0b3I9c3VwZXJjO1xuICAgIH1cblxuICAgIGlmIChvdmVycmlkZXMpIHtcbiAgICAgICAgZm9yIChpIGluIG92ZXJyaWRlcykge1xuICAgICAgICAgICAgaWYgKEwuaGFzT3duUHJvcGVydHkob3ZlcnJpZGVzLCBpKSkge1xuICAgICAgICAgICAgICAgIHN1YmMucHJvdG90eXBlW2ldPW92ZXJyaWRlc1tpXTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIEwuX0lFRW51bUZpeChzdWJjLnByb3RvdHlwZSwgb3ZlcnJpZGVzKTtcbiAgICB9XG59O1xuXG4vKlxuICogYXNuMS5qcyAtIEFTTi4xIERFUiBlbmNvZGVyIGNsYXNzZXNcbiAqXG4gKiBDb3B5cmlnaHQgKGMpIDIwMTMgS2VuamkgVXJ1c2hpbWEgKGtlbmppLnVydXNoaW1hQGdtYWlsLmNvbSlcbiAqXG4gKiBUaGlzIHNvZnR3YXJlIGlzIGxpY2Vuc2VkIHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgTUlUIExpY2Vuc2UuXG4gKiBodHRwOi8va2p1ci5naXRodWIuY29tL2pzcnNhc2lnbi9saWNlbnNlXG4gKlxuICogVGhlIGFib3ZlIGNvcHlyaWdodCBhbmQgbGljZW5zZSBub3RpY2Ugc2hhbGwgYmUgXG4gKiBpbmNsdWRlZCBpbiBhbGwgY29waWVzIG9yIHN1YnN0YW50aWFsIHBvcnRpb25zIG9mIHRoZSBTb2Z0d2FyZS5cbiAqL1xuXG4vKipcbiAqIEBmaWxlT3ZlcnZpZXdcbiAqIEBuYW1lIGFzbjEtMS4wLmpzXG4gKiBAYXV0aG9yIEtlbmppIFVydXNoaW1hIGtlbmppLnVydXNoaW1hQGdtYWlsLmNvbVxuICogQHZlcnNpb24gMS4wLjIgKDIwMTMtTWF5LTMwKVxuICogQHNpbmNlIDIuMVxuICogQGxpY2Vuc2UgPGEgaHJlZj1cImh0dHA6Ly9ranVyLmdpdGh1Yi5pby9qc3JzYXNpZ24vbGljZW5zZS9cIj5NSVQgTGljZW5zZTwvYT5cbiAqL1xuXG4vKiogXG4gKiBranVyJ3MgY2xhc3MgbGlicmFyeSBuYW1lIHNwYWNlXG4gKiA8cD5cbiAqIFRoaXMgbmFtZSBzcGFjZSBwcm92aWRlcyBmb2xsb3dpbmcgbmFtZSBzcGFjZXM6XG4gKiA8dWw+XG4gKiA8bGk+e0BsaW5rIEtKVVIuYXNuMX0gLSBBU04uMSBwcmltaXRpdmUgaGV4YWRlY2ltYWwgZW5jb2RlcjwvbGk+XG4gKiA8bGk+e0BsaW5rIEtKVVIuYXNuMS54NTA5fSAtIEFTTi4xIHN0cnVjdHVyZSBmb3IgWC41MDkgY2VydGlmaWNhdGUgYW5kIENSTDwvbGk+XG4gKiA8bGk+e0BsaW5rIEtKVVIuY3J5cHRvfSAtIEphdmEgQ3J5cHRvZ3JhcGhpYyBFeHRlbnNpb24oSkNFKSBzdHlsZSBNZXNzYWdlRGlnZXN0L1NpZ25hdHVyZSBcbiAqIGNsYXNzIGFuZCB1dGlsaXRpZXM8L2xpPlxuICogPC91bD5cbiAqIDwvcD4gXG4gKiBOT1RFOiBQbGVhc2UgaWdub3JlIG1ldGhvZCBzdW1tYXJ5IGFuZCBkb2N1bWVudCBvZiB0aGlzIG5hbWVzcGFjZS4gVGhpcyBjYXVzZWQgYnkgYSBidWcgb2YganNkb2MyLlxuICAqIEBuYW1lIEtKVVJcbiAqIEBuYW1lc3BhY2Uga2p1cidzIGNsYXNzIGxpYnJhcnkgbmFtZSBzcGFjZVxuICovXG5pZiAodHlwZW9mIEtKVVIgPT0gXCJ1bmRlZmluZWRcIiB8fCAhS0pVUikgS0pVUiA9IHt9O1xuXG4vKipcbiAqIGtqdXIncyBBU04uMSBjbGFzcyBsaWJyYXJ5IG5hbWUgc3BhY2VcbiAqIDxwPlxuICogVGhpcyBpcyBJVFUtVCBYLjY5MCBBU04uMSBERVIgZW5jb2RlciBjbGFzcyBsaWJyYXJ5IGFuZFxuICogY2xhc3Mgc3RydWN0dXJlIGFuZCBtZXRob2RzIGlzIHZlcnkgc2ltaWxhciB0byBcbiAqIG9yZy5ib3VuY3ljYXN0bGUuYXNuMSBwYWNrYWdlIG9mIFxuICogd2VsbCBrbm93biBCb3VuY3lDYXNsdGUgQ3J5cHRvZ3JhcGh5IExpYnJhcnkuXG4gKlxuICogPGg0PlBST1ZJRElORyBBU04uMSBQUklNSVRJVkVTPC9oND5cbiAqIEhlcmUgYXJlIEFTTi4xIERFUiBwcmltaXRpdmUgY2xhc3Nlcy5cbiAqIDx1bD5cbiAqIDxsaT57QGxpbmsgS0pVUi5hc24xLkRFUkJvb2xlYW59PC9saT5cbiAqIDxsaT57QGxpbmsgS0pVUi5hc24xLkRFUkludGVnZXJ9PC9saT5cbiAqIDxsaT57QGxpbmsgS0pVUi5hc24xLkRFUkJpdFN0cmluZ308L2xpPlxuICogPGxpPntAbGluayBLSlVSLmFzbjEuREVST2N0ZXRTdHJpbmd9PC9saT5cbiAqIDxsaT57QGxpbmsgS0pVUi5hc24xLkRFUk51bGx9PC9saT5cbiAqIDxsaT57QGxpbmsgS0pVUi5hc24xLkRFUk9iamVjdElkZW50aWZpZXJ9PC9saT5cbiAqIDxsaT57QGxpbmsgS0pVUi5hc24xLkRFUlVURjhTdHJpbmd9PC9saT5cbiAqIDxsaT57QGxpbmsgS0pVUi5hc24xLkRFUk51bWVyaWNTdHJpbmd9PC9saT5cbiAqIDxsaT57QGxpbmsgS0pVUi5hc24xLkRFUlByaW50YWJsZVN0cmluZ308L2xpPlxuICogPGxpPntAbGluayBLSlVSLmFzbjEuREVSVGVsZXRleFN0cmluZ308L2xpPlxuICogPGxpPntAbGluayBLSlVSLmFzbjEuREVSSUE1U3RyaW5nfTwvbGk+XG4gKiA8bGk+e0BsaW5rIEtKVVIuYXNuMS5ERVJVVENUaW1lfTwvbGk+XG4gKiA8bGk+e0BsaW5rIEtKVVIuYXNuMS5ERVJHZW5lcmFsaXplZFRpbWV9PC9saT5cbiAqIDxsaT57QGxpbmsgS0pVUi5hc24xLkRFUlNlcXVlbmNlfTwvbGk+XG4gKiA8bGk+e0BsaW5rIEtKVVIuYXNuMS5ERVJTZXR9PC9saT5cbiAqIDwvdWw+XG4gKlxuICogPGg0Pk9USEVSIEFTTi4xIENMQVNTRVM8L2g0PlxuICogPHVsPlxuICogPGxpPntAbGluayBLSlVSLmFzbjEuQVNOMU9iamVjdH08L2xpPlxuICogPGxpPntAbGluayBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmd9PC9saT5cbiAqIDxsaT57QGxpbmsgS0pVUi5hc24xLkRFUkFic3RyYWN0VGltZX08L2xpPlxuICogPGxpPntAbGluayBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJ1Y3R1cmVkfTwvbGk+XG4gKiA8bGk+e0BsaW5rIEtKVVIuYXNuMS5ERVJUYWdnZWRPYmplY3R9PC9saT5cbiAqIDwvdWw+XG4gKiA8L3A+XG4gKiBOT1RFOiBQbGVhc2UgaWdub3JlIG1ldGhvZCBzdW1tYXJ5IGFuZCBkb2N1bWVudCBvZiB0aGlzIG5hbWVzcGFjZS4gVGhpcyBjYXVzZWQgYnkgYSBidWcgb2YganNkb2MyLlxuICogQG5hbWUgS0pVUi5hc24xXG4gKiBAbmFtZXNwYWNlXG4gKi9cbmlmICh0eXBlb2YgS0pVUi5hc24xID09IFwidW5kZWZpbmVkXCIgfHwgIUtKVVIuYXNuMSkgS0pVUi5hc24xID0ge307XG5cbi8qKlxuICogQVNOMSB1dGlsaXRpZXMgY2xhc3NcbiAqIEBuYW1lIEtKVVIuYXNuMS5BU04xVXRpbFxuICogQGNsYXNzcyBBU04xIHV0aWxpdGllcyBjbGFzc1xuICogQHNpbmNlIGFzbjEgMS4wLjJcbiAqL1xuS0pVUi5hc24xLkFTTjFVdGlsID0gbmV3IGZ1bmN0aW9uKCkge1xuICAgIHRoaXMuaW50ZWdlclRvQnl0ZUhleCA9IGZ1bmN0aW9uKGkpIHtcblx0dmFyIGggPSBpLnRvU3RyaW5nKDE2KTtcblx0aWYgKChoLmxlbmd0aCAlIDIpID09IDEpIGggPSAnMCcgKyBoO1xuXHRyZXR1cm4gaDtcbiAgICB9O1xuICAgIHRoaXMuYmlnSW50VG9NaW5Ud29zQ29tcGxlbWVudHNIZXggPSBmdW5jdGlvbihiaWdJbnRlZ2VyVmFsdWUpIHtcblx0dmFyIGggPSBiaWdJbnRlZ2VyVmFsdWUudG9TdHJpbmcoMTYpO1xuXHRpZiAoaC5zdWJzdHIoMCwgMSkgIT0gJy0nKSB7XG5cdCAgICBpZiAoaC5sZW5ndGggJSAyID09IDEpIHtcblx0XHRoID0gJzAnICsgaDtcblx0ICAgIH0gZWxzZSB7XG5cdFx0aWYgKCEgaC5tYXRjaCgvXlswLTddLykpIHtcblx0XHQgICAgaCA9ICcwMCcgKyBoO1xuXHRcdH1cblx0ICAgIH1cblx0fSBlbHNlIHtcblx0ICAgIHZhciBoUG9zID0gaC5zdWJzdHIoMSk7XG5cdCAgICB2YXIgeG9yTGVuID0gaFBvcy5sZW5ndGg7XG5cdCAgICBpZiAoeG9yTGVuICUgMiA9PSAxKSB7XG5cdFx0eG9yTGVuICs9IDE7XG5cdCAgICB9IGVsc2Uge1xuXHRcdGlmICghIGgubWF0Y2goL15bMC03XS8pKSB7XG5cdFx0ICAgIHhvckxlbiArPSAyO1xuXHRcdH1cblx0ICAgIH1cblx0ICAgIHZhciBoTWFzayA9ICcnO1xuXHQgICAgZm9yICh2YXIgaSA9IDA7IGkgPCB4b3JMZW47IGkrKykge1xuXHRcdGhNYXNrICs9ICdmJztcblx0ICAgIH1cblx0ICAgIHZhciBiaU1hc2sgPSBuZXcgQmlnSW50ZWdlcihoTWFzaywgMTYpO1xuXHQgICAgdmFyIGJpTmVnID0gYmlNYXNrLnhvcihiaWdJbnRlZ2VyVmFsdWUpLmFkZChCaWdJbnRlZ2VyLk9ORSk7XG5cdCAgICBoID0gYmlOZWcudG9TdHJpbmcoMTYpLnJlcGxhY2UoL14tLywgJycpO1xuXHR9XG5cdHJldHVybiBoO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogZ2V0IFBFTSBzdHJpbmcgZnJvbSBoZXhhZGVjaW1hbCBkYXRhIGFuZCBoZWFkZXIgc3RyaW5nXG4gICAgICogQG5hbWUgZ2V0UEVNU3RyaW5nRnJvbUhleFxuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuQVNOMVV0aWxcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcGFyYW0ge1N0cmluZ30gZGF0YUhleCBoZXhhZGVjaW1hbCBzdHJpbmcgb2YgUEVNIGJvZHlcbiAgICAgKiBAcGFyYW0ge1N0cmluZ30gcGVtSGVhZGVyIFBFTSBoZWFkZXIgc3RyaW5nIChleC4gJ1JTQSBQUklWQVRFIEtFWScpXG4gICAgICogQHJldHVybiB7U3RyaW5nfSBQRU0gZm9ybWF0dGVkIHN0cmluZyBvZiBpbnB1dCBkYXRhXG4gICAgICogQGRlc2NyaXB0aW9uXG4gICAgICogQGV4YW1wbGVcbiAgICAgKiB2YXIgcGVtICA9IEtKVVIuYXNuMS5BU04xVXRpbC5nZXRQRU1TdHJpbmdGcm9tSGV4KCc2MTYxNjEnLCAnUlNBIFBSSVZBVEUgS0VZJyk7XG4gICAgICogLy8gdmFsdWUgb2YgcGVtIHdpbGwgYmU6XG4gICAgICogLS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tXG4gICAgICogWVdGaFxuICAgICAqIC0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS1cbiAgICAgKi9cbiAgICB0aGlzLmdldFBFTVN0cmluZ0Zyb21IZXggPSBmdW5jdGlvbihkYXRhSGV4LCBwZW1IZWFkZXIpIHtcblx0dmFyIGRhdGFXQSA9IENyeXB0b0pTLmVuYy5IZXgucGFyc2UoZGF0YUhleCk7XG5cdHZhciBkYXRhQjY0ID0gQ3J5cHRvSlMuZW5jLkJhc2U2NC5zdHJpbmdpZnkoZGF0YVdBKTtcblx0dmFyIHBlbUJvZHkgPSBkYXRhQjY0LnJlcGxhY2UoLyguezY0fSkvZywgXCIkMVxcclxcblwiKTtcbiAgICAgICAgcGVtQm9keSA9IHBlbUJvZHkucmVwbGFjZSgvXFxyXFxuJC8sICcnKTtcblx0cmV0dXJuIFwiLS0tLS1CRUdJTiBcIiArIHBlbUhlYWRlciArIFwiLS0tLS1cXHJcXG5cIiArIFxuICAgICAgICAgICAgICAgcGVtQm9keSArIFxuICAgICAgICAgICAgICAgXCJcXHJcXG4tLS0tLUVORCBcIiArIHBlbUhlYWRlciArIFwiLS0tLS1cXHJcXG5cIjtcbiAgICB9O1xufTtcblxuLy8gKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcbi8vICBBYnN0cmFjdCBBU04uMSBDbGFzc2VzXG4vLyAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxuXG4vLyAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxuXG4vKipcbiAqIGJhc2UgY2xhc3MgZm9yIEFTTi4xIERFUiBlbmNvZGVyIG9iamVjdFxuICogQG5hbWUgS0pVUi5hc24xLkFTTjFPYmplY3RcbiAqIEBjbGFzcyBiYXNlIGNsYXNzIGZvciBBU04uMSBERVIgZW5jb2RlciBvYmplY3RcbiAqIEBwcm9wZXJ0eSB7Qm9vbGVhbn0gaXNNb2RpZmllZCBmbGFnIHdoZXRoZXIgaW50ZXJuYWwgZGF0YSB3YXMgY2hhbmdlZFxuICogQHByb3BlcnR5IHtTdHJpbmd9IGhUTFYgaGV4YWRlY2ltYWwgc3RyaW5nIG9mIEFTTi4xIFRMVlxuICogQHByb3BlcnR5IHtTdHJpbmd9IGhUIGhleGFkZWNpbWFsIHN0cmluZyBvZiBBU04uMSBUTFYgdGFnKFQpXG4gKiBAcHJvcGVydHkge1N0cmluZ30gaEwgaGV4YWRlY2ltYWwgc3RyaW5nIG9mIEFTTi4xIFRMViBsZW5ndGgoTClcbiAqIEBwcm9wZXJ0eSB7U3RyaW5nfSBoViBoZXhhZGVjaW1hbCBzdHJpbmcgb2YgQVNOLjEgVExWIHZhbHVlKFYpXG4gKiBAZGVzY3JpcHRpb25cbiAqL1xuS0pVUi5hc24xLkFTTjFPYmplY3QgPSBmdW5jdGlvbigpIHtcbiAgICB2YXIgaXNNb2RpZmllZCA9IHRydWU7XG4gICAgdmFyIGhUTFYgPSBudWxsO1xuICAgIHZhciBoVCA9ICcwMCdcbiAgICB2YXIgaEwgPSAnMDAnO1xuICAgIHZhciBoViA9ICcnO1xuXG4gICAgLyoqXG4gICAgICogZ2V0IGhleGFkZWNpbWFsIEFTTi4xIFRMViBsZW5ndGgoTCkgYnl0ZXMgZnJvbSBUTFYgdmFsdWUoVilcbiAgICAgKiBAbmFtZSBnZXRMZW5ndGhIZXhGcm9tVmFsdWVcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkFTTjFPYmplY3RcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcmV0dXJuIHtTdHJpbmd9IGhleGFkZWNpbWFsIHN0cmluZyBvZiBBU04uMSBUTFYgbGVuZ3RoKEwpXG4gICAgICovXG4gICAgdGhpcy5nZXRMZW5ndGhIZXhGcm9tVmFsdWUgPSBmdW5jdGlvbigpIHtcblx0aWYgKHR5cGVvZiB0aGlzLmhWID09IFwidW5kZWZpbmVkXCIgfHwgdGhpcy5oViA9PSBudWxsKSB7XG5cdCAgICB0aHJvdyBcInRoaXMuaFYgaXMgbnVsbCBvciB1bmRlZmluZWQuXCI7XG5cdH1cblx0aWYgKHRoaXMuaFYubGVuZ3RoICUgMiA9PSAxKSB7XG5cdCAgICB0aHJvdyBcInZhbHVlIGhleCBtdXN0IGJlIGV2ZW4gbGVuZ3RoOiBuPVwiICsgaFYubGVuZ3RoICsgXCIsdj1cIiArIHRoaXMuaFY7XG5cdH1cblx0dmFyIG4gPSB0aGlzLmhWLmxlbmd0aCAvIDI7XG5cdHZhciBoTiA9IG4udG9TdHJpbmcoMTYpO1xuXHRpZiAoaE4ubGVuZ3RoICUgMiA9PSAxKSB7XG5cdCAgICBoTiA9IFwiMFwiICsgaE47XG5cdH1cblx0aWYgKG4gPCAxMjgpIHtcblx0ICAgIHJldHVybiBoTjtcblx0fSBlbHNlIHtcblx0ICAgIHZhciBoTmxlbiA9IGhOLmxlbmd0aCAvIDI7XG5cdCAgICBpZiAoaE5sZW4gPiAxNSkge1xuXHRcdHRocm93IFwiQVNOLjEgbGVuZ3RoIHRvbyBsb25nIHRvIHJlcHJlc2VudCBieSA4eDogbiA9IFwiICsgbi50b1N0cmluZygxNik7XG5cdCAgICB9XG5cdCAgICB2YXIgaGVhZCA9IDEyOCArIGhObGVuO1xuXHQgICAgcmV0dXJuIGhlYWQudG9TdHJpbmcoMTYpICsgaE47XG5cdH1cbiAgICB9O1xuXG4gICAgLyoqXG4gICAgICogZ2V0IGhleGFkZWNpbWFsIHN0cmluZyBvZiBBU04uMSBUTFYgYnl0ZXNcbiAgICAgKiBAbmFtZSBnZXRFbmNvZGVkSGV4XG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5BU04xT2JqZWN0XG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHJldHVybiB7U3RyaW5nfSBoZXhhZGVjaW1hbCBzdHJpbmcgb2YgQVNOLjEgVExWXG4gICAgICovXG4gICAgdGhpcy5nZXRFbmNvZGVkSGV4ID0gZnVuY3Rpb24oKSB7XG5cdGlmICh0aGlzLmhUTFYgPT0gbnVsbCB8fCB0aGlzLmlzTW9kaWZpZWQpIHtcblx0ICAgIHRoaXMuaFYgPSB0aGlzLmdldEZyZXNoVmFsdWVIZXgoKTtcblx0ICAgIHRoaXMuaEwgPSB0aGlzLmdldExlbmd0aEhleEZyb21WYWx1ZSgpO1xuXHQgICAgdGhpcy5oVExWID0gdGhpcy5oVCArIHRoaXMuaEwgKyB0aGlzLmhWO1xuXHQgICAgdGhpcy5pc01vZGlmaWVkID0gZmFsc2U7XG5cdCAgICAvL2NvbnNvbGUuZXJyb3IoXCJmaXJzdCB0aW1lOiBcIiArIHRoaXMuaFRMVik7XG5cdH1cblx0cmV0dXJuIHRoaXMuaFRMVjtcbiAgICB9O1xuXG4gICAgLyoqXG4gICAgICogZ2V0IGhleGFkZWNpbWFsIHN0cmluZyBvZiBBU04uMSBUTFYgdmFsdWUoVikgYnl0ZXNcbiAgICAgKiBAbmFtZSBnZXRWYWx1ZUhleFxuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuQVNOMU9iamVjdFxuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEByZXR1cm4ge1N0cmluZ30gaGV4YWRlY2ltYWwgc3RyaW5nIG9mIEFTTi4xIFRMViB2YWx1ZShWKSBieXRlc1xuICAgICAqL1xuICAgIHRoaXMuZ2V0VmFsdWVIZXggPSBmdW5jdGlvbigpIHtcblx0dGhpcy5nZXRFbmNvZGVkSGV4KCk7XG5cdHJldHVybiB0aGlzLmhWO1xuICAgIH1cblxuICAgIHRoaXMuZ2V0RnJlc2hWYWx1ZUhleCA9IGZ1bmN0aW9uKCkge1xuXHRyZXR1cm4gJyc7XG4gICAgfTtcbn07XG5cbi8vID09IEJFR0lOIERFUkFic3RyYWN0U3RyaW5nID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxuLyoqXG4gKiBiYXNlIGNsYXNzIGZvciBBU04uMSBERVIgc3RyaW5nIGNsYXNzZXNcbiAqIEBuYW1lIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZ1xuICogQGNsYXNzIGJhc2UgY2xhc3MgZm9yIEFTTi4xIERFUiBzdHJpbmcgY2xhc3Nlc1xuICogQHBhcmFtIHtBcnJheX0gcGFyYW1zIGFzc29jaWF0aXZlIGFycmF5IG9mIHBhcmFtZXRlcnMgKGV4LiB7J3N0cic6ICdhYWEnfSlcbiAqIEBwcm9wZXJ0eSB7U3RyaW5nfSBzIGludGVybmFsIHN0cmluZyBvZiB2YWx1ZVxuICogQGV4dGVuZHMgS0pVUi5hc24xLkFTTjFPYmplY3RcbiAqIEBkZXNjcmlwdGlvblxuICogPGJyLz5cbiAqIEFzIGZvciBhcmd1bWVudCAncGFyYW1zJyBmb3IgY29uc3RydWN0b3IsIHlvdSBjYW4gc3BlY2lmeSBvbmUgb2ZcbiAqIGZvbGxvd2luZyBwcm9wZXJ0aWVzOlxuICogPHVsPlxuICogPGxpPnN0ciAtIHNwZWNpZnkgaW5pdGlhbCBBU04uMSB2YWx1ZShWKSBieSBhIHN0cmluZzwvbGk+XG4gKiA8bGk+aGV4IC0gc3BlY2lmeSBpbml0aWFsIEFTTi4xIHZhbHVlKFYpIGJ5IGEgaGV4YWRlY2ltYWwgc3RyaW5nPC9saT5cbiAqIDwvdWw+XG4gKiBOT1RFOiAncGFyYW1zJyBjYW4gYmUgb21pdHRlZC5cbiAqL1xuS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nID0gZnVuY3Rpb24ocGFyYW1zKSB7XG4gICAgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nLnN1cGVyY2xhc3MuY29uc3RydWN0b3IuY2FsbCh0aGlzKTtcbiAgICB2YXIgcyA9IG51bGw7XG4gICAgdmFyIGhWID0gbnVsbDtcblxuICAgIC8qKlxuICAgICAqIGdldCBzdHJpbmcgdmFsdWUgb2YgdGhpcyBzdHJpbmcgb2JqZWN0XG4gICAgICogQG5hbWUgZ2V0U3RyaW5nXG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZ1xuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEByZXR1cm4ge1N0cmluZ30gc3RyaW5nIHZhbHVlIG9mIHRoaXMgc3RyaW5nIG9iamVjdFxuICAgICAqL1xuICAgIHRoaXMuZ2V0U3RyaW5nID0gZnVuY3Rpb24oKSB7XG5cdHJldHVybiB0aGlzLnM7XG4gICAgfTtcblxuICAgIC8qKlxuICAgICAqIHNldCB2YWx1ZSBieSBhIHN0cmluZ1xuICAgICAqIEBuYW1lIHNldFN0cmluZ1xuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmdcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcGFyYW0ge1N0cmluZ30gbmV3UyB2YWx1ZSBieSBhIHN0cmluZyB0byBzZXRcbiAgICAgKi9cbiAgICB0aGlzLnNldFN0cmluZyA9IGZ1bmN0aW9uKG5ld1MpIHtcblx0dGhpcy5oVExWID0gbnVsbDtcblx0dGhpcy5pc01vZGlmaWVkID0gdHJ1ZTtcblx0dGhpcy5zID0gbmV3Uztcblx0dGhpcy5oViA9IHN0b2hleCh0aGlzLnMpO1xuICAgIH07XG5cbiAgICAvKipcbiAgICAgKiBzZXQgdmFsdWUgYnkgYSBoZXhhZGVjaW1hbCBzdHJpbmdcbiAgICAgKiBAbmFtZSBzZXRTdHJpbmdIZXhcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nXG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHBhcmFtIHtTdHJpbmd9IG5ld0hleFN0cmluZyB2YWx1ZSBieSBhIGhleGFkZWNpbWFsIHN0cmluZyB0byBzZXRcbiAgICAgKi9cbiAgICB0aGlzLnNldFN0cmluZ0hleCA9IGZ1bmN0aW9uKG5ld0hleFN0cmluZykge1xuXHR0aGlzLmhUTFYgPSBudWxsO1xuXHR0aGlzLmlzTW9kaWZpZWQgPSB0cnVlO1xuXHR0aGlzLnMgPSBudWxsO1xuXHR0aGlzLmhWID0gbmV3SGV4U3RyaW5nO1xuICAgIH07XG5cbiAgICB0aGlzLmdldEZyZXNoVmFsdWVIZXggPSBmdW5jdGlvbigpIHtcblx0cmV0dXJuIHRoaXMuaFY7XG4gICAgfTtcblxuICAgIGlmICh0eXBlb2YgcGFyYW1zICE9IFwidW5kZWZpbmVkXCIpIHtcblx0aWYgKHR5cGVvZiBwYXJhbXNbJ3N0ciddICE9IFwidW5kZWZpbmVkXCIpIHtcblx0ICAgIHRoaXMuc2V0U3RyaW5nKHBhcmFtc1snc3RyJ10pO1xuXHR9IGVsc2UgaWYgKHR5cGVvZiBwYXJhbXNbJ2hleCddICE9IFwidW5kZWZpbmVkXCIpIHtcblx0ICAgIHRoaXMuc2V0U3RyaW5nSGV4KHBhcmFtc1snaGV4J10pO1xuXHR9XG4gICAgfVxufTtcbkpTWC5leHRlbmQoS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nLCBLSlVSLmFzbjEuQVNOMU9iamVjdCk7XG4vLyA9PSBFTkQgICBERVJBYnN0cmFjdFN0cmluZyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cblxuLy8gPT0gQkVHSU4gREVSQWJzdHJhY3RUaW1lID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG4vKipcbiAqIGJhc2UgY2xhc3MgZm9yIEFTTi4xIERFUiBHZW5lcmFsaXplZC9VVENUaW1lIGNsYXNzXG4gKiBAbmFtZSBLSlVSLmFzbjEuREVSQWJzdHJhY3RUaW1lXG4gKiBAY2xhc3MgYmFzZSBjbGFzcyBmb3IgQVNOLjEgREVSIEdlbmVyYWxpemVkL1VUQ1RpbWUgY2xhc3NcbiAqIEBwYXJhbSB7QXJyYXl9IHBhcmFtcyBhc3NvY2lhdGl2ZSBhcnJheSBvZiBwYXJhbWV0ZXJzIChleC4geydzdHInOiAnMTMwNDMwMjM1OTU5Wid9KVxuICogQGV4dGVuZHMgS0pVUi5hc24xLkFTTjFPYmplY3RcbiAqIEBkZXNjcmlwdGlvblxuICogQHNlZSBLSlVSLmFzbjEuQVNOMU9iamVjdCAtIHN1cGVyY2xhc3NcbiAqL1xuS0pVUi5hc24xLkRFUkFic3RyYWN0VGltZSA9IGZ1bmN0aW9uKHBhcmFtcykge1xuICAgIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFRpbWUuc3VwZXJjbGFzcy5jb25zdHJ1Y3Rvci5jYWxsKHRoaXMpO1xuICAgIHZhciBzID0gbnVsbDtcbiAgICB2YXIgZGF0ZSA9IG51bGw7XG5cbiAgICAvLyAtLS0gUFJJVkFURSBNRVRIT0RTIC0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gICAgdGhpcy5sb2NhbERhdGVUb1VUQyA9IGZ1bmN0aW9uKGQpIHtcblx0dXRjID0gZC5nZXRUaW1lKCkgKyAoZC5nZXRUaW1lem9uZU9mZnNldCgpICogNjAwMDApO1xuXHR2YXIgdXRjRGF0ZSA9IG5ldyBEYXRlKHV0Yyk7XG5cdHJldHVybiB1dGNEYXRlO1xuICAgIH07XG5cbiAgICB0aGlzLmZvcm1hdERhdGUgPSBmdW5jdGlvbihkYXRlT2JqZWN0LCB0eXBlKSB7XG5cdHZhciBwYWQgPSB0aGlzLnplcm9QYWRkaW5nO1xuXHR2YXIgZCA9IHRoaXMubG9jYWxEYXRlVG9VVEMoZGF0ZU9iamVjdCk7XG5cdHZhciB5ZWFyID0gU3RyaW5nKGQuZ2V0RnVsbFllYXIoKSk7XG5cdGlmICh0eXBlID09ICd1dGMnKSB5ZWFyID0geWVhci5zdWJzdHIoMiwgMik7XG5cdHZhciBtb250aCA9IHBhZChTdHJpbmcoZC5nZXRNb250aCgpICsgMSksIDIpO1xuXHR2YXIgZGF5ID0gcGFkKFN0cmluZyhkLmdldERhdGUoKSksIDIpO1xuXHR2YXIgaG91ciA9IHBhZChTdHJpbmcoZC5nZXRIb3VycygpKSwgMik7XG5cdHZhciBtaW4gPSBwYWQoU3RyaW5nKGQuZ2V0TWludXRlcygpKSwgMik7XG5cdHZhciBzZWMgPSBwYWQoU3RyaW5nKGQuZ2V0U2Vjb25kcygpKSwgMik7XG5cdHJldHVybiB5ZWFyICsgbW9udGggKyBkYXkgKyBob3VyICsgbWluICsgc2VjICsgJ1onO1xuICAgIH07XG5cbiAgICB0aGlzLnplcm9QYWRkaW5nID0gZnVuY3Rpb24ocywgbGVuKSB7XG5cdGlmIChzLmxlbmd0aCA+PSBsZW4pIHJldHVybiBzO1xuXHRyZXR1cm4gbmV3IEFycmF5KGxlbiAtIHMubGVuZ3RoICsgMSkuam9pbignMCcpICsgcztcbiAgICB9O1xuXG4gICAgLy8gLS0tIFBVQkxJQyBNRVRIT0RTIC0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gICAgLyoqXG4gICAgICogZ2V0IHN0cmluZyB2YWx1ZSBvZiB0aGlzIHN0cmluZyBvYmplY3RcbiAgICAgKiBAbmFtZSBnZXRTdHJpbmdcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkRFUkFic3RyYWN0VGltZVxuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEByZXR1cm4ge1N0cmluZ30gc3RyaW5nIHZhbHVlIG9mIHRoaXMgdGltZSBvYmplY3RcbiAgICAgKi9cbiAgICB0aGlzLmdldFN0cmluZyA9IGZ1bmN0aW9uKCkge1xuXHRyZXR1cm4gdGhpcy5zO1xuICAgIH07XG5cbiAgICAvKipcbiAgICAgKiBzZXQgdmFsdWUgYnkgYSBzdHJpbmdcbiAgICAgKiBAbmFtZSBzZXRTdHJpbmdcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkRFUkFic3RyYWN0VGltZVxuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEBwYXJhbSB7U3RyaW5nfSBuZXdTIHZhbHVlIGJ5IGEgc3RyaW5nIHRvIHNldCBzdWNoIGxpa2UgXCIxMzA0MzAyMzU5NTlaXCJcbiAgICAgKi9cbiAgICB0aGlzLnNldFN0cmluZyA9IGZ1bmN0aW9uKG5ld1MpIHtcblx0dGhpcy5oVExWID0gbnVsbDtcblx0dGhpcy5pc01vZGlmaWVkID0gdHJ1ZTtcblx0dGhpcy5zID0gbmV3Uztcblx0dGhpcy5oViA9IHN0b2hleCh0aGlzLnMpO1xuICAgIH07XG5cbiAgICAvKipcbiAgICAgKiBzZXQgdmFsdWUgYnkgYSBEYXRlIG9iamVjdFxuICAgICAqIEBuYW1lIHNldEJ5RGF0ZVZhbHVlXG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFRpbWVcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcGFyYW0ge0ludGVnZXJ9IHllYXIgeWVhciBvZiBkYXRlIChleC4gMjAxMylcbiAgICAgKiBAcGFyYW0ge0ludGVnZXJ9IG1vbnRoIG1vbnRoIG9mIGRhdGUgYmV0d2VlbiAxIGFuZCAxMiAoZXguIDEyKVxuICAgICAqIEBwYXJhbSB7SW50ZWdlcn0gZGF5IGRheSBvZiBtb250aFxuICAgICAqIEBwYXJhbSB7SW50ZWdlcn0gaG91ciBob3VycyBvZiBkYXRlXG4gICAgICogQHBhcmFtIHtJbnRlZ2VyfSBtaW4gbWludXRlcyBvZiBkYXRlXG4gICAgICogQHBhcmFtIHtJbnRlZ2VyfSBzZWMgc2Vjb25kcyBvZiBkYXRlXG4gICAgICovXG4gICAgdGhpcy5zZXRCeURhdGVWYWx1ZSA9IGZ1bmN0aW9uKHllYXIsIG1vbnRoLCBkYXksIGhvdXIsIG1pbiwgc2VjKSB7XG5cdHZhciBkYXRlT2JqZWN0ID0gbmV3IERhdGUoRGF0ZS5VVEMoeWVhciwgbW9udGggLSAxLCBkYXksIGhvdXIsIG1pbiwgc2VjLCAwKSk7XG5cdHRoaXMuc2V0QnlEYXRlKGRhdGVPYmplY3QpO1xuICAgIH07XG5cbiAgICB0aGlzLmdldEZyZXNoVmFsdWVIZXggPSBmdW5jdGlvbigpIHtcblx0cmV0dXJuIHRoaXMuaFY7XG4gICAgfTtcbn07XG5KU1guZXh0ZW5kKEtKVVIuYXNuMS5ERVJBYnN0cmFjdFRpbWUsIEtKVVIuYXNuMS5BU04xT2JqZWN0KTtcbi8vID09IEVORCAgIERFUkFic3RyYWN0VGltZSA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxuXG4vLyA9PSBCRUdJTiBERVJBYnN0cmFjdFN0cnVjdHVyZWQgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cbi8qKlxuICogYmFzZSBjbGFzcyBmb3IgQVNOLjEgREVSIHN0cnVjdHVyZWQgY2xhc3NcbiAqIEBuYW1lIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cnVjdHVyZWRcbiAqIEBjbGFzcyBiYXNlIGNsYXNzIGZvciBBU04uMSBERVIgc3RydWN0dXJlZCBjbGFzc1xuICogQHByb3BlcnR5IHtBcnJheX0gYXNuMUFycmF5IGludGVybmFsIGFycmF5IG9mIEFTTjFPYmplY3RcbiAqIEBleHRlbmRzIEtKVVIuYXNuMS5BU04xT2JqZWN0XG4gKiBAZGVzY3JpcHRpb25cbiAqIEBzZWUgS0pVUi5hc24xLkFTTjFPYmplY3QgLSBzdXBlcmNsYXNzXG4gKi9cbktKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cnVjdHVyZWQgPSBmdW5jdGlvbihwYXJhbXMpIHtcbiAgICBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmcuc3VwZXJjbGFzcy5jb25zdHJ1Y3Rvci5jYWxsKHRoaXMpO1xuICAgIHZhciBhc24xQXJyYXkgPSBudWxsO1xuXG4gICAgLyoqXG4gICAgICogc2V0IHZhbHVlIGJ5IGFycmF5IG9mIEFTTjFPYmplY3RcbiAgICAgKiBAbmFtZSBzZXRCeUFTTjFPYmplY3RBcnJheVxuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJ1Y3R1cmVkXG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHBhcmFtIHthcnJheX0gYXNuMU9iamVjdEFycmF5IGFycmF5IG9mIEFTTjFPYmplY3QgdG8gc2V0XG4gICAgICovXG4gICAgdGhpcy5zZXRCeUFTTjFPYmplY3RBcnJheSA9IGZ1bmN0aW9uKGFzbjFPYmplY3RBcnJheSkge1xuXHR0aGlzLmhUTFYgPSBudWxsO1xuXHR0aGlzLmlzTW9kaWZpZWQgPSB0cnVlO1xuXHR0aGlzLmFzbjFBcnJheSA9IGFzbjFPYmplY3RBcnJheTtcbiAgICB9O1xuXG4gICAgLyoqXG4gICAgICogYXBwZW5kIGFuIEFTTjFPYmplY3QgdG8gaW50ZXJuYWwgYXJyYXlcbiAgICAgKiBAbmFtZSBhcHBlbmRBU04xT2JqZWN0XG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cnVjdHVyZWRcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcGFyYW0ge0FTTjFPYmplY3R9IGFzbjFPYmplY3QgdG8gYWRkXG4gICAgICovXG4gICAgdGhpcy5hcHBlbmRBU04xT2JqZWN0ID0gZnVuY3Rpb24oYXNuMU9iamVjdCkge1xuXHR0aGlzLmhUTFYgPSBudWxsO1xuXHR0aGlzLmlzTW9kaWZpZWQgPSB0cnVlO1xuXHR0aGlzLmFzbjFBcnJheS5wdXNoKGFzbjFPYmplY3QpO1xuICAgIH07XG5cbiAgICB0aGlzLmFzbjFBcnJheSA9IG5ldyBBcnJheSgpO1xuICAgIGlmICh0eXBlb2YgcGFyYW1zICE9IFwidW5kZWZpbmVkXCIpIHtcblx0aWYgKHR5cGVvZiBwYXJhbXNbJ2FycmF5J10gIT0gXCJ1bmRlZmluZWRcIikge1xuXHQgICAgdGhpcy5hc24xQXJyYXkgPSBwYXJhbXNbJ2FycmF5J107XG5cdH1cbiAgICB9XG59O1xuSlNYLmV4dGVuZChLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJ1Y3R1cmVkLCBLSlVSLmFzbjEuQVNOMU9iamVjdCk7XG5cblxuLy8gKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcbi8vICBBU04uMSBPYmplY3QgQ2xhc3Nlc1xuLy8gKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcblxuLy8gKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcbi8qKlxuICogY2xhc3MgZm9yIEFTTi4xIERFUiBCb29sZWFuXG4gKiBAbmFtZSBLSlVSLmFzbjEuREVSQm9vbGVhblxuICogQGNsYXNzIGNsYXNzIGZvciBBU04uMSBERVIgQm9vbGVhblxuICogQGV4dGVuZHMgS0pVUi5hc24xLkFTTjFPYmplY3RcbiAqIEBkZXNjcmlwdGlvblxuICogQHNlZSBLSlVSLmFzbjEuQVNOMU9iamVjdCAtIHN1cGVyY2xhc3NcbiAqL1xuS0pVUi5hc24xLkRFUkJvb2xlYW4gPSBmdW5jdGlvbigpIHtcbiAgICBLSlVSLmFzbjEuREVSQm9vbGVhbi5zdXBlcmNsYXNzLmNvbnN0cnVjdG9yLmNhbGwodGhpcyk7XG4gICAgdGhpcy5oVCA9IFwiMDFcIjtcbiAgICB0aGlzLmhUTFYgPSBcIjAxMDFmZlwiO1xufTtcbkpTWC5leHRlbmQoS0pVUi5hc24xLkRFUkJvb2xlYW4sIEtKVVIuYXNuMS5BU04xT2JqZWN0KTtcblxuLy8gKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcbi8qKlxuICogY2xhc3MgZm9yIEFTTi4xIERFUiBJbnRlZ2VyXG4gKiBAbmFtZSBLSlVSLmFzbjEuREVSSW50ZWdlclxuICogQGNsYXNzIGNsYXNzIGZvciBBU04uMSBERVIgSW50ZWdlclxuICogQGV4dGVuZHMgS0pVUi5hc24xLkFTTjFPYmplY3RcbiAqIEBkZXNjcmlwdGlvblxuICogPGJyLz5cbiAqIEFzIGZvciBhcmd1bWVudCAncGFyYW1zJyBmb3IgY29uc3RydWN0b3IsIHlvdSBjYW4gc3BlY2lmeSBvbmUgb2ZcbiAqIGZvbGxvd2luZyBwcm9wZXJ0aWVzOlxuICogPHVsPlxuICogPGxpPmludCAtIHNwZWNpZnkgaW5pdGlhbCBBU04uMSB2YWx1ZShWKSBieSBpbnRlZ2VyIHZhbHVlPC9saT5cbiAqIDxsaT5iaWdpbnQgLSBzcGVjaWZ5IGluaXRpYWwgQVNOLjEgdmFsdWUoVikgYnkgQmlnSW50ZWdlciBvYmplY3Q8L2xpPlxuICogPGxpPmhleCAtIHNwZWNpZnkgaW5pdGlhbCBBU04uMSB2YWx1ZShWKSBieSBhIGhleGFkZWNpbWFsIHN0cmluZzwvbGk+XG4gKiA8L3VsPlxuICogTk9URTogJ3BhcmFtcycgY2FuIGJlIG9taXR0ZWQuXG4gKi9cbktKVVIuYXNuMS5ERVJJbnRlZ2VyID0gZnVuY3Rpb24ocGFyYW1zKSB7XG4gICAgS0pVUi5hc24xLkRFUkludGVnZXIuc3VwZXJjbGFzcy5jb25zdHJ1Y3Rvci5jYWxsKHRoaXMpO1xuICAgIHRoaXMuaFQgPSBcIjAyXCI7XG5cbiAgICAvKipcbiAgICAgKiBzZXQgdmFsdWUgYnkgVG9tIFd1J3MgQmlnSW50ZWdlciBvYmplY3RcbiAgICAgKiBAbmFtZSBzZXRCeUJpZ0ludGVnZXJcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkRFUkludGVnZXJcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcGFyYW0ge0JpZ0ludGVnZXJ9IGJpZ0ludGVnZXJWYWx1ZSB0byBzZXRcbiAgICAgKi9cbiAgICB0aGlzLnNldEJ5QmlnSW50ZWdlciA9IGZ1bmN0aW9uKGJpZ0ludGVnZXJWYWx1ZSkge1xuXHR0aGlzLmhUTFYgPSBudWxsO1xuXHR0aGlzLmlzTW9kaWZpZWQgPSB0cnVlO1xuXHR0aGlzLmhWID0gS0pVUi5hc24xLkFTTjFVdGlsLmJpZ0ludFRvTWluVHdvc0NvbXBsZW1lbnRzSGV4KGJpZ0ludGVnZXJWYWx1ZSk7XG4gICAgfTtcblxuICAgIC8qKlxuICAgICAqIHNldCB2YWx1ZSBieSBpbnRlZ2VyIHZhbHVlXG4gICAgICogQG5hbWUgc2V0QnlJbnRlZ2VyXG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5ERVJJbnRlZ2VyXG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHBhcmFtIHtJbnRlZ2VyfSBpbnRlZ2VyIHZhbHVlIHRvIHNldFxuICAgICAqL1xuICAgIHRoaXMuc2V0QnlJbnRlZ2VyID0gZnVuY3Rpb24oaW50VmFsdWUpIHtcblx0dmFyIGJpID0gbmV3IEJpZ0ludGVnZXIoU3RyaW5nKGludFZhbHVlKSwgMTApO1xuXHR0aGlzLnNldEJ5QmlnSW50ZWdlcihiaSk7XG4gICAgfTtcblxuICAgIC8qKlxuICAgICAqIHNldCB2YWx1ZSBieSBpbnRlZ2VyIHZhbHVlXG4gICAgICogQG5hbWUgc2V0VmFsdWVIZXhcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkRFUkludGVnZXJcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcGFyYW0ge1N0cmluZ30gaGV4YWRlY2ltYWwgc3RyaW5nIG9mIGludGVnZXIgdmFsdWVcbiAgICAgKiBAZGVzY3JpcHRpb25cbiAgICAgKiA8YnIvPlxuICAgICAqIE5PVEU6IFZhbHVlIHNoYWxsIGJlIHJlcHJlc2VudGVkIGJ5IG1pbmltdW0gb2N0ZXQgbGVuZ3RoIG9mXG4gICAgICogdHdvJ3MgY29tcGxlbWVudCByZXByZXNlbnRhdGlvbi5cbiAgICAgKi9cbiAgICB0aGlzLnNldFZhbHVlSGV4ID0gZnVuY3Rpb24obmV3SGV4U3RyaW5nKSB7XG5cdHRoaXMuaFYgPSBuZXdIZXhTdHJpbmc7XG4gICAgfTtcblxuICAgIHRoaXMuZ2V0RnJlc2hWYWx1ZUhleCA9IGZ1bmN0aW9uKCkge1xuXHRyZXR1cm4gdGhpcy5oVjtcbiAgICB9O1xuXG4gICAgaWYgKHR5cGVvZiBwYXJhbXMgIT0gXCJ1bmRlZmluZWRcIikge1xuXHRpZiAodHlwZW9mIHBhcmFtc1snYmlnaW50J10gIT0gXCJ1bmRlZmluZWRcIikge1xuXHQgICAgdGhpcy5zZXRCeUJpZ0ludGVnZXIocGFyYW1zWydiaWdpbnQnXSk7XG5cdH0gZWxzZSBpZiAodHlwZW9mIHBhcmFtc1snaW50J10gIT0gXCJ1bmRlZmluZWRcIikge1xuXHQgICAgdGhpcy5zZXRCeUludGVnZXIocGFyYW1zWydpbnQnXSk7XG5cdH0gZWxzZSBpZiAodHlwZW9mIHBhcmFtc1snaGV4J10gIT0gXCJ1bmRlZmluZWRcIikge1xuXHQgICAgdGhpcy5zZXRWYWx1ZUhleChwYXJhbXNbJ2hleCddKTtcblx0fVxuICAgIH1cbn07XG5KU1guZXh0ZW5kKEtKVVIuYXNuMS5ERVJJbnRlZ2VyLCBLSlVSLmFzbjEuQVNOMU9iamVjdCk7XG5cbi8vICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXG4vKipcbiAqIGNsYXNzIGZvciBBU04uMSBERVIgZW5jb2RlZCBCaXRTdHJpbmcgcHJpbWl0aXZlXG4gKiBAbmFtZSBLSlVSLmFzbjEuREVSQml0U3RyaW5nXG4gKiBAY2xhc3MgY2xhc3MgZm9yIEFTTi4xIERFUiBlbmNvZGVkIEJpdFN0cmluZyBwcmltaXRpdmVcbiAqIEBleHRlbmRzIEtKVVIuYXNuMS5BU04xT2JqZWN0XG4gKiBAZGVzY3JpcHRpb24gXG4gKiA8YnIvPlxuICogQXMgZm9yIGFyZ3VtZW50ICdwYXJhbXMnIGZvciBjb25zdHJ1Y3RvciwgeW91IGNhbiBzcGVjaWZ5IG9uZSBvZlxuICogZm9sbG93aW5nIHByb3BlcnRpZXM6XG4gKiA8dWw+XG4gKiA8bGk+YmluIC0gc3BlY2lmeSBiaW5hcnkgc3RyaW5nIChleC4gJzEwMTExJyk8L2xpPlxuICogPGxpPmFycmF5IC0gc3BlY2lmeSBhcnJheSBvZiBib29sZWFuIChleC4gW3RydWUsZmFsc2UsdHJ1ZSx0cnVlXSk8L2xpPlxuICogPGxpPmhleCAtIHNwZWNpZnkgaGV4YWRlY2ltYWwgc3RyaW5nIG9mIEFTTi4xIHZhbHVlKFYpIGluY2x1ZGluZyB1bnVzZWQgYml0czwvbGk+XG4gKiA8L3VsPlxuICogTk9URTogJ3BhcmFtcycgY2FuIGJlIG9taXR0ZWQuXG4gKi9cbktKVVIuYXNuMS5ERVJCaXRTdHJpbmcgPSBmdW5jdGlvbihwYXJhbXMpIHtcbiAgICBLSlVSLmFzbjEuREVSQml0U3RyaW5nLnN1cGVyY2xhc3MuY29uc3RydWN0b3IuY2FsbCh0aGlzKTtcbiAgICB0aGlzLmhUID0gXCIwM1wiO1xuXG4gICAgLyoqXG4gICAgICogc2V0IEFTTi4xIHZhbHVlKFYpIGJ5IGEgaGV4YWRlY2ltYWwgc3RyaW5nIGluY2x1ZGluZyB1bnVzZWQgYml0c1xuICAgICAqIEBuYW1lIHNldEhleFZhbHVlSW5jbHVkaW5nVW51c2VkQml0c1xuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuREVSQml0U3RyaW5nXG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHBhcmFtIHtTdHJpbmd9IG5ld0hleFN0cmluZ0luY2x1ZGluZ1VudXNlZEJpdHNcbiAgICAgKi9cbiAgICB0aGlzLnNldEhleFZhbHVlSW5jbHVkaW5nVW51c2VkQml0cyA9IGZ1bmN0aW9uKG5ld0hleFN0cmluZ0luY2x1ZGluZ1VudXNlZEJpdHMpIHtcblx0dGhpcy5oVExWID0gbnVsbDtcblx0dGhpcy5pc01vZGlmaWVkID0gdHJ1ZTtcblx0dGhpcy5oViA9IG5ld0hleFN0cmluZ0luY2x1ZGluZ1VudXNlZEJpdHM7XG4gICAgfTtcblxuICAgIC8qKlxuICAgICAqIHNldCBBU04uMSB2YWx1ZShWKSBieSB1bnVzZWQgYml0IGFuZCBoZXhhZGVjaW1hbCBzdHJpbmcgb2YgdmFsdWVcbiAgICAgKiBAbmFtZSBzZXRVbnVzZWRCaXRzQW5kSGV4VmFsdWVcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkRFUkJpdFN0cmluZ1xuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEBwYXJhbSB7SW50ZWdlcn0gdW51c2VkQml0c1xuICAgICAqIEBwYXJhbSB7U3RyaW5nfSBoVmFsdWVcbiAgICAgKi9cbiAgICB0aGlzLnNldFVudXNlZEJpdHNBbmRIZXhWYWx1ZSA9IGZ1bmN0aW9uKHVudXNlZEJpdHMsIGhWYWx1ZSkge1xuXHRpZiAodW51c2VkQml0cyA8IDAgfHwgNyA8IHVudXNlZEJpdHMpIHtcblx0ICAgIHRocm93IFwidW51c2VkIGJpdHMgc2hhbGwgYmUgZnJvbSAwIHRvIDc6IHUgPSBcIiArIHVudXNlZEJpdHM7XG5cdH1cblx0dmFyIGhVbnVzZWRCaXRzID0gXCIwXCIgKyB1bnVzZWRCaXRzO1xuXHR0aGlzLmhUTFYgPSBudWxsO1xuXHR0aGlzLmlzTW9kaWZpZWQgPSB0cnVlO1xuXHR0aGlzLmhWID0gaFVudXNlZEJpdHMgKyBoVmFsdWU7XG4gICAgfTtcblxuICAgIC8qKlxuICAgICAqIHNldCBBU04uMSBERVIgQml0U3RyaW5nIGJ5IGJpbmFyeSBzdHJpbmdcbiAgICAgKiBAbmFtZSBzZXRCeUJpbmFyeVN0cmluZ1xuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuREVSQml0U3RyaW5nXG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHBhcmFtIHtTdHJpbmd9IGJpbmFyeVN0cmluZyBiaW5hcnkgdmFsdWUgc3RyaW5nIChpLmUuICcxMDExMScpXG4gICAgICogQGRlc2NyaXB0aW9uXG4gICAgICogSXRzIHVudXNlZCBiaXRzIHdpbGwgYmUgY2FsY3VsYXRlZCBhdXRvbWF0aWNhbGx5IGJ5IGxlbmd0aCBvZiBcbiAgICAgKiAnYmluYXJ5VmFsdWUnLiA8YnIvPlxuICAgICAqIE5PVEU6IFRyYWlsaW5nIHplcm9zICcwJyB3aWxsIGJlIGlnbm9yZWQuXG4gICAgICovXG4gICAgdGhpcy5zZXRCeUJpbmFyeVN0cmluZyA9IGZ1bmN0aW9uKGJpbmFyeVN0cmluZykge1xuXHRiaW5hcnlTdHJpbmcgPSBiaW5hcnlTdHJpbmcucmVwbGFjZSgvMCskLywgJycpO1xuXHR2YXIgdW51c2VkQml0cyA9IDggLSBiaW5hcnlTdHJpbmcubGVuZ3RoICUgODtcblx0aWYgKHVudXNlZEJpdHMgPT0gOCkgdW51c2VkQml0cyA9IDA7XG5cdGZvciAodmFyIGkgPSAwOyBpIDw9IHVudXNlZEJpdHM7IGkrKykge1xuXHQgICAgYmluYXJ5U3RyaW5nICs9ICcwJztcblx0fVxuXHR2YXIgaCA9ICcnO1xuXHRmb3IgKHZhciBpID0gMDsgaSA8IGJpbmFyeVN0cmluZy5sZW5ndGggLSAxOyBpICs9IDgpIHtcblx0ICAgIHZhciBiID0gYmluYXJ5U3RyaW5nLnN1YnN0cihpLCA4KTtcblx0ICAgIHZhciB4ID0gcGFyc2VJbnQoYiwgMikudG9TdHJpbmcoMTYpO1xuXHQgICAgaWYgKHgubGVuZ3RoID09IDEpIHggPSAnMCcgKyB4O1xuXHQgICAgaCArPSB4OyAgXG5cdH1cblx0dGhpcy5oVExWID0gbnVsbDtcblx0dGhpcy5pc01vZGlmaWVkID0gdHJ1ZTtcblx0dGhpcy5oViA9ICcwJyArIHVudXNlZEJpdHMgKyBoO1xuICAgIH07XG5cbiAgICAvKipcbiAgICAgKiBzZXQgQVNOLjEgVExWIHZhbHVlKFYpIGJ5IGFuIGFycmF5IG9mIGJvb2xlYW5cbiAgICAgKiBAbmFtZSBzZXRCeUJvb2xlYW5BcnJheVxuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuREVSQml0U3RyaW5nXG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHBhcmFtIHthcnJheX0gYm9vbGVhbkFycmF5IGFycmF5IG9mIGJvb2xlYW4gKGV4LiBbdHJ1ZSwgZmFsc2UsIHRydWVdKVxuICAgICAqIEBkZXNjcmlwdGlvblxuICAgICAqIE5PVEU6IFRyYWlsaW5nIGZhbHNlcyB3aWxsIGJlIGlnbm9yZWQuXG4gICAgICovXG4gICAgdGhpcy5zZXRCeUJvb2xlYW5BcnJheSA9IGZ1bmN0aW9uKGJvb2xlYW5BcnJheSkge1xuXHR2YXIgcyA9ICcnO1xuXHRmb3IgKHZhciBpID0gMDsgaSA8IGJvb2xlYW5BcnJheS5sZW5ndGg7IGkrKykge1xuXHQgICAgaWYgKGJvb2xlYW5BcnJheVtpXSA9PSB0cnVlKSB7XG5cdFx0cyArPSAnMSc7XG5cdCAgICB9IGVsc2Uge1xuXHRcdHMgKz0gJzAnO1xuXHQgICAgfVxuXHR9XG5cdHRoaXMuc2V0QnlCaW5hcnlTdHJpbmcocyk7XG4gICAgfTtcblxuICAgIC8qKlxuICAgICAqIGdlbmVyYXRlIGFuIGFycmF5IG9mIGZhbHNlIHdpdGggc3BlY2lmaWVkIGxlbmd0aFxuICAgICAqIEBuYW1lIG5ld0ZhbHNlQXJyYXlcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkRFUkJpdFN0cmluZ1xuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEBwYXJhbSB7SW50ZWdlcn0gbkxlbmd0aCBsZW5ndGggb2YgYXJyYXkgdG8gZ2VuZXJhdGVcbiAgICAgKiBAcmV0dXJuIHthcnJheX0gYXJyYXkgb2YgYm9vbGVhbiBmYWx1c2VcbiAgICAgKiBAZGVzY3JpcHRpb25cbiAgICAgKiBUaGlzIHN0YXRpYyBtZXRob2QgbWF5IGJlIHVzZWZ1bCB0byBpbml0aWFsaXplIGJvb2xlYW4gYXJyYXkuXG4gICAgICovXG4gICAgdGhpcy5uZXdGYWxzZUFycmF5ID0gZnVuY3Rpb24obkxlbmd0aCkge1xuXHR2YXIgYSA9IG5ldyBBcnJheShuTGVuZ3RoKTtcblx0Zm9yICh2YXIgaSA9IDA7IGkgPCBuTGVuZ3RoOyBpKyspIHtcblx0ICAgIGFbaV0gPSBmYWxzZTtcblx0fVxuXHRyZXR1cm4gYTtcbiAgICB9O1xuXG4gICAgdGhpcy5nZXRGcmVzaFZhbHVlSGV4ID0gZnVuY3Rpb24oKSB7XG5cdHJldHVybiB0aGlzLmhWO1xuICAgIH07XG5cbiAgICBpZiAodHlwZW9mIHBhcmFtcyAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdGlmICh0eXBlb2YgcGFyYW1zWydoZXgnXSAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdCAgICB0aGlzLnNldEhleFZhbHVlSW5jbHVkaW5nVW51c2VkQml0cyhwYXJhbXNbJ2hleCddKTtcblx0fSBlbHNlIGlmICh0eXBlb2YgcGFyYW1zWydiaW4nXSAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdCAgICB0aGlzLnNldEJ5QmluYXJ5U3RyaW5nKHBhcmFtc1snYmluJ10pO1xuXHR9IGVsc2UgaWYgKHR5cGVvZiBwYXJhbXNbJ2FycmF5J10gIT0gXCJ1bmRlZmluZWRcIikge1xuXHQgICAgdGhpcy5zZXRCeUJvb2xlYW5BcnJheShwYXJhbXNbJ2FycmF5J10pO1xuXHR9XG4gICAgfVxufTtcbkpTWC5leHRlbmQoS0pVUi5hc24xLkRFUkJpdFN0cmluZywgS0pVUi5hc24xLkFTTjFPYmplY3QpO1xuXG4vLyAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxuLyoqXG4gKiBjbGFzcyBmb3IgQVNOLjEgREVSIE9jdGV0U3RyaW5nXG4gKiBAbmFtZSBLSlVSLmFzbjEuREVST2N0ZXRTdHJpbmdcbiAqIEBjbGFzcyBjbGFzcyBmb3IgQVNOLjEgREVSIE9jdGV0U3RyaW5nXG4gKiBAcGFyYW0ge0FycmF5fSBwYXJhbXMgYXNzb2NpYXRpdmUgYXJyYXkgb2YgcGFyYW1ldGVycyAoZXguIHsnc3RyJzogJ2FhYSd9KVxuICogQGV4dGVuZHMgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nXG4gKiBAZGVzY3JpcHRpb25cbiAqIEBzZWUgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nIC0gc3VwZXJjbGFzc1xuICovXG5LSlVSLmFzbjEuREVST2N0ZXRTdHJpbmcgPSBmdW5jdGlvbihwYXJhbXMpIHtcbiAgICBLSlVSLmFzbjEuREVST2N0ZXRTdHJpbmcuc3VwZXJjbGFzcy5jb25zdHJ1Y3Rvci5jYWxsKHRoaXMsIHBhcmFtcyk7XG4gICAgdGhpcy5oVCA9IFwiMDRcIjtcbn07XG5KU1guZXh0ZW5kKEtKVVIuYXNuMS5ERVJPY3RldFN0cmluZywgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nKTtcblxuLy8gKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcbi8qKlxuICogY2xhc3MgZm9yIEFTTi4xIERFUiBOdWxsXG4gKiBAbmFtZSBLSlVSLmFzbjEuREVSTnVsbFxuICogQGNsYXNzIGNsYXNzIGZvciBBU04uMSBERVIgTnVsbFxuICogQGV4dGVuZHMgS0pVUi5hc24xLkFTTjFPYmplY3RcbiAqIEBkZXNjcmlwdGlvblxuICogQHNlZSBLSlVSLmFzbjEuQVNOMU9iamVjdCAtIHN1cGVyY2xhc3NcbiAqL1xuS0pVUi5hc24xLkRFUk51bGwgPSBmdW5jdGlvbigpIHtcbiAgICBLSlVSLmFzbjEuREVSTnVsbC5zdXBlcmNsYXNzLmNvbnN0cnVjdG9yLmNhbGwodGhpcyk7XG4gICAgdGhpcy5oVCA9IFwiMDVcIjtcbiAgICB0aGlzLmhUTFYgPSBcIjA1MDBcIjtcbn07XG5KU1guZXh0ZW5kKEtKVVIuYXNuMS5ERVJOdWxsLCBLSlVSLmFzbjEuQVNOMU9iamVjdCk7XG5cbi8vICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXG4vKipcbiAqIGNsYXNzIGZvciBBU04uMSBERVIgT2JqZWN0SWRlbnRpZmllclxuICogQG5hbWUgS0pVUi5hc24xLkRFUk9iamVjdElkZW50aWZpZXJcbiAqIEBjbGFzcyBjbGFzcyBmb3IgQVNOLjEgREVSIE9iamVjdElkZW50aWZpZXJcbiAqIEBwYXJhbSB7QXJyYXl9IHBhcmFtcyBhc3NvY2lhdGl2ZSBhcnJheSBvZiBwYXJhbWV0ZXJzIChleC4geydvaWQnOiAnMi41LjQuNSd9KVxuICogQGV4dGVuZHMgS0pVUi5hc24xLkFTTjFPYmplY3RcbiAqIEBkZXNjcmlwdGlvblxuICogPGJyLz5cbiAqIEFzIGZvciBhcmd1bWVudCAncGFyYW1zJyBmb3IgY29uc3RydWN0b3IsIHlvdSBjYW4gc3BlY2lmeSBvbmUgb2ZcbiAqIGZvbGxvd2luZyBwcm9wZXJ0aWVzOlxuICogPHVsPlxuICogPGxpPm9pZCAtIHNwZWNpZnkgaW5pdGlhbCBBU04uMSB2YWx1ZShWKSBieSBhIG9pZCBzdHJpbmcgKGV4LiAyLjUuNC4xMyk8L2xpPlxuICogPGxpPmhleCAtIHNwZWNpZnkgaW5pdGlhbCBBU04uMSB2YWx1ZShWKSBieSBhIGhleGFkZWNpbWFsIHN0cmluZzwvbGk+XG4gKiA8L3VsPlxuICogTk9URTogJ3BhcmFtcycgY2FuIGJlIG9taXR0ZWQuXG4gKi9cbktKVVIuYXNuMS5ERVJPYmplY3RJZGVudGlmaWVyID0gZnVuY3Rpb24ocGFyYW1zKSB7XG4gICAgdmFyIGl0b3ggPSBmdW5jdGlvbihpKSB7XG5cdHZhciBoID0gaS50b1N0cmluZygxNik7XG5cdGlmIChoLmxlbmd0aCA9PSAxKSBoID0gJzAnICsgaDtcblx0cmV0dXJuIGg7XG4gICAgfTtcbiAgICB2YXIgcm9pZHRveCA9IGZ1bmN0aW9uKHJvaWQpIHtcblx0dmFyIGggPSAnJztcblx0dmFyIGJpID0gbmV3IEJpZ0ludGVnZXIocm9pZCwgMTApO1xuXHR2YXIgYiA9IGJpLnRvU3RyaW5nKDIpO1xuXHR2YXIgcGFkTGVuID0gNyAtIGIubGVuZ3RoICUgNztcblx0aWYgKHBhZExlbiA9PSA3KSBwYWRMZW4gPSAwO1xuXHR2YXIgYlBhZCA9ICcnO1xuXHRmb3IgKHZhciBpID0gMDsgaSA8IHBhZExlbjsgaSsrKSBiUGFkICs9ICcwJztcblx0YiA9IGJQYWQgKyBiO1xuXHRmb3IgKHZhciBpID0gMDsgaSA8IGIubGVuZ3RoIC0gMTsgaSArPSA3KSB7XG5cdCAgICB2YXIgYjggPSBiLnN1YnN0cihpLCA3KTtcblx0ICAgIGlmIChpICE9IGIubGVuZ3RoIC0gNykgYjggPSAnMScgKyBiODtcblx0ICAgIGggKz0gaXRveChwYXJzZUludChiOCwgMikpO1xuXHR9XG5cdHJldHVybiBoO1xuICAgIH1cblxuICAgIEtKVVIuYXNuMS5ERVJPYmplY3RJZGVudGlmaWVyLnN1cGVyY2xhc3MuY29uc3RydWN0b3IuY2FsbCh0aGlzKTtcbiAgICB0aGlzLmhUID0gXCIwNlwiO1xuXG4gICAgLyoqXG4gICAgICogc2V0IHZhbHVlIGJ5IGEgaGV4YWRlY2ltYWwgc3RyaW5nXG4gICAgICogQG5hbWUgc2V0VmFsdWVIZXhcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkRFUk9iamVjdElkZW50aWZpZXJcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcGFyYW0ge1N0cmluZ30gbmV3SGV4U3RyaW5nIGhleGFkZWNpbWFsIHZhbHVlIG9mIE9JRCBieXRlc1xuICAgICAqL1xuICAgIHRoaXMuc2V0VmFsdWVIZXggPSBmdW5jdGlvbihuZXdIZXhTdHJpbmcpIHtcblx0dGhpcy5oVExWID0gbnVsbDtcblx0dGhpcy5pc01vZGlmaWVkID0gdHJ1ZTtcblx0dGhpcy5zID0gbnVsbDtcblx0dGhpcy5oViA9IG5ld0hleFN0cmluZztcbiAgICB9O1xuXG4gICAgLyoqXG4gICAgICogc2V0IHZhbHVlIGJ5IGEgT0lEIHN0cmluZ1xuICAgICAqIEBuYW1lIHNldFZhbHVlT2lkU3RyaW5nXG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5ERVJPYmplY3RJZGVudGlmaWVyXG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHBhcmFtIHtTdHJpbmd9IG9pZFN0cmluZyBPSUQgc3RyaW5nIChleC4gMi41LjQuMTMpXG4gICAgICovXG4gICAgdGhpcy5zZXRWYWx1ZU9pZFN0cmluZyA9IGZ1bmN0aW9uKG9pZFN0cmluZykge1xuXHRpZiAoISBvaWRTdHJpbmcubWF0Y2goL15bMC05Ll0rJC8pKSB7XG5cdCAgICB0aHJvdyBcIm1hbGZvcm1lZCBvaWQgc3RyaW5nOiBcIiArIG9pZFN0cmluZztcblx0fVxuXHR2YXIgaCA9ICcnO1xuXHR2YXIgYSA9IG9pZFN0cmluZy5zcGxpdCgnLicpO1xuXHR2YXIgaTAgPSBwYXJzZUludChhWzBdKSAqIDQwICsgcGFyc2VJbnQoYVsxXSk7XG5cdGggKz0gaXRveChpMCk7XG5cdGEuc3BsaWNlKDAsIDIpO1xuXHRmb3IgKHZhciBpID0gMDsgaSA8IGEubGVuZ3RoOyBpKyspIHtcblx0ICAgIGggKz0gcm9pZHRveChhW2ldKTtcblx0fVxuXHR0aGlzLmhUTFYgPSBudWxsO1xuXHR0aGlzLmlzTW9kaWZpZWQgPSB0cnVlO1xuXHR0aGlzLnMgPSBudWxsO1xuXHR0aGlzLmhWID0gaDtcbiAgICB9O1xuXG4gICAgLyoqXG4gICAgICogc2V0IHZhbHVlIGJ5IGEgT0lEIG5hbWVcbiAgICAgKiBAbmFtZSBzZXRWYWx1ZU5hbWVcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkRFUk9iamVjdElkZW50aWZpZXJcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcGFyYW0ge1N0cmluZ30gb2lkTmFtZSBPSUQgbmFtZSAoZXguICdzZXJ2ZXJBdXRoJylcbiAgICAgKiBAc2luY2UgMS4wLjFcbiAgICAgKiBAZGVzY3JpcHRpb25cbiAgICAgKiBPSUQgbmFtZSBzaGFsbCBiZSBkZWZpbmVkIGluICdLSlVSLmFzbjEueDUwOS5PSUQubmFtZTJvaWRMaXN0Jy5cbiAgICAgKiBPdGhlcndpc2UgcmFpc2UgZXJyb3IuXG4gICAgICovXG4gICAgdGhpcy5zZXRWYWx1ZU5hbWUgPSBmdW5jdGlvbihvaWROYW1lKSB7XG5cdGlmICh0eXBlb2YgS0pVUi5hc24xLng1MDkuT0lELm5hbWUyb2lkTGlzdFtvaWROYW1lXSAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdCAgICB2YXIgb2lkID0gS0pVUi5hc24xLng1MDkuT0lELm5hbWUyb2lkTGlzdFtvaWROYW1lXTtcblx0ICAgIHRoaXMuc2V0VmFsdWVPaWRTdHJpbmcob2lkKTtcblx0fSBlbHNlIHtcblx0ICAgIHRocm93IFwiREVST2JqZWN0SWRlbnRpZmllciBvaWROYW1lIHVuZGVmaW5lZDogXCIgKyBvaWROYW1lO1xuXHR9XG4gICAgfTtcblxuICAgIHRoaXMuZ2V0RnJlc2hWYWx1ZUhleCA9IGZ1bmN0aW9uKCkge1xuXHRyZXR1cm4gdGhpcy5oVjtcbiAgICB9O1xuXG4gICAgaWYgKHR5cGVvZiBwYXJhbXMgIT0gXCJ1bmRlZmluZWRcIikge1xuXHRpZiAodHlwZW9mIHBhcmFtc1snb2lkJ10gIT0gXCJ1bmRlZmluZWRcIikge1xuXHQgICAgdGhpcy5zZXRWYWx1ZU9pZFN0cmluZyhwYXJhbXNbJ29pZCddKTtcblx0fSBlbHNlIGlmICh0eXBlb2YgcGFyYW1zWydoZXgnXSAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdCAgICB0aGlzLnNldFZhbHVlSGV4KHBhcmFtc1snaGV4J10pO1xuXHR9IGVsc2UgaWYgKHR5cGVvZiBwYXJhbXNbJ25hbWUnXSAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdCAgICB0aGlzLnNldFZhbHVlTmFtZShwYXJhbXNbJ25hbWUnXSk7XG5cdH1cbiAgICB9XG59O1xuSlNYLmV4dGVuZChLSlVSLmFzbjEuREVST2JqZWN0SWRlbnRpZmllciwgS0pVUi5hc24xLkFTTjFPYmplY3QpO1xuXG4vLyAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxuLyoqXG4gKiBjbGFzcyBmb3IgQVNOLjEgREVSIFVURjhTdHJpbmdcbiAqIEBuYW1lIEtKVVIuYXNuMS5ERVJVVEY4U3RyaW5nXG4gKiBAY2xhc3MgY2xhc3MgZm9yIEFTTi4xIERFUiBVVEY4U3RyaW5nXG4gKiBAcGFyYW0ge0FycmF5fSBwYXJhbXMgYXNzb2NpYXRpdmUgYXJyYXkgb2YgcGFyYW1ldGVycyAoZXguIHsnc3RyJzogJ2FhYSd9KVxuICogQGV4dGVuZHMgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nXG4gKiBAZGVzY3JpcHRpb25cbiAqIEBzZWUgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nIC0gc3VwZXJjbGFzc1xuICovXG5LSlVSLmFzbjEuREVSVVRGOFN0cmluZyA9IGZ1bmN0aW9uKHBhcmFtcykge1xuICAgIEtKVVIuYXNuMS5ERVJVVEY4U3RyaW5nLnN1cGVyY2xhc3MuY29uc3RydWN0b3IuY2FsbCh0aGlzLCBwYXJhbXMpO1xuICAgIHRoaXMuaFQgPSBcIjBjXCI7XG59O1xuSlNYLmV4dGVuZChLSlVSLmFzbjEuREVSVVRGOFN0cmluZywgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nKTtcblxuLy8gKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcbi8qKlxuICogY2xhc3MgZm9yIEFTTi4xIERFUiBOdW1lcmljU3RyaW5nXG4gKiBAbmFtZSBLSlVSLmFzbjEuREVSTnVtZXJpY1N0cmluZ1xuICogQGNsYXNzIGNsYXNzIGZvciBBU04uMSBERVIgTnVtZXJpY1N0cmluZ1xuICogQHBhcmFtIHtBcnJheX0gcGFyYW1zIGFzc29jaWF0aXZlIGFycmF5IG9mIHBhcmFtZXRlcnMgKGV4LiB7J3N0cic6ICdhYWEnfSlcbiAqIEBleHRlbmRzIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZ1xuICogQGRlc2NyaXB0aW9uXG4gKiBAc2VlIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZyAtIHN1cGVyY2xhc3NcbiAqL1xuS0pVUi5hc24xLkRFUk51bWVyaWNTdHJpbmcgPSBmdW5jdGlvbihwYXJhbXMpIHtcbiAgICBLSlVSLmFzbjEuREVSTnVtZXJpY1N0cmluZy5zdXBlcmNsYXNzLmNvbnN0cnVjdG9yLmNhbGwodGhpcywgcGFyYW1zKTtcbiAgICB0aGlzLmhUID0gXCIxMlwiO1xufTtcbkpTWC5leHRlbmQoS0pVUi5hc24xLkRFUk51bWVyaWNTdHJpbmcsIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZyk7XG5cbi8vICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXG4vKipcbiAqIGNsYXNzIGZvciBBU04uMSBERVIgUHJpbnRhYmxlU3RyaW5nXG4gKiBAbmFtZSBLSlVSLmFzbjEuREVSUHJpbnRhYmxlU3RyaW5nXG4gKiBAY2xhc3MgY2xhc3MgZm9yIEFTTi4xIERFUiBQcmludGFibGVTdHJpbmdcbiAqIEBwYXJhbSB7QXJyYXl9IHBhcmFtcyBhc3NvY2lhdGl2ZSBhcnJheSBvZiBwYXJhbWV0ZXJzIChleC4geydzdHInOiAnYWFhJ30pXG4gKiBAZXh0ZW5kcyBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmdcbiAqIEBkZXNjcmlwdGlvblxuICogQHNlZSBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmcgLSBzdXBlcmNsYXNzXG4gKi9cbktKVVIuYXNuMS5ERVJQcmludGFibGVTdHJpbmcgPSBmdW5jdGlvbihwYXJhbXMpIHtcbiAgICBLSlVSLmFzbjEuREVSUHJpbnRhYmxlU3RyaW5nLnN1cGVyY2xhc3MuY29uc3RydWN0b3IuY2FsbCh0aGlzLCBwYXJhbXMpO1xuICAgIHRoaXMuaFQgPSBcIjEzXCI7XG59O1xuSlNYLmV4dGVuZChLSlVSLmFzbjEuREVSUHJpbnRhYmxlU3RyaW5nLCBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmcpO1xuXG4vLyAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxuLyoqXG4gKiBjbGFzcyBmb3IgQVNOLjEgREVSIFRlbGV0ZXhTdHJpbmdcbiAqIEBuYW1lIEtKVVIuYXNuMS5ERVJUZWxldGV4U3RyaW5nXG4gKiBAY2xhc3MgY2xhc3MgZm9yIEFTTi4xIERFUiBUZWxldGV4U3RyaW5nXG4gKiBAcGFyYW0ge0FycmF5fSBwYXJhbXMgYXNzb2NpYXRpdmUgYXJyYXkgb2YgcGFyYW1ldGVycyAoZXguIHsnc3RyJzogJ2FhYSd9KVxuICogQGV4dGVuZHMgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nXG4gKiBAZGVzY3JpcHRpb25cbiAqIEBzZWUgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nIC0gc3VwZXJjbGFzc1xuICovXG5LSlVSLmFzbjEuREVSVGVsZXRleFN0cmluZyA9IGZ1bmN0aW9uKHBhcmFtcykge1xuICAgIEtKVVIuYXNuMS5ERVJUZWxldGV4U3RyaW5nLnN1cGVyY2xhc3MuY29uc3RydWN0b3IuY2FsbCh0aGlzLCBwYXJhbXMpO1xuICAgIHRoaXMuaFQgPSBcIjE0XCI7XG59O1xuSlNYLmV4dGVuZChLSlVSLmFzbjEuREVSVGVsZXRleFN0cmluZywgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nKTtcblxuLy8gKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcbi8qKlxuICogY2xhc3MgZm9yIEFTTi4xIERFUiBJQTVTdHJpbmdcbiAqIEBuYW1lIEtKVVIuYXNuMS5ERVJJQTVTdHJpbmdcbiAqIEBjbGFzcyBjbGFzcyBmb3IgQVNOLjEgREVSIElBNVN0cmluZ1xuICogQHBhcmFtIHtBcnJheX0gcGFyYW1zIGFzc29jaWF0aXZlIGFycmF5IG9mIHBhcmFtZXRlcnMgKGV4LiB7J3N0cic6ICdhYWEnfSlcbiAqIEBleHRlbmRzIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZ1xuICogQGRlc2NyaXB0aW9uXG4gKiBAc2VlIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZyAtIHN1cGVyY2xhc3NcbiAqL1xuS0pVUi5hc24xLkRFUklBNVN0cmluZyA9IGZ1bmN0aW9uKHBhcmFtcykge1xuICAgIEtKVVIuYXNuMS5ERVJJQTVTdHJpbmcuc3VwZXJjbGFzcy5jb25zdHJ1Y3Rvci5jYWxsKHRoaXMsIHBhcmFtcyk7XG4gICAgdGhpcy5oVCA9IFwiMTZcIjtcbn07XG5KU1guZXh0ZW5kKEtKVVIuYXNuMS5ERVJJQTVTdHJpbmcsIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZyk7XG5cbi8vICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXG4vKipcbiAqIGNsYXNzIGZvciBBU04uMSBERVIgVVRDVGltZVxuICogQG5hbWUgS0pVUi5hc24xLkRFUlVUQ1RpbWVcbiAqIEBjbGFzcyBjbGFzcyBmb3IgQVNOLjEgREVSIFVUQ1RpbWVcbiAqIEBwYXJhbSB7QXJyYXl9IHBhcmFtcyBhc3NvY2lhdGl2ZSBhcnJheSBvZiBwYXJhbWV0ZXJzIChleC4geydzdHInOiAnMTMwNDMwMjM1OTU5Wid9KVxuICogQGV4dGVuZHMgS0pVUi5hc24xLkRFUkFic3RyYWN0VGltZVxuICogQGRlc2NyaXB0aW9uXG4gKiA8YnIvPlxuICogQXMgZm9yIGFyZ3VtZW50ICdwYXJhbXMnIGZvciBjb25zdHJ1Y3RvciwgeW91IGNhbiBzcGVjaWZ5IG9uZSBvZlxuICogZm9sbG93aW5nIHByb3BlcnRpZXM6XG4gKiA8dWw+XG4gKiA8bGk+c3RyIC0gc3BlY2lmeSBpbml0aWFsIEFTTi4xIHZhbHVlKFYpIGJ5IGEgc3RyaW5nIChleC4nMTMwNDMwMjM1OTU5WicpPC9saT5cbiAqIDxsaT5oZXggLSBzcGVjaWZ5IGluaXRpYWwgQVNOLjEgdmFsdWUoVikgYnkgYSBoZXhhZGVjaW1hbCBzdHJpbmc8L2xpPlxuICogPGxpPmRhdGUgLSBzcGVjaWZ5IERhdGUgb2JqZWN0LjwvbGk+XG4gKiA8L3VsPlxuICogTk9URTogJ3BhcmFtcycgY2FuIGJlIG9taXR0ZWQuXG4gKiA8aDQ+RVhBTVBMRVM8L2g0PlxuICogQGV4YW1wbGVcbiAqIHZhciBkMSA9IG5ldyBLSlVSLmFzbjEuREVSVVRDVGltZSgpO1xuICogZDEuc2V0U3RyaW5nKCcxMzA0MzAxMjU5NTlaJyk7XG4gKlxuICogdmFyIGQyID0gbmV3IEtKVVIuYXNuMS5ERVJVVENUaW1lKHsnc3RyJzogJzEzMDQzMDEyNTk1OVonfSk7XG4gKlxuICogdmFyIGQzID0gbmV3IEtKVVIuYXNuMS5ERVJVVENUaW1lKHsnZGF0ZSc6IG5ldyBEYXRlKERhdGUuVVRDKDIwMTUsIDAsIDMxLCAwLCAwLCAwLCAwKSl9KTtcbiAqL1xuS0pVUi5hc24xLkRFUlVUQ1RpbWUgPSBmdW5jdGlvbihwYXJhbXMpIHtcbiAgICBLSlVSLmFzbjEuREVSVVRDVGltZS5zdXBlcmNsYXNzLmNvbnN0cnVjdG9yLmNhbGwodGhpcywgcGFyYW1zKTtcbiAgICB0aGlzLmhUID0gXCIxN1wiO1xuXG4gICAgLyoqXG4gICAgICogc2V0IHZhbHVlIGJ5IGEgRGF0ZSBvYmplY3RcbiAgICAgKiBAbmFtZSBzZXRCeURhdGVcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkRFUlVUQ1RpbWVcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcGFyYW0ge0RhdGV9IGRhdGVPYmplY3QgRGF0ZSBvYmplY3QgdG8gc2V0IEFTTi4xIHZhbHVlKFYpXG4gICAgICovXG4gICAgdGhpcy5zZXRCeURhdGUgPSBmdW5jdGlvbihkYXRlT2JqZWN0KSB7XG5cdHRoaXMuaFRMViA9IG51bGw7XG5cdHRoaXMuaXNNb2RpZmllZCA9IHRydWU7XG5cdHRoaXMuZGF0ZSA9IGRhdGVPYmplY3Q7XG5cdHRoaXMucyA9IHRoaXMuZm9ybWF0RGF0ZSh0aGlzLmRhdGUsICd1dGMnKTtcblx0dGhpcy5oViA9IHN0b2hleCh0aGlzLnMpO1xuICAgIH07XG5cbiAgICBpZiAodHlwZW9mIHBhcmFtcyAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdGlmICh0eXBlb2YgcGFyYW1zWydzdHInXSAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdCAgICB0aGlzLnNldFN0cmluZyhwYXJhbXNbJ3N0ciddKTtcblx0fSBlbHNlIGlmICh0eXBlb2YgcGFyYW1zWydoZXgnXSAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdCAgICB0aGlzLnNldFN0cmluZ0hleChwYXJhbXNbJ2hleCddKTtcblx0fSBlbHNlIGlmICh0eXBlb2YgcGFyYW1zWydkYXRlJ10gIT0gXCJ1bmRlZmluZWRcIikge1xuXHQgICAgdGhpcy5zZXRCeURhdGUocGFyYW1zWydkYXRlJ10pO1xuXHR9XG4gICAgfVxufTtcbkpTWC5leHRlbmQoS0pVUi5hc24xLkRFUlVUQ1RpbWUsIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFRpbWUpO1xuXG4vLyAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxuLyoqXG4gKiBjbGFzcyBmb3IgQVNOLjEgREVSIEdlbmVyYWxpemVkVGltZVxuICogQG5hbWUgS0pVUi5hc24xLkRFUkdlbmVyYWxpemVkVGltZVxuICogQGNsYXNzIGNsYXNzIGZvciBBU04uMSBERVIgR2VuZXJhbGl6ZWRUaW1lXG4gKiBAcGFyYW0ge0FycmF5fSBwYXJhbXMgYXNzb2NpYXRpdmUgYXJyYXkgb2YgcGFyYW1ldGVycyAoZXguIHsnc3RyJzogJzIwMTMwNDMwMjM1OTU5Wid9KVxuICogQGV4dGVuZHMgS0pVUi5hc24xLkRFUkFic3RyYWN0VGltZVxuICogQGRlc2NyaXB0aW9uXG4gKiA8YnIvPlxuICogQXMgZm9yIGFyZ3VtZW50ICdwYXJhbXMnIGZvciBjb25zdHJ1Y3RvciwgeW91IGNhbiBzcGVjaWZ5IG9uZSBvZlxuICogZm9sbG93aW5nIHByb3BlcnRpZXM6XG4gKiA8dWw+XG4gKiA8bGk+c3RyIC0gc3BlY2lmeSBpbml0aWFsIEFTTi4xIHZhbHVlKFYpIGJ5IGEgc3RyaW5nIChleC4nMjAxMzA0MzAyMzU5NTlaJyk8L2xpPlxuICogPGxpPmhleCAtIHNwZWNpZnkgaW5pdGlhbCBBU04uMSB2YWx1ZShWKSBieSBhIGhleGFkZWNpbWFsIHN0cmluZzwvbGk+XG4gKiA8bGk+ZGF0ZSAtIHNwZWNpZnkgRGF0ZSBvYmplY3QuPC9saT5cbiAqIDwvdWw+XG4gKiBOT1RFOiAncGFyYW1zJyBjYW4gYmUgb21pdHRlZC5cbiAqL1xuS0pVUi5hc24xLkRFUkdlbmVyYWxpemVkVGltZSA9IGZ1bmN0aW9uKHBhcmFtcykge1xuICAgIEtKVVIuYXNuMS5ERVJHZW5lcmFsaXplZFRpbWUuc3VwZXJjbGFzcy5jb25zdHJ1Y3Rvci5jYWxsKHRoaXMsIHBhcmFtcyk7XG4gICAgdGhpcy5oVCA9IFwiMThcIjtcblxuICAgIC8qKlxuICAgICAqIHNldCB2YWx1ZSBieSBhIERhdGUgb2JqZWN0XG4gICAgICogQG5hbWUgc2V0QnlEYXRlXG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5ERVJHZW5lcmFsaXplZFRpbWVcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcGFyYW0ge0RhdGV9IGRhdGVPYmplY3QgRGF0ZSBvYmplY3QgdG8gc2V0IEFTTi4xIHZhbHVlKFYpXG4gICAgICogQGV4YW1wbGVcbiAgICAgKiBXaGVuIHlvdSBzcGVjaWZ5IFVUQyB0aW1lLCB1c2UgJ0RhdGUuVVRDJyBtZXRob2QgbGlrZSB0aGlzOjxici8+XG4gICAgICogdmFyIG8gPSBuZXcgREVSVVRDVGltZSgpO1xuICAgICAqIHZhciBkYXRlID0gbmV3IERhdGUoRGF0ZS5VVEMoMjAxNSwgMCwgMzEsIDIzLCA1OSwgNTksIDApKTsgIzIwMTVKQU4zMSAyMzo1OTo1OVxuICAgICAqIG8uc2V0QnlEYXRlKGRhdGUpO1xuICAgICAqL1xuICAgIHRoaXMuc2V0QnlEYXRlID0gZnVuY3Rpb24oZGF0ZU9iamVjdCkge1xuXHR0aGlzLmhUTFYgPSBudWxsO1xuXHR0aGlzLmlzTW9kaWZpZWQgPSB0cnVlO1xuXHR0aGlzLmRhdGUgPSBkYXRlT2JqZWN0O1xuXHR0aGlzLnMgPSB0aGlzLmZvcm1hdERhdGUodGhpcy5kYXRlLCAnZ2VuJyk7XG5cdHRoaXMuaFYgPSBzdG9oZXgodGhpcy5zKTtcbiAgICB9O1xuXG4gICAgaWYgKHR5cGVvZiBwYXJhbXMgIT0gXCJ1bmRlZmluZWRcIikge1xuXHRpZiAodHlwZW9mIHBhcmFtc1snc3RyJ10gIT0gXCJ1bmRlZmluZWRcIikge1xuXHQgICAgdGhpcy5zZXRTdHJpbmcocGFyYW1zWydzdHInXSk7XG5cdH0gZWxzZSBpZiAodHlwZW9mIHBhcmFtc1snaGV4J10gIT0gXCJ1bmRlZmluZWRcIikge1xuXHQgICAgdGhpcy5zZXRTdHJpbmdIZXgocGFyYW1zWydoZXgnXSk7XG5cdH0gZWxzZSBpZiAodHlwZW9mIHBhcmFtc1snZGF0ZSddICE9IFwidW5kZWZpbmVkXCIpIHtcblx0ICAgIHRoaXMuc2V0QnlEYXRlKHBhcmFtc1snZGF0ZSddKTtcblx0fVxuICAgIH1cbn07XG5KU1guZXh0ZW5kKEtKVVIuYXNuMS5ERVJHZW5lcmFsaXplZFRpbWUsIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFRpbWUpO1xuXG4vLyAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxuLyoqXG4gKiBjbGFzcyBmb3IgQVNOLjEgREVSIFNlcXVlbmNlXG4gKiBAbmFtZSBLSlVSLmFzbjEuREVSU2VxdWVuY2VcbiAqIEBjbGFzcyBjbGFzcyBmb3IgQVNOLjEgREVSIFNlcXVlbmNlXG4gKiBAZXh0ZW5kcyBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJ1Y3R1cmVkXG4gKiBAZGVzY3JpcHRpb25cbiAqIDxici8+XG4gKiBBcyBmb3IgYXJndW1lbnQgJ3BhcmFtcycgZm9yIGNvbnN0cnVjdG9yLCB5b3UgY2FuIHNwZWNpZnkgb25lIG9mXG4gKiBmb2xsb3dpbmcgcHJvcGVydGllczpcbiAqIDx1bD5cbiAqIDxsaT5hcnJheSAtIHNwZWNpZnkgYXJyYXkgb2YgQVNOMU9iamVjdCB0byBzZXQgZWxlbWVudHMgb2YgY29udGVudDwvbGk+XG4gKiA8L3VsPlxuICogTk9URTogJ3BhcmFtcycgY2FuIGJlIG9taXR0ZWQuXG4gKi9cbktKVVIuYXNuMS5ERVJTZXF1ZW5jZSA9IGZ1bmN0aW9uKHBhcmFtcykge1xuICAgIEtKVVIuYXNuMS5ERVJTZXF1ZW5jZS5zdXBlcmNsYXNzLmNvbnN0cnVjdG9yLmNhbGwodGhpcywgcGFyYW1zKTtcbiAgICB0aGlzLmhUID0gXCIzMFwiO1xuICAgIHRoaXMuZ2V0RnJlc2hWYWx1ZUhleCA9IGZ1bmN0aW9uKCkge1xuXHR2YXIgaCA9ICcnO1xuXHRmb3IgKHZhciBpID0gMDsgaSA8IHRoaXMuYXNuMUFycmF5Lmxlbmd0aDsgaSsrKSB7XG5cdCAgICB2YXIgYXNuMU9iaiA9IHRoaXMuYXNuMUFycmF5W2ldO1xuXHQgICAgaCArPSBhc24xT2JqLmdldEVuY29kZWRIZXgoKTtcblx0fVxuXHR0aGlzLmhWID0gaDtcblx0cmV0dXJuIHRoaXMuaFY7XG4gICAgfTtcbn07XG5KU1guZXh0ZW5kKEtKVVIuYXNuMS5ERVJTZXF1ZW5jZSwgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RydWN0dXJlZCk7XG5cbi8vICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXG4vKipcbiAqIGNsYXNzIGZvciBBU04uMSBERVIgU2V0XG4gKiBAbmFtZSBLSlVSLmFzbjEuREVSU2V0XG4gKiBAY2xhc3MgY2xhc3MgZm9yIEFTTi4xIERFUiBTZXRcbiAqIEBleHRlbmRzIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cnVjdHVyZWRcbiAqIEBkZXNjcmlwdGlvblxuICogPGJyLz5cbiAqIEFzIGZvciBhcmd1bWVudCAncGFyYW1zJyBmb3IgY29uc3RydWN0b3IsIHlvdSBjYW4gc3BlY2lmeSBvbmUgb2ZcbiAqIGZvbGxvd2luZyBwcm9wZXJ0aWVzOlxuICogPHVsPlxuICogPGxpPmFycmF5IC0gc3BlY2lmeSBhcnJheSBvZiBBU04xT2JqZWN0IHRvIHNldCBlbGVtZW50cyBvZiBjb250ZW50PC9saT5cbiAqIDwvdWw+XG4gKiBOT1RFOiAncGFyYW1zJyBjYW4gYmUgb21pdHRlZC5cbiAqL1xuS0pVUi5hc24xLkRFUlNldCA9IGZ1bmN0aW9uKHBhcmFtcykge1xuICAgIEtKVVIuYXNuMS5ERVJTZXQuc3VwZXJjbGFzcy5jb25zdHJ1Y3Rvci5jYWxsKHRoaXMsIHBhcmFtcyk7XG4gICAgdGhpcy5oVCA9IFwiMzFcIjtcbiAgICB0aGlzLmdldEZyZXNoVmFsdWVIZXggPSBmdW5jdGlvbigpIHtcblx0dmFyIGEgPSBuZXcgQXJyYXkoKTtcblx0Zm9yICh2YXIgaSA9IDA7IGkgPCB0aGlzLmFzbjFBcnJheS5sZW5ndGg7IGkrKykge1xuXHQgICAgdmFyIGFzbjFPYmogPSB0aGlzLmFzbjFBcnJheVtpXTtcblx0ICAgIGEucHVzaChhc24xT2JqLmdldEVuY29kZWRIZXgoKSk7XG5cdH1cblx0YS5zb3J0KCk7XG5cdHRoaXMuaFYgPSBhLmpvaW4oJycpO1xuXHRyZXR1cm4gdGhpcy5oVjtcbiAgICB9O1xufTtcbkpTWC5leHRlbmQoS0pVUi5hc24xLkRFUlNldCwgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RydWN0dXJlZCk7XG5cbi8vICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXG4vKipcbiAqIGNsYXNzIGZvciBBU04uMSBERVIgVGFnZ2VkT2JqZWN0XG4gKiBAbmFtZSBLSlVSLmFzbjEuREVSVGFnZ2VkT2JqZWN0XG4gKiBAY2xhc3MgY2xhc3MgZm9yIEFTTi4xIERFUiBUYWdnZWRPYmplY3RcbiAqIEBleHRlbmRzIEtKVVIuYXNuMS5BU04xT2JqZWN0XG4gKiBAZGVzY3JpcHRpb25cbiAqIDxici8+XG4gKiBQYXJhbWV0ZXIgJ3RhZ05vTmV4JyBpcyBBU04uMSB0YWcoVCkgdmFsdWUgZm9yIHRoaXMgb2JqZWN0LlxuICogRm9yIGV4YW1wbGUsIGlmIHlvdSBmaW5kICdbMV0nIHRhZyBpbiBhIEFTTi4xIGR1bXAsIFxuICogJ3RhZ05vSGV4JyB3aWxsIGJlICdhMScuXG4gKiA8YnIvPlxuICogQXMgZm9yIG9wdGlvbmFsIGFyZ3VtZW50ICdwYXJhbXMnIGZvciBjb25zdHJ1Y3RvciwgeW91IGNhbiBzcGVjaWZ5ICpBTlkqIG9mXG4gKiBmb2xsb3dpbmcgcHJvcGVydGllczpcbiAqIDx1bD5cbiAqIDxsaT5leHBsaWNpdCAtIHNwZWNpZnkgdHJ1ZSBpZiB0aGlzIGlzIGV4cGxpY2l0IHRhZyBvdGhlcndpc2UgZmFsc2UgXG4gKiAgICAgKGRlZmF1bHQgaXMgJ3RydWUnKS48L2xpPlxuICogPGxpPnRhZyAtIHNwZWNpZnkgdGFnIChkZWZhdWx0IGlzICdhMCcgd2hpY2ggbWVhbnMgWzBdKTwvbGk+XG4gKiA8bGk+b2JqIC0gc3BlY2lmeSBBU04xT2JqZWN0IHdoaWNoIGlzIHRhZ2dlZDwvbGk+XG4gKiA8L3VsPlxuICogQGV4YW1wbGVcbiAqIGQxID0gbmV3IEtKVVIuYXNuMS5ERVJVVEY4U3RyaW5nKHsnc3RyJzonYSd9KTtcbiAqIGQyID0gbmV3IEtKVVIuYXNuMS5ERVJUYWdnZWRPYmplY3QoeydvYmonOiBkMX0pO1xuICogaGV4ID0gZDIuZ2V0RW5jb2RlZEhleCgpO1xuICovXG5LSlVSLmFzbjEuREVSVGFnZ2VkT2JqZWN0ID0gZnVuY3Rpb24ocGFyYW1zKSB7XG4gICAgS0pVUi5hc24xLkRFUlRhZ2dlZE9iamVjdC5zdXBlcmNsYXNzLmNvbnN0cnVjdG9yLmNhbGwodGhpcyk7XG4gICAgdGhpcy5oVCA9IFwiYTBcIjtcbiAgICB0aGlzLmhWID0gJyc7XG4gICAgdGhpcy5pc0V4cGxpY2l0ID0gdHJ1ZTtcbiAgICB0aGlzLmFzbjFPYmplY3QgPSBudWxsO1xuXG4gICAgLyoqXG4gICAgICogc2V0IHZhbHVlIGJ5IGFuIEFTTjFPYmplY3RcbiAgICAgKiBAbmFtZSBzZXRTdHJpbmdcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkRFUlRhZ2dlZE9iamVjdFxuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEBwYXJhbSB7Qm9vbGVhbn0gaXNFeHBsaWNpdEZsYWcgZmxhZyBmb3IgZXhwbGljaXQvaW1wbGljaXQgdGFnXG4gICAgICogQHBhcmFtIHtJbnRlZ2VyfSB0YWdOb0hleCBoZXhhZGVjaW1hbCBzdHJpbmcgb2YgQVNOLjEgdGFnXG4gICAgICogQHBhcmFtIHtBU04xT2JqZWN0fSBhc24xT2JqZWN0IEFTTi4xIHRvIGVuY2Fwc3VsYXRlXG4gICAgICovXG4gICAgdGhpcy5zZXRBU04xT2JqZWN0ID0gZnVuY3Rpb24oaXNFeHBsaWNpdEZsYWcsIHRhZ05vSGV4LCBhc24xT2JqZWN0KSB7XG5cdHRoaXMuaFQgPSB0YWdOb0hleDtcblx0dGhpcy5pc0V4cGxpY2l0ID0gaXNFeHBsaWNpdEZsYWc7XG5cdHRoaXMuYXNuMU9iamVjdCA9IGFzbjFPYmplY3Q7XG5cdGlmICh0aGlzLmlzRXhwbGljaXQpIHtcblx0ICAgIHRoaXMuaFYgPSB0aGlzLmFzbjFPYmplY3QuZ2V0RW5jb2RlZEhleCgpO1xuXHQgICAgdGhpcy5oVExWID0gbnVsbDtcblx0ICAgIHRoaXMuaXNNb2RpZmllZCA9IHRydWU7XG5cdH0gZWxzZSB7XG5cdCAgICB0aGlzLmhWID0gbnVsbDtcblx0ICAgIHRoaXMuaFRMViA9IGFzbjFPYmplY3QuZ2V0RW5jb2RlZEhleCgpO1xuXHQgICAgdGhpcy5oVExWID0gdGhpcy5oVExWLnJlcGxhY2UoL14uLi8sIHRhZ05vSGV4KTtcblx0ICAgIHRoaXMuaXNNb2RpZmllZCA9IGZhbHNlO1xuXHR9XG4gICAgfTtcblxuICAgIHRoaXMuZ2V0RnJlc2hWYWx1ZUhleCA9IGZ1bmN0aW9uKCkge1xuXHRyZXR1cm4gdGhpcy5oVjtcbiAgICB9O1xuXG4gICAgaWYgKHR5cGVvZiBwYXJhbXMgIT0gXCJ1bmRlZmluZWRcIikge1xuXHRpZiAodHlwZW9mIHBhcmFtc1sndGFnJ10gIT0gXCJ1bmRlZmluZWRcIikge1xuXHQgICAgdGhpcy5oVCA9IHBhcmFtc1sndGFnJ107XG5cdH1cblx0aWYgKHR5cGVvZiBwYXJhbXNbJ2V4cGxpY2l0J10gIT0gXCJ1bmRlZmluZWRcIikge1xuXHQgICAgdGhpcy5pc0V4cGxpY2l0ID0gcGFyYW1zWydleHBsaWNpdCddO1xuXHR9XG5cdGlmICh0eXBlb2YgcGFyYW1zWydvYmonXSAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdCAgICB0aGlzLmFzbjFPYmplY3QgPSBwYXJhbXNbJ29iaiddO1xuXHQgICAgdGhpcy5zZXRBU04xT2JqZWN0KHRoaXMuaXNFeHBsaWNpdCwgdGhpcy5oVCwgdGhpcy5hc24xT2JqZWN0KTtcblx0fVxuICAgIH1cbn07XG5KU1guZXh0ZW5kKEtKVVIuYXNuMS5ERVJUYWdnZWRPYmplY3QsIEtKVVIuYXNuMS5BU04xT2JqZWN0KTtcbi8vIEhleCBKYXZhU2NyaXB0IGRlY29kZXJcbi8vIENvcHlyaWdodCAoYykgMjAwOC0yMDEzIExhcG8gTHVjaGluaSA8bGFwb0BsYXBvLml0PlxuXG4vLyBQZXJtaXNzaW9uIHRvIHVzZSwgY29weSwgbW9kaWZ5LCBhbmQvb3IgZGlzdHJpYnV0ZSB0aGlzIHNvZnR3YXJlIGZvciBhbnlcbi8vIHB1cnBvc2Ugd2l0aCBvciB3aXRob3V0IGZlZSBpcyBoZXJlYnkgZ3JhbnRlZCwgcHJvdmlkZWQgdGhhdCB0aGUgYWJvdmVcbi8vIGNvcHlyaWdodCBub3RpY2UgYW5kIHRoaXMgcGVybWlzc2lvbiBub3RpY2UgYXBwZWFyIGluIGFsbCBjb3BpZXMuXG4vLyBcbi8vIFRIRSBTT0ZUV0FSRSBJUyBQUk9WSURFRCBcIkFTIElTXCIgQU5EIFRIRSBBVVRIT1IgRElTQ0xBSU1TIEFMTCBXQVJSQU5USUVTXG4vLyBXSVRIIFJFR0FSRCBUTyBUSElTIFNPRlRXQVJFIElOQ0xVRElORyBBTEwgSU1QTElFRCBXQVJSQU5USUVTIE9GXG4vLyBNRVJDSEFOVEFCSUxJVFkgQU5EIEZJVE5FU1MuIElOIE5PIEVWRU5UIFNIQUxMIFRIRSBBVVRIT1IgQkUgTElBQkxFIEZPUlxuLy8gQU5ZIFNQRUNJQUwsIERJUkVDVCwgSU5ESVJFQ1QsIE9SIENPTlNFUVVFTlRJQUwgREFNQUdFUyBPUiBBTlkgREFNQUdFU1xuLy8gV0hBVFNPRVZFUiBSRVNVTFRJTkcgRlJPTSBMT1NTIE9GIFVTRSwgREFUQSBPUiBQUk9GSVRTLCBXSEVUSEVSIElOIEFOXG4vLyBBQ1RJT04gT0YgQ09OVFJBQ1QsIE5FR0xJR0VOQ0UgT1IgT1RIRVIgVE9SVElPVVMgQUNUSU9OLCBBUklTSU5HIE9VVCBPRlxuLy8gT1IgSU4gQ09OTkVDVElPTiBXSVRIIFRIRSBVU0UgT1IgUEVSRk9STUFOQ0UgT0YgVEhJUyBTT0ZUV0FSRS5cblxuLypqc2hpbnQgYnJvd3NlcjogdHJ1ZSwgc3RyaWN0OiB0cnVlLCBpbW1lZDogdHJ1ZSwgbGF0ZWRlZjogdHJ1ZSwgdW5kZWY6IHRydWUsIHJlZ2V4ZGFzaDogZmFsc2UgKi9cbihmdW5jdGlvbiAodW5kZWZpbmVkKSB7XG5cInVzZSBzdHJpY3RcIjtcblxudmFyIEhleCA9IHt9LFxuICAgIGRlY29kZXI7XG5cbkhleC5kZWNvZGUgPSBmdW5jdGlvbihhKSB7XG4gICAgdmFyIGk7XG4gICAgaWYgKGRlY29kZXIgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICB2YXIgaGV4ID0gXCIwMTIzNDU2Nzg5QUJDREVGXCIsXG4gICAgICAgICAgICBpZ25vcmUgPSBcIiBcXGZcXG5cXHJcXHRcXHUwMEEwXFx1MjAyOFxcdTIwMjlcIjtcbiAgICAgICAgZGVjb2RlciA9IFtdO1xuICAgICAgICBmb3IgKGkgPSAwOyBpIDwgMTY7ICsraSlcbiAgICAgICAgICAgIGRlY29kZXJbaGV4LmNoYXJBdChpKV0gPSBpO1xuICAgICAgICBoZXggPSBoZXgudG9Mb3dlckNhc2UoKTtcbiAgICAgICAgZm9yIChpID0gMTA7IGkgPCAxNjsgKytpKVxuICAgICAgICAgICAgZGVjb2RlcltoZXguY2hhckF0KGkpXSA9IGk7XG4gICAgICAgIGZvciAoaSA9IDA7IGkgPCBpZ25vcmUubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICBkZWNvZGVyW2lnbm9yZS5jaGFyQXQoaSldID0gLTE7XG4gICAgfVxuICAgIHZhciBvdXQgPSBbXSxcbiAgICAgICAgYml0cyA9IDAsXG4gICAgICAgIGNoYXJfY291bnQgPSAwO1xuICAgIGZvciAoaSA9IDA7IGkgPCBhLmxlbmd0aDsgKytpKSB7XG4gICAgICAgIHZhciBjID0gYS5jaGFyQXQoaSk7XG4gICAgICAgIGlmIChjID09ICc9JylcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjID0gZGVjb2RlcltjXTtcbiAgICAgICAgaWYgKGMgPT0gLTEpXG4gICAgICAgICAgICBjb250aW51ZTtcbiAgICAgICAgaWYgKGMgPT09IHVuZGVmaW5lZClcbiAgICAgICAgICAgIHRocm93ICdJbGxlZ2FsIGNoYXJhY3RlciBhdCBvZmZzZXQgJyArIGk7XG4gICAgICAgIGJpdHMgfD0gYztcbiAgICAgICAgaWYgKCsrY2hhcl9jb3VudCA+PSAyKSB7XG4gICAgICAgICAgICBvdXRbb3V0Lmxlbmd0aF0gPSBiaXRzO1xuICAgICAgICAgICAgYml0cyA9IDA7XG4gICAgICAgICAgICBjaGFyX2NvdW50ID0gMDtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGJpdHMgPDw9IDQ7XG4gICAgICAgIH1cbiAgICB9XG4gICAgaWYgKGNoYXJfY291bnQpXG4gICAgICAgIHRocm93IFwiSGV4IGVuY29kaW5nIGluY29tcGxldGU6IDQgYml0cyBtaXNzaW5nXCI7XG4gICAgcmV0dXJuIG91dDtcbn07XG5cbi8vIGV4cG9ydCBnbG9iYWxzXG53aW5kb3cuSGV4ID0gSGV4O1xufSkoKTtcbi8vIEJhc2U2NCBKYXZhU2NyaXB0IGRlY29kZXJcbi8vIENvcHlyaWdodCAoYykgMjAwOC0yMDEzIExhcG8gTHVjaGluaSA8bGFwb0BsYXBvLml0PlxuXG4vLyBQZXJtaXNzaW9uIHRvIHVzZSwgY29weSwgbW9kaWZ5LCBhbmQvb3IgZGlzdHJpYnV0ZSB0aGlzIHNvZnR3YXJlIGZvciBhbnlcbi8vIHB1cnBvc2Ugd2l0aCBvciB3aXRob3V0IGZlZSBpcyBoZXJlYnkgZ3JhbnRlZCwgcHJvdmlkZWQgdGhhdCB0aGUgYWJvdmVcbi8vIGNvcHlyaWdodCBub3RpY2UgYW5kIHRoaXMgcGVybWlzc2lvbiBub3RpY2UgYXBwZWFyIGluIGFsbCBjb3BpZXMuXG4vLyBcbi8vIFRIRSBTT0ZUV0FSRSBJUyBQUk9WSURFRCBcIkFTIElTXCIgQU5EIFRIRSBBVVRIT1IgRElTQ0xBSU1TIEFMTCBXQVJSQU5USUVTXG4vLyBXSVRIIFJFR0FSRCBUTyBUSElTIFNPRlRXQVJFIElOQ0xVRElORyBBTEwgSU1QTElFRCBXQVJSQU5USUVTIE9GXG4vLyBNRVJDSEFOVEFCSUxJVFkgQU5EIEZJVE5FU1MuIElOIE5PIEVWRU5UIFNIQUxMIFRIRSBBVVRIT1IgQkUgTElBQkxFIEZPUlxuLy8gQU5ZIFNQRUNJQUwsIERJUkVDVCwgSU5ESVJFQ1QsIE9SIENPTlNFUVVFTlRJQUwgREFNQUdFUyBPUiBBTlkgREFNQUdFU1xuLy8gV0hBVFNPRVZFUiBSRVNVTFRJTkcgRlJPTSBMT1NTIE9GIFVTRSwgREFUQSBPUiBQUk9GSVRTLCBXSEVUSEVSIElOIEFOXG4vLyBBQ1RJT04gT0YgQ09OVFJBQ1QsIE5FR0xJR0VOQ0UgT1IgT1RIRVIgVE9SVElPVVMgQUNUSU9OLCBBUklTSU5HIE9VVCBPRlxuLy8gT1IgSU4gQ09OTkVDVElPTiBXSVRIIFRIRSBVU0UgT1IgUEVSRk9STUFOQ0UgT0YgVEhJUyBTT0ZUV0FSRS5cblxuLypqc2hpbnQgYnJvd3NlcjogdHJ1ZSwgc3RyaWN0OiB0cnVlLCBpbW1lZDogdHJ1ZSwgbGF0ZWRlZjogdHJ1ZSwgdW5kZWY6IHRydWUsIHJlZ2V4ZGFzaDogZmFsc2UgKi9cbihmdW5jdGlvbiAodW5kZWZpbmVkKSB7XG5cInVzZSBzdHJpY3RcIjtcblxudmFyIEJhc2U2NCA9IHt9LFxuICAgIGRlY29kZXI7XG5cbkJhc2U2NC5kZWNvZGUgPSBmdW5jdGlvbiAoYSkge1xuICAgIHZhciBpO1xuICAgIGlmIChkZWNvZGVyID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgdmFyIGI2NCA9IFwiQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODkrL1wiLFxuICAgICAgICAgICAgaWdub3JlID0gXCI9IFxcZlxcblxcclxcdFxcdTAwQTBcXHUyMDI4XFx1MjAyOVwiO1xuICAgICAgICBkZWNvZGVyID0gW107XG4gICAgICAgIGZvciAoaSA9IDA7IGkgPCA2NDsgKytpKVxuICAgICAgICAgICAgZGVjb2RlcltiNjQuY2hhckF0KGkpXSA9IGk7XG4gICAgICAgIGZvciAoaSA9IDA7IGkgPCBpZ25vcmUubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICBkZWNvZGVyW2lnbm9yZS5jaGFyQXQoaSldID0gLTE7XG4gICAgfVxuICAgIHZhciBvdXQgPSBbXTtcbiAgICB2YXIgYml0cyA9IDAsIGNoYXJfY291bnQgPSAwO1xuICAgIGZvciAoaSA9IDA7IGkgPCBhLmxlbmd0aDsgKytpKSB7XG4gICAgICAgIHZhciBjID0gYS5jaGFyQXQoaSk7XG4gICAgICAgIGlmIChjID09ICc9JylcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjID0gZGVjb2RlcltjXTtcbiAgICAgICAgaWYgKGMgPT0gLTEpXG4gICAgICAgICAgICBjb250aW51ZTtcbiAgICAgICAgaWYgKGMgPT09IHVuZGVmaW5lZClcbiAgICAgICAgICAgIHRocm93ICdJbGxlZ2FsIGNoYXJhY3RlciBhdCBvZmZzZXQgJyArIGk7XG4gICAgICAgIGJpdHMgfD0gYztcbiAgICAgICAgaWYgKCsrY2hhcl9jb3VudCA+PSA0KSB7XG4gICAgICAgICAgICBvdXRbb3V0Lmxlbmd0aF0gPSAoYml0cyA+PiAxNik7XG4gICAgICAgICAgICBvdXRbb3V0Lmxlbmd0aF0gPSAoYml0cyA+PiA4KSAmIDB4RkY7XG4gICAgICAgICAgICBvdXRbb3V0Lmxlbmd0aF0gPSBiaXRzICYgMHhGRjtcbiAgICAgICAgICAgIGJpdHMgPSAwO1xuICAgICAgICAgICAgY2hhcl9jb3VudCA9IDA7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBiaXRzIDw8PSA2O1xuICAgICAgICB9XG4gICAgfVxuICAgIHN3aXRjaCAoY2hhcl9jb3VudCkge1xuICAgICAgY2FzZSAxOlxuICAgICAgICB0aHJvdyBcIkJhc2U2NCBlbmNvZGluZyBpbmNvbXBsZXRlOiBhdCBsZWFzdCAyIGJpdHMgbWlzc2luZ1wiO1xuICAgICAgY2FzZSAyOlxuICAgICAgICBvdXRbb3V0Lmxlbmd0aF0gPSAoYml0cyA+PiAxMCk7XG4gICAgICAgIGJyZWFrO1xuICAgICAgY2FzZSAzOlxuICAgICAgICBvdXRbb3V0Lmxlbmd0aF0gPSAoYml0cyA+PiAxNik7XG4gICAgICAgIG91dFtvdXQubGVuZ3RoXSA9IChiaXRzID4+IDgpICYgMHhGRjtcbiAgICAgICAgYnJlYWs7XG4gICAgfVxuICAgIHJldHVybiBvdXQ7XG59O1xuXG5CYXNlNjQucmUgPSAvLS0tLS1CRUdJTiBbXi1dKy0tLS0tKFtBLVphLXowLTkrXFwvPVxcc10rKS0tLS0tRU5EIFteLV0rLS0tLS18YmVnaW4tYmFzZTY0W15cXG5dK1xcbihbQS1aYS16MC05K1xcLz1cXHNdKyk9PT09LztcbkJhc2U2NC51bmFybW9yID0gZnVuY3Rpb24gKGEpIHtcbiAgICB2YXIgbSA9IEJhc2U2NC5yZS5leGVjKGEpO1xuICAgIGlmIChtKSB7XG4gICAgICAgIGlmIChtWzFdKVxuICAgICAgICAgICAgYSA9IG1bMV07XG4gICAgICAgIGVsc2UgaWYgKG1bMl0pXG4gICAgICAgICAgICBhID0gbVsyXTtcbiAgICAgICAgZWxzZVxuICAgICAgICAgICAgdGhyb3cgXCJSZWdFeHAgb3V0IG9mIHN5bmNcIjtcbiAgICB9XG4gICAgcmV0dXJuIEJhc2U2NC5kZWNvZGUoYSk7XG59O1xuXG4vLyBleHBvcnQgZ2xvYmFsc1xud2luZG93LkJhc2U2NCA9IEJhc2U2NDtcbn0pKCk7XG4vLyBBU04uMSBKYXZhU2NyaXB0IGRlY29kZXJcbi8vIENvcHlyaWdodCAoYykgMjAwOC0yMDEzIExhcG8gTHVjaGluaSA8bGFwb0BsYXBvLml0PlxuXG4vLyBQZXJtaXNzaW9uIHRvIHVzZSwgY29weSwgbW9kaWZ5LCBhbmQvb3IgZGlzdHJpYnV0ZSB0aGlzIHNvZnR3YXJlIGZvciBhbnlcbi8vIHB1cnBvc2Ugd2l0aCBvciB3aXRob3V0IGZlZSBpcyBoZXJlYnkgZ3JhbnRlZCwgcHJvdmlkZWQgdGhhdCB0aGUgYWJvdmVcbi8vIGNvcHlyaWdodCBub3RpY2UgYW5kIHRoaXMgcGVybWlzc2lvbiBub3RpY2UgYXBwZWFyIGluIGFsbCBjb3BpZXMuXG4vLyBcbi8vIFRIRSBTT0ZUV0FSRSBJUyBQUk9WSURFRCBcIkFTIElTXCIgQU5EIFRIRSBBVVRIT1IgRElTQ0xBSU1TIEFMTCBXQVJSQU5USUVTXG4vLyBXSVRIIFJFR0FSRCBUTyBUSElTIFNPRlRXQVJFIElOQ0xVRElORyBBTEwgSU1QTElFRCBXQVJSQU5USUVTIE9GXG4vLyBNRVJDSEFOVEFCSUxJVFkgQU5EIEZJVE5FU1MuIElOIE5PIEVWRU5UIFNIQUxMIFRIRSBBVVRIT1IgQkUgTElBQkxFIEZPUlxuLy8gQU5ZIFNQRUNJQUwsIERJUkVDVCwgSU5ESVJFQ1QsIE9SIENPTlNFUVVFTlRJQUwgREFNQUdFUyBPUiBBTlkgREFNQUdFU1xuLy8gV0hBVFNPRVZFUiBSRVNVTFRJTkcgRlJPTSBMT1NTIE9GIFVTRSwgREFUQSBPUiBQUk9GSVRTLCBXSEVUSEVSIElOIEFOXG4vLyBBQ1RJT04gT0YgQ09OVFJBQ1QsIE5FR0xJR0VOQ0UgT1IgT1RIRVIgVE9SVElPVVMgQUNUSU9OLCBBUklTSU5HIE9VVCBPRlxuLy8gT1IgSU4gQ09OTkVDVElPTiBXSVRIIFRIRSBVU0UgT1IgUEVSRk9STUFOQ0UgT0YgVEhJUyBTT0ZUV0FSRS5cblxuLypqc2hpbnQgYnJvd3NlcjogdHJ1ZSwgc3RyaWN0OiB0cnVlLCBpbW1lZDogdHJ1ZSwgbGF0ZWRlZjogdHJ1ZSwgdW5kZWY6IHRydWUsIHJlZ2V4ZGFzaDogZmFsc2UgKi9cbi8qZ2xvYmFsIG9pZHMgKi9cbihmdW5jdGlvbiAodW5kZWZpbmVkKSB7XG5cInVzZSBzdHJpY3RcIjtcblxudmFyIGhhcmRMaW1pdCA9IDEwMCxcbiAgICBlbGxpcHNpcyA9IFwiXFx1MjAyNlwiLFxuICAgIERPTSA9IHtcbiAgICAgICAgdGFnOiBmdW5jdGlvbiAodGFnTmFtZSwgY2xhc3NOYW1lKSB7XG4gICAgICAgICAgICB2YXIgdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQodGFnTmFtZSk7XG4gICAgICAgICAgICB0LmNsYXNzTmFtZSA9IGNsYXNzTmFtZTtcbiAgICAgICAgICAgIHJldHVybiB0O1xuICAgICAgICB9LFxuICAgICAgICB0ZXh0OiBmdW5jdGlvbiAoc3RyKSB7XG4gICAgICAgICAgICByZXR1cm4gZG9jdW1lbnQuY3JlYXRlVGV4dE5vZGUoc3RyKTtcbiAgICAgICAgfVxuICAgIH07XG5cbmZ1bmN0aW9uIFN0cmVhbShlbmMsIHBvcykge1xuICAgIGlmIChlbmMgaW5zdGFuY2VvZiBTdHJlYW0pIHtcbiAgICAgICAgdGhpcy5lbmMgPSBlbmMuZW5jO1xuICAgICAgICB0aGlzLnBvcyA9IGVuYy5wb3M7XG4gICAgfSBlbHNlIHtcbiAgICAgICAgdGhpcy5lbmMgPSBlbmM7XG4gICAgICAgIHRoaXMucG9zID0gcG9zO1xuICAgIH1cbn1cblN0cmVhbS5wcm90b3R5cGUuZ2V0ID0gZnVuY3Rpb24gKHBvcykge1xuICAgIGlmIChwb3MgPT09IHVuZGVmaW5lZClcbiAgICAgICAgcG9zID0gdGhpcy5wb3MrKztcbiAgICBpZiAocG9zID49IHRoaXMuZW5jLmxlbmd0aClcbiAgICAgICAgdGhyb3cgJ1JlcXVlc3RpbmcgYnl0ZSBvZmZzZXQgJyArIHBvcyArICcgb24gYSBzdHJlYW0gb2YgbGVuZ3RoICcgKyB0aGlzLmVuYy5sZW5ndGg7XG4gICAgcmV0dXJuIHRoaXMuZW5jW3Bvc107XG59O1xuU3RyZWFtLnByb3RvdHlwZS5oZXhEaWdpdHMgPSBcIjAxMjM0NTY3ODlBQkNERUZcIjtcblN0cmVhbS5wcm90b3R5cGUuaGV4Qnl0ZSA9IGZ1bmN0aW9uIChiKSB7XG4gICAgcmV0dXJuIHRoaXMuaGV4RGlnaXRzLmNoYXJBdCgoYiA+PiA0KSAmIDB4RikgKyB0aGlzLmhleERpZ2l0cy5jaGFyQXQoYiAmIDB4Rik7XG59O1xuU3RyZWFtLnByb3RvdHlwZS5oZXhEdW1wID0gZnVuY3Rpb24gKHN0YXJ0LCBlbmQsIHJhdykge1xuICAgIHZhciBzID0gXCJcIjtcbiAgICBmb3IgKHZhciBpID0gc3RhcnQ7IGkgPCBlbmQ7ICsraSkge1xuICAgICAgICBzICs9IHRoaXMuaGV4Qnl0ZSh0aGlzLmdldChpKSk7XG4gICAgICAgIGlmIChyYXcgIT09IHRydWUpXG4gICAgICAgICAgICBzd2l0Y2ggKGkgJiAweEYpIHtcbiAgICAgICAgICAgIGNhc2UgMHg3OiBzICs9IFwiICBcIjsgYnJlYWs7XG4gICAgICAgICAgICBjYXNlIDB4RjogcyArPSBcIlxcblwiOyBicmVhaztcbiAgICAgICAgICAgIGRlZmF1bHQ6ICBzICs9IFwiIFwiO1xuICAgICAgICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gcztcbn07XG5TdHJlYW0ucHJvdG90eXBlLnBhcnNlU3RyaW5nSVNPID0gZnVuY3Rpb24gKHN0YXJ0LCBlbmQpIHtcbiAgICB2YXIgcyA9IFwiXCI7XG4gICAgZm9yICh2YXIgaSA9IHN0YXJ0OyBpIDwgZW5kOyArK2kpXG4gICAgICAgIHMgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSh0aGlzLmdldChpKSk7XG4gICAgcmV0dXJuIHM7XG59O1xuU3RyZWFtLnByb3RvdHlwZS5wYXJzZVN0cmluZ1VURiA9IGZ1bmN0aW9uIChzdGFydCwgZW5kKSB7XG4gICAgdmFyIHMgPSBcIlwiO1xuICAgIGZvciAodmFyIGkgPSBzdGFydDsgaSA8IGVuZDsgKSB7XG4gICAgICAgIHZhciBjID0gdGhpcy5nZXQoaSsrKTtcbiAgICAgICAgaWYgKGMgPCAxMjgpXG4gICAgICAgICAgICBzICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoYyk7XG4gICAgICAgIGVsc2UgaWYgKChjID4gMTkxKSAmJiAoYyA8IDIyNCkpXG4gICAgICAgICAgICBzICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoKChjICYgMHgxRikgPDwgNikgfCAodGhpcy5nZXQoaSsrKSAmIDB4M0YpKTtcbiAgICAgICAgZWxzZVxuICAgICAgICAgICAgcyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKCgoYyAmIDB4MEYpIDw8IDEyKSB8ICgodGhpcy5nZXQoaSsrKSAmIDB4M0YpIDw8IDYpIHwgKHRoaXMuZ2V0KGkrKykgJiAweDNGKSk7XG4gICAgfVxuICAgIHJldHVybiBzO1xufTtcblN0cmVhbS5wcm90b3R5cGUucGFyc2VTdHJpbmdCTVAgPSBmdW5jdGlvbiAoc3RhcnQsIGVuZCkge1xuICAgIHZhciBzdHIgPSBcIlwiXG4gICAgZm9yICh2YXIgaSA9IHN0YXJ0OyBpIDwgZW5kOyBpICs9IDIpIHtcbiAgICAgICAgdmFyIGhpZ2hfYnl0ZSA9IHRoaXMuZ2V0KGkpO1xuICAgICAgICB2YXIgbG93X2J5dGUgPSB0aGlzLmdldChpICsgMSk7XG4gICAgICAgIHN0ciArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKCAoaGlnaF9ieXRlIDw8IDgpICsgbG93X2J5dGUgKTtcbiAgICB9XG5cbiAgICByZXR1cm4gc3RyO1xufTtcblN0cmVhbS5wcm90b3R5cGUucmVUaW1lID0gL14oKD86MVs4OV18MlxcZCk/XFxkXFxkKSgwWzEtOV18MVswLTJdKSgwWzEtOV18WzEyXVxcZHwzWzAxXSkoWzAxXVxcZHwyWzAtM10pKD86KFswLTVdXFxkKSg/OihbMC01XVxcZCkoPzpbLixdKFxcZHsxLDN9KSk/KT8pPyhafFstK10oPzpbMF1cXGR8MVswLTJdKShbMC01XVxcZCk/KT8kLztcblN0cmVhbS5wcm90b3R5cGUucGFyc2VUaW1lID0gZnVuY3Rpb24gKHN0YXJ0LCBlbmQpIHtcbiAgICB2YXIgcyA9IHRoaXMucGFyc2VTdHJpbmdJU08oc3RhcnQsIGVuZCksXG4gICAgICAgIG0gPSB0aGlzLnJlVGltZS5leGVjKHMpO1xuICAgIGlmICghbSlcbiAgICAgICAgcmV0dXJuIFwiVW5yZWNvZ25pemVkIHRpbWU6IFwiICsgcztcbiAgICBzID0gbVsxXSArIFwiLVwiICsgbVsyXSArIFwiLVwiICsgbVszXSArIFwiIFwiICsgbVs0XTtcbiAgICBpZiAobVs1XSkge1xuICAgICAgICBzICs9IFwiOlwiICsgbVs1XTtcbiAgICAgICAgaWYgKG1bNl0pIHtcbiAgICAgICAgICAgIHMgKz0gXCI6XCIgKyBtWzZdO1xuICAgICAgICAgICAgaWYgKG1bN10pXG4gICAgICAgICAgICAgICAgcyArPSBcIi5cIiArIG1bN107XG4gICAgICAgIH1cbiAgICB9XG4gICAgaWYgKG1bOF0pIHtcbiAgICAgICAgcyArPSBcIiBVVENcIjtcbiAgICAgICAgaWYgKG1bOF0gIT0gJ1onKSB7XG4gICAgICAgICAgICBzICs9IG1bOF07XG4gICAgICAgICAgICBpZiAobVs5XSlcbiAgICAgICAgICAgICAgICBzICs9IFwiOlwiICsgbVs5XTtcbiAgICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gcztcbn07XG5TdHJlYW0ucHJvdG90eXBlLnBhcnNlSW50ZWdlciA9IGZ1bmN0aW9uIChzdGFydCwgZW5kKSB7XG4gICAgLy9UT0RPIHN1cHBvcnQgbmVnYXRpdmUgbnVtYmVyc1xuICAgIHZhciBsZW4gPSBlbmQgLSBzdGFydDtcbiAgICBpZiAobGVuID4gNCkge1xuICAgICAgICBsZW4gPDw9IDM7XG4gICAgICAgIHZhciBzID0gdGhpcy5nZXQoc3RhcnQpO1xuICAgICAgICBpZiAocyA9PT0gMClcbiAgICAgICAgICAgIGxlbiAtPSA4O1xuICAgICAgICBlbHNlXG4gICAgICAgICAgICB3aGlsZSAocyA8IDEyOCkge1xuICAgICAgICAgICAgICAgIHMgPDw9IDE7XG4gICAgICAgICAgICAgICAgLS1sZW47XG4gICAgICAgICAgICB9XG4gICAgICAgIHJldHVybiBcIihcIiArIGxlbiArIFwiIGJpdClcIjtcbiAgICB9XG4gICAgdmFyIG4gPSAwO1xuICAgIGZvciAodmFyIGkgPSBzdGFydDsgaSA8IGVuZDsgKytpKVxuICAgICAgICBuID0gKG4gPDwgOCkgfCB0aGlzLmdldChpKTtcbiAgICByZXR1cm4gbjtcbn07XG5TdHJlYW0ucHJvdG90eXBlLnBhcnNlQml0U3RyaW5nID0gZnVuY3Rpb24gKHN0YXJ0LCBlbmQpIHtcbiAgICB2YXIgdW51c2VkQml0ID0gdGhpcy5nZXQoc3RhcnQpLFxuICAgICAgICBsZW5CaXQgPSAoKGVuZCAtIHN0YXJ0IC0gMSkgPDwgMykgLSB1bnVzZWRCaXQsXG4gICAgICAgIHMgPSBcIihcIiArIGxlbkJpdCArIFwiIGJpdClcIjtcbiAgICBpZiAobGVuQml0IDw9IDIwKSB7XG4gICAgICAgIHZhciBza2lwID0gdW51c2VkQml0O1xuICAgICAgICBzICs9IFwiIFwiO1xuICAgICAgICBmb3IgKHZhciBpID0gZW5kIC0gMTsgaSA+IHN0YXJ0OyAtLWkpIHtcbiAgICAgICAgICAgIHZhciBiID0gdGhpcy5nZXQoaSk7XG4gICAgICAgICAgICBmb3IgKHZhciBqID0gc2tpcDsgaiA8IDg7ICsrailcbiAgICAgICAgICAgICAgICBzICs9IChiID4+IGopICYgMSA/IFwiMVwiIDogXCIwXCI7XG4gICAgICAgICAgICBza2lwID0gMDtcbiAgICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gcztcbn07XG5TdHJlYW0ucHJvdG90eXBlLnBhcnNlT2N0ZXRTdHJpbmcgPSBmdW5jdGlvbiAoc3RhcnQsIGVuZCkge1xuICAgIHZhciBsZW4gPSBlbmQgLSBzdGFydCxcbiAgICAgICAgcyA9IFwiKFwiICsgbGVuICsgXCIgYnl0ZSkgXCI7XG4gICAgaWYgKGxlbiA+IGhhcmRMaW1pdClcbiAgICAgICAgZW5kID0gc3RhcnQgKyBoYXJkTGltaXQ7XG4gICAgZm9yICh2YXIgaSA9IHN0YXJ0OyBpIDwgZW5kOyArK2kpXG4gICAgICAgIHMgKz0gdGhpcy5oZXhCeXRlKHRoaXMuZ2V0KGkpKTsgLy9UT0RPOiBhbHNvIHRyeSBMYXRpbjE/XG4gICAgaWYgKGxlbiA+IGhhcmRMaW1pdClcbiAgICAgICAgcyArPSBlbGxpcHNpcztcbiAgICByZXR1cm4gcztcbn07XG5TdHJlYW0ucHJvdG90eXBlLnBhcnNlT0lEID0gZnVuY3Rpb24gKHN0YXJ0LCBlbmQpIHtcbiAgICB2YXIgcyA9ICcnLFxuICAgICAgICBuID0gMCxcbiAgICAgICAgYml0cyA9IDA7XG4gICAgZm9yICh2YXIgaSA9IHN0YXJ0OyBpIDwgZW5kOyArK2kpIHtcbiAgICAgICAgdmFyIHYgPSB0aGlzLmdldChpKTtcbiAgICAgICAgbiA9IChuIDw8IDcpIHwgKHYgJiAweDdGKTtcbiAgICAgICAgYml0cyArPSA3O1xuICAgICAgICBpZiAoISh2ICYgMHg4MCkpIHsgLy8gZmluaXNoZWRcbiAgICAgICAgICAgIGlmIChzID09PSAnJykge1xuICAgICAgICAgICAgICAgIHZhciBtID0gbiA8IDgwID8gbiA8IDQwID8gMCA6IDEgOiAyO1xuICAgICAgICAgICAgICAgIHMgPSBtICsgXCIuXCIgKyAobiAtIG0gKiA0MCk7XG4gICAgICAgICAgICB9IGVsc2VcbiAgICAgICAgICAgICAgICBzICs9IFwiLlwiICsgKChiaXRzID49IDMxKSA/IFwiYmlnaW50XCIgOiBuKTtcbiAgICAgICAgICAgIG4gPSBiaXRzID0gMDtcbiAgICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gcztcbn07XG5cbmZ1bmN0aW9uIEFTTjEoc3RyZWFtLCBoZWFkZXIsIGxlbmd0aCwgdGFnLCBzdWIpIHtcbiAgICB0aGlzLnN0cmVhbSA9IHN0cmVhbTtcbiAgICB0aGlzLmhlYWRlciA9IGhlYWRlcjtcbiAgICB0aGlzLmxlbmd0aCA9IGxlbmd0aDtcbiAgICB0aGlzLnRhZyA9IHRhZztcbiAgICB0aGlzLnN1YiA9IHN1Yjtcbn1cbkFTTjEucHJvdG90eXBlLnR5cGVOYW1lID0gZnVuY3Rpb24gKCkge1xuICAgIGlmICh0aGlzLnRhZyA9PT0gdW5kZWZpbmVkKVxuICAgICAgICByZXR1cm4gXCJ1bmtub3duXCI7XG4gICAgdmFyIHRhZ0NsYXNzID0gdGhpcy50YWcgPj4gNixcbiAgICAgICAgdGFnQ29uc3RydWN0ZWQgPSAodGhpcy50YWcgPj4gNSkgJiAxLFxuICAgICAgICB0YWdOdW1iZXIgPSB0aGlzLnRhZyAmIDB4MUY7XG4gICAgc3dpdGNoICh0YWdDbGFzcykge1xuICAgIGNhc2UgMDogLy8gdW5pdmVyc2FsXG4gICAgICAgIHN3aXRjaCAodGFnTnVtYmVyKSB7XG4gICAgICAgIGNhc2UgMHgwMDogcmV0dXJuIFwiRU9DXCI7XG4gICAgICAgIGNhc2UgMHgwMTogcmV0dXJuIFwiQk9PTEVBTlwiO1xuICAgICAgICBjYXNlIDB4MDI6IHJldHVybiBcIklOVEVHRVJcIjtcbiAgICAgICAgY2FzZSAweDAzOiByZXR1cm4gXCJCSVRfU1RSSU5HXCI7XG4gICAgICAgIGNhc2UgMHgwNDogcmV0dXJuIFwiT0NURVRfU1RSSU5HXCI7XG4gICAgICAgIGNhc2UgMHgwNTogcmV0dXJuIFwiTlVMTFwiO1xuICAgICAgICBjYXNlIDB4MDY6IHJldHVybiBcIk9CSkVDVF9JREVOVElGSUVSXCI7XG4gICAgICAgIGNhc2UgMHgwNzogcmV0dXJuIFwiT2JqZWN0RGVzY3JpcHRvclwiO1xuICAgICAgICBjYXNlIDB4MDg6IHJldHVybiBcIkVYVEVSTkFMXCI7XG4gICAgICAgIGNhc2UgMHgwOTogcmV0dXJuIFwiUkVBTFwiO1xuICAgICAgICBjYXNlIDB4MEE6IHJldHVybiBcIkVOVU1FUkFURURcIjtcbiAgICAgICAgY2FzZSAweDBCOiByZXR1cm4gXCJFTUJFRERFRF9QRFZcIjtcbiAgICAgICAgY2FzZSAweDBDOiByZXR1cm4gXCJVVEY4U3RyaW5nXCI7XG4gICAgICAgIGNhc2UgMHgxMDogcmV0dXJuIFwiU0VRVUVOQ0VcIjtcbiAgICAgICAgY2FzZSAweDExOiByZXR1cm4gXCJTRVRcIjtcbiAgICAgICAgY2FzZSAweDEyOiByZXR1cm4gXCJOdW1lcmljU3RyaW5nXCI7XG4gICAgICAgIGNhc2UgMHgxMzogcmV0dXJuIFwiUHJpbnRhYmxlU3RyaW5nXCI7IC8vIEFTQ0lJIHN1YnNldFxuICAgICAgICBjYXNlIDB4MTQ6IHJldHVybiBcIlRlbGV0ZXhTdHJpbmdcIjsgLy8gYWthIFQ2MVN0cmluZ1xuICAgICAgICBjYXNlIDB4MTU6IHJldHVybiBcIlZpZGVvdGV4U3RyaW5nXCI7XG4gICAgICAgIGNhc2UgMHgxNjogcmV0dXJuIFwiSUE1U3RyaW5nXCI7IC8vIEFTQ0lJXG4gICAgICAgIGNhc2UgMHgxNzogcmV0dXJuIFwiVVRDVGltZVwiO1xuICAgICAgICBjYXNlIDB4MTg6IHJldHVybiBcIkdlbmVyYWxpemVkVGltZVwiO1xuICAgICAgICBjYXNlIDB4MTk6IHJldHVybiBcIkdyYXBoaWNTdHJpbmdcIjtcbiAgICAgICAgY2FzZSAweDFBOiByZXR1cm4gXCJWaXNpYmxlU3RyaW5nXCI7IC8vIEFTQ0lJIHN1YnNldFxuICAgICAgICBjYXNlIDB4MUI6IHJldHVybiBcIkdlbmVyYWxTdHJpbmdcIjtcbiAgICAgICAgY2FzZSAweDFDOiByZXR1cm4gXCJVbml2ZXJzYWxTdHJpbmdcIjtcbiAgICAgICAgY2FzZSAweDFFOiByZXR1cm4gXCJCTVBTdHJpbmdcIjtcbiAgICAgICAgZGVmYXVsdDogICByZXR1cm4gXCJVbml2ZXJzYWxfXCIgKyB0YWdOdW1iZXIudG9TdHJpbmcoMTYpO1xuICAgICAgICB9XG4gICAgY2FzZSAxOiByZXR1cm4gXCJBcHBsaWNhdGlvbl9cIiArIHRhZ051bWJlci50b1N0cmluZygxNik7XG4gICAgY2FzZSAyOiByZXR1cm4gXCJbXCIgKyB0YWdOdW1iZXIgKyBcIl1cIjsgLy8gQ29udGV4dFxuICAgIGNhc2UgMzogcmV0dXJuIFwiUHJpdmF0ZV9cIiArIHRhZ051bWJlci50b1N0cmluZygxNik7XG4gICAgfVxufTtcbkFTTjEucHJvdG90eXBlLnJlU2VlbXNBU0NJSSA9IC9eWyAtfl0rJC87XG5BU04xLnByb3RvdHlwZS5jb250ZW50ID0gZnVuY3Rpb24gKCkge1xuICAgIGlmICh0aGlzLnRhZyA9PT0gdW5kZWZpbmVkKVxuICAgICAgICByZXR1cm4gbnVsbDtcbiAgICB2YXIgdGFnQ2xhc3MgPSB0aGlzLnRhZyA+PiA2LFxuICAgICAgICB0YWdOdW1iZXIgPSB0aGlzLnRhZyAmIDB4MUYsXG4gICAgICAgIGNvbnRlbnQgPSB0aGlzLnBvc0NvbnRlbnQoKSxcbiAgICAgICAgbGVuID0gTWF0aC5hYnModGhpcy5sZW5ndGgpO1xuICAgIGlmICh0YWdDbGFzcyAhPT0gMCkgeyAvLyB1bml2ZXJzYWxcbiAgICAgICAgaWYgKHRoaXMuc3ViICE9PSBudWxsKVxuICAgICAgICAgICAgcmV0dXJuIFwiKFwiICsgdGhpcy5zdWIubGVuZ3RoICsgXCIgZWxlbSlcIjtcbiAgICAgICAgLy9UT0RPOiBUUlkgVE8gUEFSU0UgQVNDSUkgU1RSSU5HXG4gICAgICAgIHZhciBzID0gdGhpcy5zdHJlYW0ucGFyc2VTdHJpbmdJU08oY29udGVudCwgY29udGVudCArIE1hdGgubWluKGxlbiwgaGFyZExpbWl0KSk7XG4gICAgICAgIGlmICh0aGlzLnJlU2VlbXNBU0NJSS50ZXN0KHMpKVxuICAgICAgICAgICAgcmV0dXJuIHMuc3Vic3RyaW5nKDAsIDIgKiBoYXJkTGltaXQpICsgKChzLmxlbmd0aCA+IDIgKiBoYXJkTGltaXQpID8gZWxsaXBzaXMgOiBcIlwiKTtcbiAgICAgICAgZWxzZVxuICAgICAgICAgICAgcmV0dXJuIHRoaXMuc3RyZWFtLnBhcnNlT2N0ZXRTdHJpbmcoY29udGVudCwgY29udGVudCArIGxlbik7XG4gICAgfVxuICAgIHN3aXRjaCAodGFnTnVtYmVyKSB7XG4gICAgY2FzZSAweDAxOiAvLyBCT09MRUFOXG4gICAgICAgIHJldHVybiAodGhpcy5zdHJlYW0uZ2V0KGNvbnRlbnQpID09PSAwKSA/IFwiZmFsc2VcIiA6IFwidHJ1ZVwiO1xuICAgIGNhc2UgMHgwMjogLy8gSU5URUdFUlxuICAgICAgICByZXR1cm4gdGhpcy5zdHJlYW0ucGFyc2VJbnRlZ2VyKGNvbnRlbnQsIGNvbnRlbnQgKyBsZW4pO1xuICAgIGNhc2UgMHgwMzogLy8gQklUX1NUUklOR1xuICAgICAgICByZXR1cm4gdGhpcy5zdWIgPyBcIihcIiArIHRoaXMuc3ViLmxlbmd0aCArIFwiIGVsZW0pXCIgOlxuICAgICAgICAgICAgdGhpcy5zdHJlYW0ucGFyc2VCaXRTdHJpbmcoY29udGVudCwgY29udGVudCArIGxlbik7XG4gICAgY2FzZSAweDA0OiAvLyBPQ1RFVF9TVFJJTkdcbiAgICAgICAgcmV0dXJuIHRoaXMuc3ViID8gXCIoXCIgKyB0aGlzLnN1Yi5sZW5ndGggKyBcIiBlbGVtKVwiIDpcbiAgICAgICAgICAgIHRoaXMuc3RyZWFtLnBhcnNlT2N0ZXRTdHJpbmcoY29udGVudCwgY29udGVudCArIGxlbik7XG4gICAgLy9jYXNlIDB4MDU6IC8vIE5VTExcbiAgICBjYXNlIDB4MDY6IC8vIE9CSkVDVF9JREVOVElGSUVSXG4gICAgICAgIHJldHVybiB0aGlzLnN0cmVhbS5wYXJzZU9JRChjb250ZW50LCBjb250ZW50ICsgbGVuKTtcbiAgICAvL2Nhc2UgMHgwNzogLy8gT2JqZWN0RGVzY3JpcHRvclxuICAgIC8vY2FzZSAweDA4OiAvLyBFWFRFUk5BTFxuICAgIC8vY2FzZSAweDA5OiAvLyBSRUFMXG4gICAgLy9jYXNlIDB4MEE6IC8vIEVOVU1FUkFURURcbiAgICAvL2Nhc2UgMHgwQjogLy8gRU1CRURERURfUERWXG4gICAgY2FzZSAweDEwOiAvLyBTRVFVRU5DRVxuICAgIGNhc2UgMHgxMTogLy8gU0VUXG4gICAgICAgIHJldHVybiBcIihcIiArIHRoaXMuc3ViLmxlbmd0aCArIFwiIGVsZW0pXCI7XG4gICAgY2FzZSAweDBDOiAvLyBVVEY4U3RyaW5nXG4gICAgICAgIHJldHVybiB0aGlzLnN0cmVhbS5wYXJzZVN0cmluZ1VURihjb250ZW50LCBjb250ZW50ICsgbGVuKTtcbiAgICBjYXNlIDB4MTI6IC8vIE51bWVyaWNTdHJpbmdcbiAgICBjYXNlIDB4MTM6IC8vIFByaW50YWJsZVN0cmluZ1xuICAgIGNhc2UgMHgxNDogLy8gVGVsZXRleFN0cmluZ1xuICAgIGNhc2UgMHgxNTogLy8gVmlkZW90ZXhTdHJpbmdcbiAgICBjYXNlIDB4MTY6IC8vIElBNVN0cmluZ1xuICAgIC8vY2FzZSAweDE5OiAvLyBHcmFwaGljU3RyaW5nXG4gICAgY2FzZSAweDFBOiAvLyBWaXNpYmxlU3RyaW5nXG4gICAgLy9jYXNlIDB4MUI6IC8vIEdlbmVyYWxTdHJpbmdcbiAgICAvL2Nhc2UgMHgxQzogLy8gVW5pdmVyc2FsU3RyaW5nXG4gICAgICAgIHJldHVybiB0aGlzLnN0cmVhbS5wYXJzZVN0cmluZ0lTTyhjb250ZW50LCBjb250ZW50ICsgbGVuKTtcbiAgICBjYXNlIDB4MUU6IC8vIEJNUFN0cmluZ1xuICAgICAgICByZXR1cm4gdGhpcy5zdHJlYW0ucGFyc2VTdHJpbmdCTVAoY29udGVudCwgY29udGVudCArIGxlbik7XG4gICAgY2FzZSAweDE3OiAvLyBVVENUaW1lXG4gICAgY2FzZSAweDE4OiAvLyBHZW5lcmFsaXplZFRpbWVcbiAgICAgICAgcmV0dXJuIHRoaXMuc3RyZWFtLnBhcnNlVGltZShjb250ZW50LCBjb250ZW50ICsgbGVuKTtcbiAgICB9XG4gICAgcmV0dXJuIG51bGw7XG59O1xuQVNOMS5wcm90b3R5cGUudG9TdHJpbmcgPSBmdW5jdGlvbiAoKSB7XG4gICAgcmV0dXJuIHRoaXMudHlwZU5hbWUoKSArIFwiQFwiICsgdGhpcy5zdHJlYW0ucG9zICsgXCJbaGVhZGVyOlwiICsgdGhpcy5oZWFkZXIgKyBcIixsZW5ndGg6XCIgKyB0aGlzLmxlbmd0aCArIFwiLHN1YjpcIiArICgodGhpcy5zdWIgPT09IG51bGwpID8gJ251bGwnIDogdGhpcy5zdWIubGVuZ3RoKSArIFwiXVwiO1xufTtcbkFTTjEucHJvdG90eXBlLnByaW50ID0gZnVuY3Rpb24gKGluZGVudCkge1xuICAgIGlmIChpbmRlbnQgPT09IHVuZGVmaW5lZCkgaW5kZW50ID0gJyc7XG4gICAgZG9jdW1lbnQud3JpdGVsbihpbmRlbnQgKyB0aGlzKTtcbiAgICBpZiAodGhpcy5zdWIgIT09IG51bGwpIHtcbiAgICAgICAgaW5kZW50ICs9ICcgICc7XG4gICAgICAgIGZvciAodmFyIGkgPSAwLCBtYXggPSB0aGlzLnN1Yi5sZW5ndGg7IGkgPCBtYXg7ICsraSlcbiAgICAgICAgICAgIHRoaXMuc3ViW2ldLnByaW50KGluZGVudCk7XG4gICAgfVxufTtcbkFTTjEucHJvdG90eXBlLnRvUHJldHR5U3RyaW5nID0gZnVuY3Rpb24gKGluZGVudCkge1xuICAgIGlmIChpbmRlbnQgPT09IHVuZGVmaW5lZCkgaW5kZW50ID0gJyc7XG4gICAgdmFyIHMgPSBpbmRlbnQgKyB0aGlzLnR5cGVOYW1lKCkgKyBcIiBAXCIgKyB0aGlzLnN0cmVhbS5wb3M7XG4gICAgaWYgKHRoaXMubGVuZ3RoID49IDApXG4gICAgICAgIHMgKz0gXCIrXCI7XG4gICAgcyArPSB0aGlzLmxlbmd0aDtcbiAgICBpZiAodGhpcy50YWcgJiAweDIwKVxuICAgICAgICBzICs9IFwiIChjb25zdHJ1Y3RlZClcIjtcbiAgICBlbHNlIGlmICgoKHRoaXMudGFnID09IDB4MDMpIHx8ICh0aGlzLnRhZyA9PSAweDA0KSkgJiYgKHRoaXMuc3ViICE9PSBudWxsKSlcbiAgICAgICAgcyArPSBcIiAoZW5jYXBzdWxhdGVzKVwiO1xuICAgIHMgKz0gXCJcXG5cIjtcbiAgICBpZiAodGhpcy5zdWIgIT09IG51bGwpIHtcbiAgICAgICAgaW5kZW50ICs9ICcgICc7XG4gICAgICAgIGZvciAodmFyIGkgPSAwLCBtYXggPSB0aGlzLnN1Yi5sZW5ndGg7IGkgPCBtYXg7ICsraSlcbiAgICAgICAgICAgIHMgKz0gdGhpcy5zdWJbaV0udG9QcmV0dHlTdHJpbmcoaW5kZW50KTtcbiAgICB9XG4gICAgcmV0dXJuIHM7XG59O1xuQVNOMS5wcm90b3R5cGUudG9ET00gPSBmdW5jdGlvbiAoKSB7XG4gICAgdmFyIG5vZGUgPSBET00udGFnKFwiZGl2XCIsIFwibm9kZVwiKTtcbiAgICBub2RlLmFzbjEgPSB0aGlzO1xuICAgIHZhciBoZWFkID0gRE9NLnRhZyhcImRpdlwiLCBcImhlYWRcIik7XG4gICAgdmFyIHMgPSB0aGlzLnR5cGVOYW1lKCkucmVwbGFjZSgvXy9nLCBcIiBcIik7XG4gICAgaGVhZC5pbm5lckhUTUwgPSBzO1xuICAgIHZhciBjb250ZW50ID0gdGhpcy5jb250ZW50KCk7XG4gICAgaWYgKGNvbnRlbnQgIT09IG51bGwpIHtcbiAgICAgICAgY29udGVudCA9IFN0cmluZyhjb250ZW50KS5yZXBsYWNlKC88L2csIFwiJmx0O1wiKTtcbiAgICAgICAgdmFyIHByZXZpZXcgPSBET00udGFnKFwic3BhblwiLCBcInByZXZpZXdcIik7XG4gICAgICAgIHByZXZpZXcuYXBwZW5kQ2hpbGQoRE9NLnRleHQoY29udGVudCkpO1xuICAgICAgICBoZWFkLmFwcGVuZENoaWxkKHByZXZpZXcpO1xuICAgIH1cbiAgICBub2RlLmFwcGVuZENoaWxkKGhlYWQpO1xuICAgIHRoaXMubm9kZSA9IG5vZGU7XG4gICAgdGhpcy5oZWFkID0gaGVhZDtcbiAgICB2YXIgdmFsdWUgPSBET00udGFnKFwiZGl2XCIsIFwidmFsdWVcIik7XG4gICAgcyA9IFwiT2Zmc2V0OiBcIiArIHRoaXMuc3RyZWFtLnBvcyArIFwiPGJyLz5cIjtcbiAgICBzICs9IFwiTGVuZ3RoOiBcIiArIHRoaXMuaGVhZGVyICsgXCIrXCI7XG4gICAgaWYgKHRoaXMubGVuZ3RoID49IDApXG4gICAgICAgIHMgKz0gdGhpcy5sZW5ndGg7XG4gICAgZWxzZVxuICAgICAgICBzICs9ICgtdGhpcy5sZW5ndGgpICsgXCIgKHVuZGVmaW5lZClcIjtcbiAgICBpZiAodGhpcy50YWcgJiAweDIwKVxuICAgICAgICBzICs9IFwiPGJyLz4oY29uc3RydWN0ZWQpXCI7XG4gICAgZWxzZSBpZiAoKCh0aGlzLnRhZyA9PSAweDAzKSB8fCAodGhpcy50YWcgPT0gMHgwNCkpICYmICh0aGlzLnN1YiAhPT0gbnVsbCkpXG4gICAgICAgIHMgKz0gXCI8YnIvPihlbmNhcHN1bGF0ZXMpXCI7XG4gICAgLy9UT0RPIGlmICh0aGlzLnRhZyA9PSAweDAzKSBzICs9IFwiVW51c2VkIGJpdHM6IFwiXG4gICAgaWYgKGNvbnRlbnQgIT09IG51bGwpIHtcbiAgICAgICAgcyArPSBcIjxici8+VmFsdWU6PGJyLz48Yj5cIiArIGNvbnRlbnQgKyBcIjwvYj5cIjtcbiAgICAgICAgaWYgKCh0eXBlb2Ygb2lkcyA9PT0gJ29iamVjdCcpICYmICh0aGlzLnRhZyA9PSAweDA2KSkge1xuICAgICAgICAgICAgdmFyIG9pZCA9IG9pZHNbY29udGVudF07XG4gICAgICAgICAgICBpZiAob2lkKSB7XG4gICAgICAgICAgICAgICAgaWYgKG9pZC5kKSBzICs9IFwiPGJyLz5cIiArIG9pZC5kO1xuICAgICAgICAgICAgICAgIGlmIChvaWQuYykgcyArPSBcIjxici8+XCIgKyBvaWQuYztcbiAgICAgICAgICAgICAgICBpZiAob2lkLncpIHMgKz0gXCI8YnIvPih3YXJuaW5nISlcIjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbiAgICB2YWx1ZS5pbm5lckhUTUwgPSBzO1xuICAgIG5vZGUuYXBwZW5kQ2hpbGQodmFsdWUpO1xuICAgIHZhciBzdWIgPSBET00udGFnKFwiZGl2XCIsIFwic3ViXCIpO1xuICAgIGlmICh0aGlzLnN1YiAhPT0gbnVsbCkge1xuICAgICAgICBmb3IgKHZhciBpID0gMCwgbWF4ID0gdGhpcy5zdWIubGVuZ3RoOyBpIDwgbWF4OyArK2kpXG4gICAgICAgICAgICBzdWIuYXBwZW5kQ2hpbGQodGhpcy5zdWJbaV0udG9ET00oKSk7XG4gICAgfVxuICAgIG5vZGUuYXBwZW5kQ2hpbGQoc3ViKTtcbiAgICBoZWFkLm9uY2xpY2sgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIG5vZGUuY2xhc3NOYW1lID0gKG5vZGUuY2xhc3NOYW1lID09IFwibm9kZSBjb2xsYXBzZWRcIikgPyBcIm5vZGVcIiA6IFwibm9kZSBjb2xsYXBzZWRcIjtcbiAgICB9O1xuICAgIHJldHVybiBub2RlO1xufTtcbkFTTjEucHJvdG90eXBlLnBvc1N0YXJ0ID0gZnVuY3Rpb24gKCkge1xuICAgIHJldHVybiB0aGlzLnN0cmVhbS5wb3M7XG59O1xuQVNOMS5wcm90b3R5cGUucG9zQ29udGVudCA9IGZ1bmN0aW9uICgpIHtcbiAgICByZXR1cm4gdGhpcy5zdHJlYW0ucG9zICsgdGhpcy5oZWFkZXI7XG59O1xuQVNOMS5wcm90b3R5cGUucG9zRW5kID0gZnVuY3Rpb24gKCkge1xuICAgIHJldHVybiB0aGlzLnN0cmVhbS5wb3MgKyB0aGlzLmhlYWRlciArIE1hdGguYWJzKHRoaXMubGVuZ3RoKTtcbn07XG5BU04xLnByb3RvdHlwZS5mYWtlSG92ZXIgPSBmdW5jdGlvbiAoY3VycmVudCkge1xuICAgIHRoaXMubm9kZS5jbGFzc05hbWUgKz0gXCIgaG92ZXJcIjtcbiAgICBpZiAoY3VycmVudClcbiAgICAgICAgdGhpcy5oZWFkLmNsYXNzTmFtZSArPSBcIiBob3ZlclwiO1xufTtcbkFTTjEucHJvdG90eXBlLmZha2VPdXQgPSBmdW5jdGlvbiAoY3VycmVudCkge1xuICAgIHZhciByZSA9IC8gP2hvdmVyLztcbiAgICB0aGlzLm5vZGUuY2xhc3NOYW1lID0gdGhpcy5ub2RlLmNsYXNzTmFtZS5yZXBsYWNlKHJlLCBcIlwiKTtcbiAgICBpZiAoY3VycmVudClcbiAgICAgICAgdGhpcy5oZWFkLmNsYXNzTmFtZSA9IHRoaXMuaGVhZC5jbGFzc05hbWUucmVwbGFjZShyZSwgXCJcIik7XG59O1xuQVNOMS5wcm90b3R5cGUudG9IZXhET01fc3ViID0gZnVuY3Rpb24gKG5vZGUsIGNsYXNzTmFtZSwgc3RyZWFtLCBzdGFydCwgZW5kKSB7XG4gICAgaWYgKHN0YXJ0ID49IGVuZClcbiAgICAgICAgcmV0dXJuO1xuICAgIHZhciBzdWIgPSBET00udGFnKFwic3BhblwiLCBjbGFzc05hbWUpO1xuICAgIHN1Yi5hcHBlbmRDaGlsZChET00udGV4dChcbiAgICAgICAgc3RyZWFtLmhleER1bXAoc3RhcnQsIGVuZCkpKTtcbiAgICBub2RlLmFwcGVuZENoaWxkKHN1Yik7XG59O1xuQVNOMS5wcm90b3R5cGUudG9IZXhET00gPSBmdW5jdGlvbiAocm9vdCkge1xuICAgIHZhciBub2RlID0gRE9NLnRhZyhcInNwYW5cIiwgXCJoZXhcIik7XG4gICAgaWYgKHJvb3QgPT09IHVuZGVmaW5lZCkgcm9vdCA9IG5vZGU7XG4gICAgdGhpcy5oZWFkLmhleE5vZGUgPSBub2RlO1xuICAgIHRoaXMuaGVhZC5vbm1vdXNlb3ZlciA9IGZ1bmN0aW9uICgpIHsgdGhpcy5oZXhOb2RlLmNsYXNzTmFtZSA9IFwiaGV4Q3VycmVudFwiOyB9O1xuICAgIHRoaXMuaGVhZC5vbm1vdXNlb3V0ICA9IGZ1bmN0aW9uICgpIHsgdGhpcy5oZXhOb2RlLmNsYXNzTmFtZSA9IFwiaGV4XCI7IH07XG4gICAgbm9kZS5hc24xID0gdGhpcztcbiAgICBub2RlLm9ubW91c2VvdmVyID0gZnVuY3Rpb24gKCkge1xuICAgICAgICB2YXIgY3VycmVudCA9ICFyb290LnNlbGVjdGVkO1xuICAgICAgICBpZiAoY3VycmVudCkge1xuICAgICAgICAgICAgcm9vdC5zZWxlY3RlZCA9IHRoaXMuYXNuMTtcbiAgICAgICAgICAgIHRoaXMuY2xhc3NOYW1lID0gXCJoZXhDdXJyZW50XCI7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5hc24xLmZha2VIb3ZlcihjdXJyZW50KTtcbiAgICB9O1xuICAgIG5vZGUub25tb3VzZW91dCAgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHZhciBjdXJyZW50ID0gKHJvb3Quc2VsZWN0ZWQgPT0gdGhpcy5hc24xKTtcbiAgICAgICAgdGhpcy5hc24xLmZha2VPdXQoY3VycmVudCk7XG4gICAgICAgIGlmIChjdXJyZW50KSB7XG4gICAgICAgICAgICByb290LnNlbGVjdGVkID0gbnVsbDtcbiAgICAgICAgICAgIHRoaXMuY2xhc3NOYW1lID0gXCJoZXhcIjtcbiAgICAgICAgfVxuICAgIH07XG4gICAgdGhpcy50b0hleERPTV9zdWIobm9kZSwgXCJ0YWdcIiwgdGhpcy5zdHJlYW0sIHRoaXMucG9zU3RhcnQoKSwgdGhpcy5wb3NTdGFydCgpICsgMSk7XG4gICAgdGhpcy50b0hleERPTV9zdWIobm9kZSwgKHRoaXMubGVuZ3RoID49IDApID8gXCJkbGVuXCIgOiBcInVsZW5cIiwgdGhpcy5zdHJlYW0sIHRoaXMucG9zU3RhcnQoKSArIDEsIHRoaXMucG9zQ29udGVudCgpKTtcbiAgICBpZiAodGhpcy5zdWIgPT09IG51bGwpXG4gICAgICAgIG5vZGUuYXBwZW5kQ2hpbGQoRE9NLnRleHQoXG4gICAgICAgICAgICB0aGlzLnN0cmVhbS5oZXhEdW1wKHRoaXMucG9zQ29udGVudCgpLCB0aGlzLnBvc0VuZCgpKSkpO1xuICAgIGVsc2UgaWYgKHRoaXMuc3ViLmxlbmd0aCA+IDApIHtcbiAgICAgICAgdmFyIGZpcnN0ID0gdGhpcy5zdWJbMF07XG4gICAgICAgIHZhciBsYXN0ID0gdGhpcy5zdWJbdGhpcy5zdWIubGVuZ3RoIC0gMV07XG4gICAgICAgIHRoaXMudG9IZXhET01fc3ViKG5vZGUsIFwiaW50cm9cIiwgdGhpcy5zdHJlYW0sIHRoaXMucG9zQ29udGVudCgpLCBmaXJzdC5wb3NTdGFydCgpKTtcbiAgICAgICAgZm9yICh2YXIgaSA9IDAsIG1heCA9IHRoaXMuc3ViLmxlbmd0aDsgaSA8IG1heDsgKytpKVxuICAgICAgICAgICAgbm9kZS5hcHBlbmRDaGlsZCh0aGlzLnN1YltpXS50b0hleERPTShyb290KSk7XG4gICAgICAgIHRoaXMudG9IZXhET01fc3ViKG5vZGUsIFwib3V0cm9cIiwgdGhpcy5zdHJlYW0sIGxhc3QucG9zRW5kKCksIHRoaXMucG9zRW5kKCkpO1xuICAgIH1cbiAgICByZXR1cm4gbm9kZTtcbn07XG5BU04xLnByb3RvdHlwZS50b0hleFN0cmluZyA9IGZ1bmN0aW9uIChyb290KSB7XG4gICAgcmV0dXJuIHRoaXMuc3RyZWFtLmhleER1bXAodGhpcy5wb3NTdGFydCgpLCB0aGlzLnBvc0VuZCgpLCB0cnVlKTtcbn07XG5BU04xLmRlY29kZUxlbmd0aCA9IGZ1bmN0aW9uIChzdHJlYW0pIHtcbiAgICB2YXIgYnVmID0gc3RyZWFtLmdldCgpLFxuICAgICAgICBsZW4gPSBidWYgJiAweDdGO1xuICAgIGlmIChsZW4gPT0gYnVmKVxuICAgICAgICByZXR1cm4gbGVuO1xuICAgIGlmIChsZW4gPiAzKVxuICAgICAgICB0aHJvdyBcIkxlbmd0aCBvdmVyIDI0IGJpdHMgbm90IHN1cHBvcnRlZCBhdCBwb3NpdGlvbiBcIiArIChzdHJlYW0ucG9zIC0gMSk7XG4gICAgaWYgKGxlbiA9PT0gMClcbiAgICAgICAgcmV0dXJuIC0xOyAvLyB1bmRlZmluZWRcbiAgICBidWYgPSAwO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgbGVuOyArK2kpXG4gICAgICAgIGJ1ZiA9IChidWYgPDwgOCkgfCBzdHJlYW0uZ2V0KCk7XG4gICAgcmV0dXJuIGJ1Zjtcbn07XG5BU04xLmhhc0NvbnRlbnQgPSBmdW5jdGlvbiAodGFnLCBsZW4sIHN0cmVhbSkge1xuICAgIGlmICh0YWcgJiAweDIwKSAvLyBjb25zdHJ1Y3RlZFxuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICBpZiAoKHRhZyA8IDB4MDMpIHx8ICh0YWcgPiAweDA0KSlcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIHZhciBwID0gbmV3IFN0cmVhbShzdHJlYW0pO1xuICAgIGlmICh0YWcgPT0gMHgwMykgcC5nZXQoKTsgLy8gQml0U3RyaW5nIHVudXNlZCBiaXRzLCBtdXN0IGJlIGluIFswLCA3XVxuICAgIHZhciBzdWJUYWcgPSBwLmdldCgpO1xuICAgIGlmICgoc3ViVGFnID4+IDYpICYgMHgwMSkgLy8gbm90ICh1bml2ZXJzYWwgb3IgY29udGV4dClcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIHRyeSB7XG4gICAgICAgIHZhciBzdWJMZW5ndGggPSBBU04xLmRlY29kZUxlbmd0aChwKTtcbiAgICAgICAgcmV0dXJuICgocC5wb3MgLSBzdHJlYW0ucG9zKSArIHN1Ykxlbmd0aCA9PSBsZW4pO1xuICAgIH0gY2F0Y2ggKGV4Y2VwdGlvbikge1xuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxufTtcbkFTTjEuZGVjb2RlID0gZnVuY3Rpb24gKHN0cmVhbSkge1xuICAgIGlmICghKHN0cmVhbSBpbnN0YW5jZW9mIFN0cmVhbSkpXG4gICAgICAgIHN0cmVhbSA9IG5ldyBTdHJlYW0oc3RyZWFtLCAwKTtcbiAgICB2YXIgc3RyZWFtU3RhcnQgPSBuZXcgU3RyZWFtKHN0cmVhbSksXG4gICAgICAgIHRhZyA9IHN0cmVhbS5nZXQoKSxcbiAgICAgICAgbGVuID0gQVNOMS5kZWNvZGVMZW5ndGgoc3RyZWFtKSxcbiAgICAgICAgaGVhZGVyID0gc3RyZWFtLnBvcyAtIHN0cmVhbVN0YXJ0LnBvcyxcbiAgICAgICAgc3ViID0gbnVsbDtcbiAgICBpZiAoQVNOMS5oYXNDb250ZW50KHRhZywgbGVuLCBzdHJlYW0pKSB7XG4gICAgICAgIC8vIGl0IGhhcyBjb250ZW50LCBzbyB3ZSBkZWNvZGUgaXRcbiAgICAgICAgdmFyIHN0YXJ0ID0gc3RyZWFtLnBvcztcbiAgICAgICAgaWYgKHRhZyA9PSAweDAzKSBzdHJlYW0uZ2V0KCk7IC8vIHNraXAgQml0U3RyaW5nIHVudXNlZCBiaXRzLCBtdXN0IGJlIGluIFswLCA3XVxuICAgICAgICBzdWIgPSBbXTtcbiAgICAgICAgaWYgKGxlbiA+PSAwKSB7XG4gICAgICAgICAgICAvLyBkZWZpbml0ZSBsZW5ndGhcbiAgICAgICAgICAgIHZhciBlbmQgPSBzdGFydCArIGxlbjtcbiAgICAgICAgICAgIHdoaWxlIChzdHJlYW0ucG9zIDwgZW5kKVxuICAgICAgICAgICAgICAgIHN1YltzdWIubGVuZ3RoXSA9IEFTTjEuZGVjb2RlKHN0cmVhbSk7XG4gICAgICAgICAgICBpZiAoc3RyZWFtLnBvcyAhPSBlbmQpXG4gICAgICAgICAgICAgICAgdGhyb3cgXCJDb250ZW50IHNpemUgaXMgbm90IGNvcnJlY3QgZm9yIGNvbnRhaW5lciBzdGFydGluZyBhdCBvZmZzZXQgXCIgKyBzdGFydDtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIC8vIHVuZGVmaW5lZCBsZW5ndGhcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgZm9yICg7Oykge1xuICAgICAgICAgICAgICAgICAgICB2YXIgcyA9IEFTTjEuZGVjb2RlKHN0cmVhbSk7XG4gICAgICAgICAgICAgICAgICAgIGlmIChzLnRhZyA9PT0gMClcbiAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgICAgICBzdWJbc3ViLmxlbmd0aF0gPSBzO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBsZW4gPSBzdGFydCAtIHN0cmVhbS5wb3M7XG4gICAgICAgICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgXCJFeGNlcHRpb24gd2hpbGUgZGVjb2RpbmcgdW5kZWZpbmVkIGxlbmd0aCBjb250ZW50OiBcIiArIGU7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9IGVsc2VcbiAgICAgICAgc3RyZWFtLnBvcyArPSBsZW47IC8vIHNraXAgY29udGVudFxuICAgIHJldHVybiBuZXcgQVNOMShzdHJlYW1TdGFydCwgaGVhZGVyLCBsZW4sIHRhZywgc3ViKTtcbn07XG5BU04xLnRlc3QgPSBmdW5jdGlvbiAoKSB7XG4gICAgdmFyIHRlc3QgPSBbXG4gICAgICAgIHsgdmFsdWU6IFsweDI3XSwgICAgICAgICAgICAgICAgICAgZXhwZWN0ZWQ6IDB4MjcgICAgIH0sXG4gICAgICAgIHsgdmFsdWU6IFsweDgxLCAweEM5XSwgICAgICAgICAgICAgZXhwZWN0ZWQ6IDB4QzkgICAgIH0sXG4gICAgICAgIHsgdmFsdWU6IFsweDgzLCAweEZFLCAweERDLCAweEJBXSwgZXhwZWN0ZWQ6IDB4RkVEQ0JBIH1cbiAgICBdO1xuICAgIGZvciAodmFyIGkgPSAwLCBtYXggPSB0ZXN0Lmxlbmd0aDsgaSA8IG1heDsgKytpKSB7XG4gICAgICAgIHZhciBwb3MgPSAwLFxuICAgICAgICAgICAgc3RyZWFtID0gbmV3IFN0cmVhbSh0ZXN0W2ldLnZhbHVlLCAwKSxcbiAgICAgICAgICAgIHJlcyA9IEFTTjEuZGVjb2RlTGVuZ3RoKHN0cmVhbSk7XG4gICAgICAgIGlmIChyZXMgIT0gdGVzdFtpXS5leHBlY3RlZClcbiAgICAgICAgICAgIGRvY3VtZW50LndyaXRlKFwiSW4gdGVzdFtcIiArIGkgKyBcIl0gZXhwZWN0ZWQgXCIgKyB0ZXN0W2ldLmV4cGVjdGVkICsgXCIgZ290IFwiICsgcmVzICsgXCJcXG5cIik7XG4gICAgfVxufTtcblxuLy8gZXhwb3J0IGdsb2JhbHNcbndpbmRvdy5BU04xID0gQVNOMTtcbn0pKCk7XG4vKipcbiAqIFJldHJpZXZlIHRoZSBoZXhhZGVjaW1hbCB2YWx1ZSAoYXMgYSBzdHJpbmcpIG9mIHRoZSBjdXJyZW50IEFTTi4xIGVsZW1lbnRcbiAqIEByZXR1cm5zIHtzdHJpbmd9XG4gKiBAcHVibGljXG4gKi9cbkFTTjEucHJvdG90eXBlLmdldEhleFN0cmluZ1ZhbHVlID0gZnVuY3Rpb24gKCkge1xuICB2YXIgaGV4U3RyaW5nID0gdGhpcy50b0hleFN0cmluZygpO1xuICB2YXIgb2Zmc2V0ID0gdGhpcy5oZWFkZXIgKiAyO1xuICB2YXIgbGVuZ3RoID0gdGhpcy5sZW5ndGggKiAyO1xuICByZXR1cm4gaGV4U3RyaW5nLnN1YnN0cihvZmZzZXQsIGxlbmd0aCk7XG59O1xuXG4vKipcbiAqIE1ldGhvZCB0byBwYXJzZSBhIHBlbSBlbmNvZGVkIHN0cmluZyBjb250YWluaW5nIGJvdGggYSBwdWJsaWMgb3IgcHJpdmF0ZSBrZXkuXG4gKiBUaGUgbWV0aG9kIHdpbGwgdHJhbnNsYXRlIHRoZSBwZW0gZW5jb2RlZCBzdHJpbmcgaW4gYSBkZXIgZW5jb2RlZCBzdHJpbmcgYW5kXG4gKiB3aWxsIHBhcnNlIHByaXZhdGUga2V5IGFuZCBwdWJsaWMga2V5IHBhcmFtZXRlcnMuIFRoaXMgbWV0aG9kIGFjY2VwdHMgcHVibGljIGtleVxuICogaW4gdGhlIHJzYWVuY3J5cHRpb24gcGtjcyAjMSBmb3JtYXQgKG9pZDogMS4yLjg0MC4xMTM1NDkuMS4xLjEpLlxuICpcbiAqIEB0b2RvIENoZWNrIGhvdyBtYW55IHJzYSBmb3JtYXRzIHVzZSB0aGUgc2FtZSBmb3JtYXQgb2YgcGtjcyAjMS5cbiAqXG4gKiBUaGUgZm9ybWF0IGlzIGRlZmluZWQgYXM6XG4gKiBQdWJsaWNLZXlJbmZvIDo6PSBTRVFVRU5DRSB7XG4gKiAgIGFsZ29yaXRobSAgICAgICBBbGdvcml0aG1JZGVudGlmaWVyLFxuICogICBQdWJsaWNLZXkgICAgICAgQklUIFNUUklOR1xuICogfVxuICogV2hlcmUgQWxnb3JpdGhtSWRlbnRpZmllciBpczpcbiAqIEFsZ29yaXRobUlkZW50aWZpZXIgOjo9IFNFUVVFTkNFIHtcbiAqICAgYWxnb3JpdGhtICAgICAgIE9CSkVDVCBJREVOVElGSUVSLCAgICAgdGhlIE9JRCBvZiB0aGUgZW5jIGFsZ29yaXRobVxuICogICBwYXJhbWV0ZXJzICAgICAgQU5ZIERFRklORUQgQlkgYWxnb3JpdGhtIE9QVElPTkFMIChOVUxMIGZvciBQS0NTICMxKVxuICogfVxuICogYW5kIFB1YmxpY0tleSBpcyBhIFNFUVVFTkNFIGVuY2Fwc3VsYXRlZCBpbiBhIEJJVCBTVFJJTkdcbiAqIFJTQVB1YmxpY0tleSA6Oj0gU0VRVUVOQ0Uge1xuICogICBtb2R1bHVzICAgICAgICAgICBJTlRFR0VSLCAgLS0gblxuICogICBwdWJsaWNFeHBvbmVudCAgICBJTlRFR0VSICAgLS0gZVxuICogfVxuICogaXQncyBwb3NzaWJsZSB0byBleGFtaW5lIHRoZSBzdHJ1Y3R1cmUgb2YgdGhlIGtleXMgb2J0YWluZWQgZnJvbSBvcGVuc3NsIHVzaW5nXG4gKiBhbiBhc24uMSBkdW1wZXIgYXMgdGhlIG9uZSB1c2VkIGhlcmUgdG8gcGFyc2UgdGhlIGNvbXBvbmVudHM6IGh0dHA6Ly9sYXBvLml0L2FzbjFqcy9cbiAqIEBhcmd1bWVudCB7c3RyaW5nfSBwZW0gdGhlIHBlbSBlbmNvZGVkIHN0cmluZywgY2FuIGluY2x1ZGUgdGhlIEJFR0lOL0VORCBoZWFkZXIvZm9vdGVyXG4gKiBAcHJpdmF0ZVxuICovXG5SU0FLZXkucHJvdG90eXBlLnBhcnNlS2V5ID0gZnVuY3Rpb24gKHBlbSkge1xuICB0cnkge1xuICAgIHZhciBtb2R1bHVzID0gMDtcbiAgICB2YXIgcHVibGljX2V4cG9uZW50ID0gMDtcbiAgICB2YXIgcmVIZXggPSAvXlxccyooPzpbMC05QS1GYS1mXVswLTlBLUZhLWZdXFxzKikrJC87XG4gICAgdmFyIGRlciA9IHJlSGV4LnRlc3QocGVtKSA/IEhleC5kZWNvZGUocGVtKSA6IEJhc2U2NC51bmFybW9yKHBlbSk7XG4gICAgdmFyIGFzbjEgPSBBU04xLmRlY29kZShkZXIpO1xuXG4gICAgLy9GaXhlcyBhIGJ1ZyB3aXRoIE9wZW5TU0wgMS4wKyBwcml2YXRlIGtleXNcbiAgICBpZihhc24xLnN1Yi5sZW5ndGggPT09IDMpe1xuICAgICAgICBhc24xID0gYXNuMS5zdWJbMl0uc3ViWzBdO1xuICAgIH1cbiAgICBpZiAoYXNuMS5zdWIubGVuZ3RoID09PSA5KSB7XG5cbiAgICAgIC8vIFBhcnNlIHRoZSBwcml2YXRlIGtleS5cbiAgICAgIG1vZHVsdXMgPSBhc24xLnN1YlsxXS5nZXRIZXhTdHJpbmdWYWx1ZSgpOyAvL2JpZ2ludFxuICAgICAgdGhpcy5uID0gcGFyc2VCaWdJbnQobW9kdWx1cywgMTYpO1xuXG4gICAgICBwdWJsaWNfZXhwb25lbnQgPSBhc24xLnN1YlsyXS5nZXRIZXhTdHJpbmdWYWx1ZSgpOyAvL2ludFxuICAgICAgdGhpcy5lID0gcGFyc2VJbnQocHVibGljX2V4cG9uZW50LCAxNik7XG5cbiAgICAgIHZhciBwcml2YXRlX2V4cG9uZW50ID0gYXNuMS5zdWJbM10uZ2V0SGV4U3RyaW5nVmFsdWUoKTsgLy9iaWdpbnRcbiAgICAgIHRoaXMuZCA9IHBhcnNlQmlnSW50KHByaXZhdGVfZXhwb25lbnQsIDE2KTtcblxuICAgICAgdmFyIHByaW1lMSA9IGFzbjEuc3ViWzRdLmdldEhleFN0cmluZ1ZhbHVlKCk7IC8vYmlnaW50XG4gICAgICB0aGlzLnAgPSBwYXJzZUJpZ0ludChwcmltZTEsIDE2KTtcblxuICAgICAgdmFyIHByaW1lMiA9IGFzbjEuc3ViWzVdLmdldEhleFN0cmluZ1ZhbHVlKCk7IC8vYmlnaW50XG4gICAgICB0aGlzLnEgPSBwYXJzZUJpZ0ludChwcmltZTIsIDE2KTtcblxuICAgICAgdmFyIGV4cG9uZW50MSA9IGFzbjEuc3ViWzZdLmdldEhleFN0cmluZ1ZhbHVlKCk7IC8vYmlnaW50XG4gICAgICB0aGlzLmRtcDEgPSBwYXJzZUJpZ0ludChleHBvbmVudDEsIDE2KTtcblxuICAgICAgdmFyIGV4cG9uZW50MiA9IGFzbjEuc3ViWzddLmdldEhleFN0cmluZ1ZhbHVlKCk7IC8vYmlnaW50XG4gICAgICB0aGlzLmRtcTEgPSBwYXJzZUJpZ0ludChleHBvbmVudDIsIDE2KTtcblxuICAgICAgdmFyIGNvZWZmaWNpZW50ID0gYXNuMS5zdWJbOF0uZ2V0SGV4U3RyaW5nVmFsdWUoKTsgLy9iaWdpbnRcbiAgICAgIHRoaXMuY29lZmYgPSBwYXJzZUJpZ0ludChjb2VmZmljaWVudCwgMTYpO1xuXG4gICAgfVxuICAgIGVsc2UgaWYgKGFzbjEuc3ViLmxlbmd0aCA9PT0gMikge1xuXG4gICAgICAvLyBQYXJzZSB0aGUgcHVibGljIGtleS5cbiAgICAgIHZhciBiaXRfc3RyaW5nID0gYXNuMS5zdWJbMV07XG4gICAgICB2YXIgc2VxdWVuY2UgPSBiaXRfc3RyaW5nLnN1YlswXTtcblxuICAgICAgbW9kdWx1cyA9IHNlcXVlbmNlLnN1YlswXS5nZXRIZXhTdHJpbmdWYWx1ZSgpO1xuICAgICAgdGhpcy5uID0gcGFyc2VCaWdJbnQobW9kdWx1cywgMTYpO1xuICAgICAgcHVibGljX2V4cG9uZW50ID0gc2VxdWVuY2Uuc3ViWzFdLmdldEhleFN0cmluZ1ZhbHVlKCk7XG4gICAgICB0aGlzLmUgPSBwYXJzZUludChwdWJsaWNfZXhwb25lbnQsIDE2KTtcblxuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gICAgcmV0dXJuIHRydWU7XG4gIH1cbiAgY2F0Y2ggKGV4KSB7XG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG59O1xuXG4vKipcbiAqIFRyYW5zbGF0ZSByc2EgcGFyYW1ldGVycyBpbiBhIGhleCBlbmNvZGVkIHN0cmluZyByZXByZXNlbnRpbmcgdGhlIHJzYSBrZXkuXG4gKlxuICogVGhlIHRyYW5zbGF0aW9uIGZvbGxvdyB0aGUgQVNOLjEgbm90YXRpb24gOlxuICogUlNBUHJpdmF0ZUtleSA6Oj0gU0VRVUVOQ0Uge1xuICogICB2ZXJzaW9uICAgICAgICAgICBWZXJzaW9uLFxuICogICBtb2R1bHVzICAgICAgICAgICBJTlRFR0VSLCAgLS0gblxuICogICBwdWJsaWNFeHBvbmVudCAgICBJTlRFR0VSLCAgLS0gZVxuICogICBwcml2YXRlRXhwb25lbnQgICBJTlRFR0VSLCAgLS0gZFxuICogICBwcmltZTEgICAgICAgICAgICBJTlRFR0VSLCAgLS0gcFxuICogICBwcmltZTIgICAgICAgICAgICBJTlRFR0VSLCAgLS0gcVxuICogICBleHBvbmVudDEgICAgICAgICBJTlRFR0VSLCAgLS0gZCBtb2QgKHAxKVxuICogICBleHBvbmVudDIgICAgICAgICBJTlRFR0VSLCAgLS0gZCBtb2QgKHEtMSlcbiAqICAgY29lZmZpY2llbnQgICAgICAgSU5URUdFUiwgIC0tIChpbnZlcnNlIG9mIHEpIG1vZCBwXG4gKiB9XG4gKiBAcmV0dXJucyB7c3RyaW5nfSAgREVSIEVuY29kZWQgU3RyaW5nIHJlcHJlc2VudGluZyB0aGUgcnNhIHByaXZhdGUga2V5XG4gKiBAcHJpdmF0ZVxuICovXG5SU0FLZXkucHJvdG90eXBlLmdldFByaXZhdGVCYXNlS2V5ID0gZnVuY3Rpb24gKCkge1xuICB2YXIgb3B0aW9ucyA9IHtcbiAgICAnYXJyYXknOiBbXG4gICAgICBuZXcgS0pVUi5hc24xLkRFUkludGVnZXIoeydpbnQnOiAwfSksXG4gICAgICBuZXcgS0pVUi5hc24xLkRFUkludGVnZXIoeydiaWdpbnQnOiB0aGlzLm59KSxcbiAgICAgIG5ldyBLSlVSLmFzbjEuREVSSW50ZWdlcih7J2ludCc6IHRoaXMuZX0pLFxuICAgICAgbmV3IEtKVVIuYXNuMS5ERVJJbnRlZ2VyKHsnYmlnaW50JzogdGhpcy5kfSksXG4gICAgICBuZXcgS0pVUi5hc24xLkRFUkludGVnZXIoeydiaWdpbnQnOiB0aGlzLnB9KSxcbiAgICAgIG5ldyBLSlVSLmFzbjEuREVSSW50ZWdlcih7J2JpZ2ludCc6IHRoaXMucX0pLFxuICAgICAgbmV3IEtKVVIuYXNuMS5ERVJJbnRlZ2VyKHsnYmlnaW50JzogdGhpcy5kbXAxfSksXG4gICAgICBuZXcgS0pVUi5hc24xLkRFUkludGVnZXIoeydiaWdpbnQnOiB0aGlzLmRtcTF9KSxcbiAgICAgIG5ldyBLSlVSLmFzbjEuREVSSW50ZWdlcih7J2JpZ2ludCc6IHRoaXMuY29lZmZ9KVxuICAgIF1cbiAgfTtcbiAgdmFyIHNlcSA9IG5ldyBLSlVSLmFzbjEuREVSU2VxdWVuY2Uob3B0aW9ucyk7XG4gIHJldHVybiBzZXEuZ2V0RW5jb2RlZEhleCgpO1xufTtcblxuLyoqXG4gKiBiYXNlNjQgKHBlbSkgZW5jb2RlZCB2ZXJzaW9uIG9mIHRoZSBERVIgZW5jb2RlZCByZXByZXNlbnRhdGlvblxuICogQHJldHVybnMge3N0cmluZ30gcGVtIGVuY29kZWQgcmVwcmVzZW50YXRpb24gd2l0aG91dCBoZWFkZXIgYW5kIGZvb3RlclxuICogQHB1YmxpY1xuICovXG5SU0FLZXkucHJvdG90eXBlLmdldFByaXZhdGVCYXNlS2V5QjY0ID0gZnVuY3Rpb24gKCkge1xuICByZXR1cm4gaGV4MmI2NCh0aGlzLmdldFByaXZhdGVCYXNlS2V5KCkpO1xufTtcblxuLyoqXG4gKiBUcmFuc2xhdGUgcnNhIHBhcmFtZXRlcnMgaW4gYSBoZXggZW5jb2RlZCBzdHJpbmcgcmVwcmVzZW50aW5nIHRoZSByc2EgcHVibGljIGtleS5cbiAqIFRoZSByZXByZXNlbnRhdGlvbiBmb2xsb3cgdGhlIEFTTi4xIG5vdGF0aW9uIDpcbiAqIFB1YmxpY0tleUluZm8gOjo9IFNFUVVFTkNFIHtcbiAqICAgYWxnb3JpdGhtICAgICAgIEFsZ29yaXRobUlkZW50aWZpZXIsXG4gKiAgIFB1YmxpY0tleSAgICAgICBCSVQgU1RSSU5HXG4gKiB9XG4gKiBXaGVyZSBBbGdvcml0aG1JZGVudGlmaWVyIGlzOlxuICogQWxnb3JpdGhtSWRlbnRpZmllciA6Oj0gU0VRVUVOQ0Uge1xuICogICBhbGdvcml0aG0gICAgICAgT0JKRUNUIElERU5USUZJRVIsICAgICB0aGUgT0lEIG9mIHRoZSBlbmMgYWxnb3JpdGhtXG4gKiAgIHBhcmFtZXRlcnMgICAgICBBTlkgREVGSU5FRCBCWSBhbGdvcml0aG0gT1BUSU9OQUwgKE5VTEwgZm9yIFBLQ1MgIzEpXG4gKiB9XG4gKiBhbmQgUHVibGljS2V5IGlzIGEgU0VRVUVOQ0UgZW5jYXBzdWxhdGVkIGluIGEgQklUIFNUUklOR1xuICogUlNBUHVibGljS2V5IDo6PSBTRVFVRU5DRSB7XG4gKiAgIG1vZHVsdXMgICAgICAgICAgIElOVEVHRVIsICAtLSBuXG4gKiAgIHB1YmxpY0V4cG9uZW50ICAgIElOVEVHRVIgICAtLSBlXG4gKiB9XG4gKiBAcmV0dXJucyB7c3RyaW5nfSBERVIgRW5jb2RlZCBTdHJpbmcgcmVwcmVzZW50aW5nIHRoZSByc2EgcHVibGljIGtleVxuICogQHByaXZhdGVcbiAqL1xuUlNBS2V5LnByb3RvdHlwZS5nZXRQdWJsaWNCYXNlS2V5ID0gZnVuY3Rpb24gKCkge1xuICB2YXIgb3B0aW9ucyA9IHtcbiAgICAnYXJyYXknOiBbXG4gICAgICBuZXcgS0pVUi5hc24xLkRFUk9iamVjdElkZW50aWZpZXIoeydvaWQnOiAnMS4yLjg0MC4xMTM1NDkuMS4xLjEnfSksIC8vUlNBIEVuY3J5cHRpb24gcGtjcyAjMSBvaWRcbiAgICAgIG5ldyBLSlVSLmFzbjEuREVSTnVsbCgpXG4gICAgXVxuICB9O1xuICB2YXIgZmlyc3Rfc2VxdWVuY2UgPSBuZXcgS0pVUi5hc24xLkRFUlNlcXVlbmNlKG9wdGlvbnMpO1xuXG4gIG9wdGlvbnMgPSB7XG4gICAgJ2FycmF5JzogW1xuICAgICAgbmV3IEtKVVIuYXNuMS5ERVJJbnRlZ2VyKHsnYmlnaW50JzogdGhpcy5ufSksXG4gICAgICBuZXcgS0pVUi5hc24xLkRFUkludGVnZXIoeydpbnQnOiB0aGlzLmV9KVxuICAgIF1cbiAgfTtcbiAgdmFyIHNlY29uZF9zZXF1ZW5jZSA9IG5ldyBLSlVSLmFzbjEuREVSU2VxdWVuY2Uob3B0aW9ucyk7XG5cbiAgb3B0aW9ucyA9IHtcbiAgICAnaGV4JzogJzAwJyArIHNlY29uZF9zZXF1ZW5jZS5nZXRFbmNvZGVkSGV4KClcbiAgfTtcbiAgdmFyIGJpdF9zdHJpbmcgPSBuZXcgS0pVUi5hc24xLkRFUkJpdFN0cmluZyhvcHRpb25zKTtcblxuICBvcHRpb25zID0ge1xuICAgICdhcnJheSc6IFtcbiAgICAgIGZpcnN0X3NlcXVlbmNlLFxuICAgICAgYml0X3N0cmluZ1xuICAgIF1cbiAgfTtcbiAgdmFyIHNlcSA9IG5ldyBLSlVSLmFzbjEuREVSU2VxdWVuY2Uob3B0aW9ucyk7XG4gIHJldHVybiBzZXEuZ2V0RW5jb2RlZEhleCgpO1xufTtcblxuLyoqXG4gKiBiYXNlNjQgKHBlbSkgZW5jb2RlZCB2ZXJzaW9uIG9mIHRoZSBERVIgZW5jb2RlZCByZXByZXNlbnRhdGlvblxuICogQHJldHVybnMge3N0cmluZ30gcGVtIGVuY29kZWQgcmVwcmVzZW50YXRpb24gd2l0aG91dCBoZWFkZXIgYW5kIGZvb3RlclxuICogQHB1YmxpY1xuICovXG5SU0FLZXkucHJvdG90eXBlLmdldFB1YmxpY0Jhc2VLZXlCNjQgPSBmdW5jdGlvbiAoKSB7XG4gIHJldHVybiBoZXgyYjY0KHRoaXMuZ2V0UHVibGljQmFzZUtleSgpKTtcbn07XG5cbi8qKlxuICogd3JhcCB0aGUgc3RyaW5nIGluIGJsb2NrIG9mIHdpZHRoIGNoYXJzLiBUaGUgZGVmYXVsdCB2YWx1ZSBmb3IgcnNhIGtleXMgaXMgNjRcbiAqIGNoYXJhY3RlcnMuXG4gKiBAcGFyYW0ge3N0cmluZ30gc3RyIHRoZSBwZW0gZW5jb2RlZCBzdHJpbmcgd2l0aG91dCBoZWFkZXIgYW5kIGZvb3RlclxuICogQHBhcmFtIHtOdW1iZXJ9IFt3aWR0aD02NF0gLSB0aGUgbGVuZ3RoIHRoZSBzdHJpbmcgaGFzIHRvIGJlIHdyYXBwZWQgYXRcbiAqIEByZXR1cm5zIHtzdHJpbmd9XG4gKiBAcHJpdmF0ZVxuICovXG5SU0FLZXkucHJvdG90eXBlLndvcmR3cmFwID0gZnVuY3Rpb24gKHN0ciwgd2lkdGgpIHtcbiAgd2lkdGggPSB3aWR0aCB8fCA2NDtcbiAgaWYgKCFzdHIpIHtcbiAgICByZXR1cm4gc3RyO1xuICB9XG4gIHZhciByZWdleCA9ICcoLnsxLCcgKyB3aWR0aCArICd9KSggK3wkXFxuPyl8KC57MSwnICsgd2lkdGggKyAnfSknO1xuICByZXR1cm4gc3RyLm1hdGNoKFJlZ0V4cChyZWdleCwgJ2cnKSkuam9pbignXFxuJyk7XG59O1xuXG4vKipcbiAqIFJldHJpZXZlIHRoZSBwZW0gZW5jb2RlZCBwcml2YXRlIGtleVxuICogQHJldHVybnMge3N0cmluZ30gdGhlIHBlbSBlbmNvZGVkIHByaXZhdGUga2V5IHdpdGggaGVhZGVyL2Zvb3RlclxuICogQHB1YmxpY1xuICovXG5SU0FLZXkucHJvdG90eXBlLmdldFByaXZhdGVLZXkgPSBmdW5jdGlvbiAoKSB7XG4gIHZhciBrZXkgPSBcIi0tLS0tQkVHSU4gUlNBIFBSSVZBVEUgS0VZLS0tLS1cXG5cIjtcbiAga2V5ICs9IHRoaXMud29yZHdyYXAodGhpcy5nZXRQcml2YXRlQmFzZUtleUI2NCgpKSArIFwiXFxuXCI7XG4gIGtleSArPSBcIi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tXCI7XG4gIHJldHVybiBrZXk7XG59O1xuXG4vKipcbiAqIFJldHJpZXZlIHRoZSBwZW0gZW5jb2RlZCBwdWJsaWMga2V5XG4gKiBAcmV0dXJucyB7c3RyaW5nfSB0aGUgcGVtIGVuY29kZWQgcHVibGljIGtleSB3aXRoIGhlYWRlci9mb290ZXJcbiAqIEBwdWJsaWNcbiAqL1xuUlNBS2V5LnByb3RvdHlwZS5nZXRQdWJsaWNLZXkgPSBmdW5jdGlvbiAoKSB7XG4gIHZhciBrZXkgPSBcIi0tLS0tQkVHSU4gUFVCTElDIEtFWS0tLS0tXFxuXCI7XG4gIGtleSArPSB0aGlzLndvcmR3cmFwKHRoaXMuZ2V0UHVibGljQmFzZUtleUI2NCgpKSArIFwiXFxuXCI7XG4gIGtleSArPSBcIi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLVwiO1xuICByZXR1cm4ga2V5O1xufTtcblxuLyoqXG4gKiBDaGVjayBpZiB0aGUgb2JqZWN0IGNvbnRhaW5zIHRoZSBuZWNlc3NhcnkgcGFyYW1ldGVycyB0byBwb3B1bGF0ZSB0aGUgcnNhIG1vZHVsdXNcbiAqIGFuZCBwdWJsaWMgZXhwb25lbnQgcGFyYW1ldGVycy5cbiAqIEBwYXJhbSB7T2JqZWN0fSBbb2JqPXt9XSAtIEFuIG9iamVjdCB0aGF0IG1heSBjb250YWluIHRoZSB0d28gcHVibGljIGtleVxuICogcGFyYW1ldGVyc1xuICogQHJldHVybnMge2Jvb2xlYW59IHRydWUgaWYgdGhlIG9iamVjdCBjb250YWlucyBib3RoIHRoZSBtb2R1bHVzIGFuZCB0aGUgcHVibGljIGV4cG9uZW50XG4gKiBwcm9wZXJ0aWVzIChuIGFuZCBlKVxuICogQHRvZG8gY2hlY2sgZm9yIHR5cGVzIG9mIG4gYW5kIGUuIE4gc2hvdWxkIGJlIGEgcGFyc2VhYmxlIGJpZ0ludCBvYmplY3QsIEUgc2hvdWxkXG4gKiBiZSBhIHBhcnNlYWJsZSBpbnRlZ2VyIG51bWJlclxuICogQHByaXZhdGVcbiAqL1xuUlNBS2V5LnByb3RvdHlwZS5oYXNQdWJsaWNLZXlQcm9wZXJ0eSA9IGZ1bmN0aW9uIChvYmopIHtcbiAgb2JqID0gb2JqIHx8IHt9O1xuICByZXR1cm4gKFxuICAgIG9iai5oYXNPd25Qcm9wZXJ0eSgnbicpICYmXG4gICAgb2JqLmhhc093blByb3BlcnR5KCdlJylcbiAgKTtcbn07XG5cbi8qKlxuICogQ2hlY2sgaWYgdGhlIG9iamVjdCBjb250YWlucyBBTEwgdGhlIHBhcmFtZXRlcnMgb2YgYW4gUlNBIGtleS5cbiAqIEBwYXJhbSB7T2JqZWN0fSBbb2JqPXt9XSAtIEFuIG9iamVjdCB0aGF0IG1heSBjb250YWluIG5pbmUgcnNhIGtleVxuICogcGFyYW1ldGVyc1xuICogQHJldHVybnMge2Jvb2xlYW59IHRydWUgaWYgdGhlIG9iamVjdCBjb250YWlucyBhbGwgdGhlIHBhcmFtZXRlcnMgbmVlZGVkXG4gKiBAdG9kbyBjaGVjayBmb3IgdHlwZXMgb2YgdGhlIHBhcmFtZXRlcnMgYWxsIHRoZSBwYXJhbWV0ZXJzIGJ1dCB0aGUgcHVibGljIGV4cG9uZW50XG4gKiBzaG91bGQgYmUgcGFyc2VhYmxlIGJpZ2ludCBvYmplY3RzLCB0aGUgcHVibGljIGV4cG9uZW50IHNob3VsZCBiZSBhIHBhcnNlYWJsZSBpbnRlZ2VyIG51bWJlclxuICogQHByaXZhdGVcbiAqL1xuUlNBS2V5LnByb3RvdHlwZS5oYXNQcml2YXRlS2V5UHJvcGVydHkgPSBmdW5jdGlvbiAob2JqKSB7XG4gIG9iaiA9IG9iaiB8fCB7fTtcbiAgcmV0dXJuIChcbiAgICBvYmouaGFzT3duUHJvcGVydHkoJ24nKSAmJlxuICAgIG9iai5oYXNPd25Qcm9wZXJ0eSgnZScpICYmXG4gICAgb2JqLmhhc093blByb3BlcnR5KCdkJykgJiZcbiAgICBvYmouaGFzT3duUHJvcGVydHkoJ3AnKSAmJlxuICAgIG9iai5oYXNPd25Qcm9wZXJ0eSgncScpICYmXG4gICAgb2JqLmhhc093blByb3BlcnR5KCdkbXAxJykgJiZcbiAgICBvYmouaGFzT3duUHJvcGVydHkoJ2RtcTEnKSAmJlxuICAgIG9iai5oYXNPd25Qcm9wZXJ0eSgnY29lZmYnKVxuICApO1xufTtcblxuLyoqXG4gKiBQYXJzZSB0aGUgcHJvcGVydGllcyBvZiBvYmogaW4gdGhlIGN1cnJlbnQgcnNhIG9iamVjdC4gT2JqIHNob3VsZCBBVCBMRUFTVFxuICogaW5jbHVkZSB0aGUgbW9kdWx1cyBhbmQgcHVibGljIGV4cG9uZW50IChuLCBlKSBwYXJhbWV0ZXJzLlxuICogQHBhcmFtIHtPYmplY3R9IG9iaiAtIHRoZSBvYmplY3QgY29udGFpbmluZyByc2EgcGFyYW1ldGVyc1xuICogQHByaXZhdGVcbiAqL1xuUlNBS2V5LnByb3RvdHlwZS5wYXJzZVByb3BlcnRpZXNGcm9tID0gZnVuY3Rpb24gKG9iaikge1xuICB0aGlzLm4gPSBvYmoubjtcbiAgdGhpcy5lID0gb2JqLmU7XG5cbiAgaWYgKG9iai5oYXNPd25Qcm9wZXJ0eSgnZCcpKSB7XG4gICAgdGhpcy5kID0gb2JqLmQ7XG4gICAgdGhpcy5wID0gb2JqLnA7XG4gICAgdGhpcy5xID0gb2JqLnE7XG4gICAgdGhpcy5kbXAxID0gb2JqLmRtcDE7XG4gICAgdGhpcy5kbXExID0gb2JqLmRtcTE7XG4gICAgdGhpcy5jb2VmZiA9IG9iai5jb2VmZjtcbiAgfVxufTtcblxuLyoqXG4gKiBDcmVhdGUgYSBuZXcgSlNFbmNyeXB0UlNBS2V5IHRoYXQgZXh0ZW5kcyBUb20gV3UncyBSU0Ega2V5IG9iamVjdC5cbiAqIFRoaXMgb2JqZWN0IGlzIGp1c3QgYSBkZWNvcmF0b3IgZm9yIHBhcnNpbmcgdGhlIGtleSBwYXJhbWV0ZXJcbiAqIEBwYXJhbSB7c3RyaW5nfE9iamVjdH0ga2V5IC0gVGhlIGtleSBpbiBzdHJpbmcgZm9ybWF0LCBvciBhbiBvYmplY3QgY29udGFpbmluZ1xuICogdGhlIHBhcmFtZXRlcnMgbmVlZGVkIHRvIGJ1aWxkIGEgUlNBS2V5IG9iamVjdC5cbiAqIEBjb25zdHJ1Y3RvclxuICovXG52YXIgSlNFbmNyeXB0UlNBS2V5ID0gZnVuY3Rpb24gKGtleSkge1xuICAvLyBDYWxsIHRoZSBzdXBlciBjb25zdHJ1Y3Rvci5cbiAgUlNBS2V5LmNhbGwodGhpcyk7XG4gIC8vIElmIGEga2V5IGtleSB3YXMgcHJvdmlkZWQuXG4gIGlmIChrZXkpIHtcbiAgICAvLyBJZiB0aGlzIGlzIGEgc3RyaW5nLi4uXG4gICAgaWYgKHR5cGVvZiBrZXkgPT09ICdzdHJpbmcnKSB7XG4gICAgICB0aGlzLnBhcnNlS2V5KGtleSk7XG4gICAgfVxuICAgIGVsc2UgaWYgKFxuICAgICAgdGhpcy5oYXNQcml2YXRlS2V5UHJvcGVydHkoa2V5KSB8fFxuICAgICAgdGhpcy5oYXNQdWJsaWNLZXlQcm9wZXJ0eShrZXkpXG4gICAgKSB7XG4gICAgICAvLyBTZXQgdGhlIHZhbHVlcyBmb3IgdGhlIGtleS5cbiAgICAgIHRoaXMucGFyc2VQcm9wZXJ0aWVzRnJvbShrZXkpO1xuICAgIH1cbiAgfVxufTtcblxuLy8gRGVyaXZlIGZyb20gUlNBS2V5LlxuSlNFbmNyeXB0UlNBS2V5LnByb3RvdHlwZSA9IG5ldyBSU0FLZXkoKTtcblxuLy8gUmVzZXQgdGhlIGNvbnRydWN0b3IuXG5KU0VuY3J5cHRSU0FLZXkucHJvdG90eXBlLmNvbnN0cnVjdG9yID0gSlNFbmNyeXB0UlNBS2V5O1xuXG5cbi8qKlxuICpcbiAqIEBwYXJhbSB7T2JqZWN0fSBbb3B0aW9ucyA9IHt9XSAtIEFuIG9iamVjdCB0byBjdXN0b21pemUgSlNFbmNyeXB0IGJlaGF2aW91clxuICogcG9zc2libGUgcGFyYW1ldGVycyBhcmU6XG4gKiAtIGRlZmF1bHRfa2V5X3NpemUgICAgICAgIHtudW1iZXJ9ICBkZWZhdWx0OiAxMDI0IHRoZSBrZXkgc2l6ZSBpbiBiaXRcbiAqIC0gZGVmYXVsdF9wdWJsaWNfZXhwb25lbnQge3N0cmluZ30gIGRlZmF1bHQ6ICcwMTAwMDEnIHRoZSBoZXhhZGVjaW1hbCByZXByZXNlbnRhdGlvbiBvZiB0aGUgcHVibGljIGV4cG9uZW50XG4gKiAtIGxvZyAgICAgICAgICAgICAgICAgICAgIHtib29sZWFufSBkZWZhdWx0OiBmYWxzZSB3aGV0aGVyIGxvZyB3YXJuL2Vycm9yIG9yIG5vdFxuICogQGNvbnN0cnVjdG9yXG4gKi9cbnZhciBKU0VuY3J5cHQgPSBmdW5jdGlvbiAob3B0aW9ucykge1xuICBvcHRpb25zID0gb3B0aW9ucyB8fCB7fTtcbiAgdGhpcy5kZWZhdWx0X2tleV9zaXplID0gcGFyc2VJbnQob3B0aW9ucy5kZWZhdWx0X2tleV9zaXplKSB8fCAxMDI0O1xuICB0aGlzLmRlZmF1bHRfcHVibGljX2V4cG9uZW50ID0gb3B0aW9ucy5kZWZhdWx0X3B1YmxpY19leHBvbmVudCB8fCAnMDEwMDAxJzsgLy82NTUzNyBkZWZhdWx0IG9wZW5zc2wgcHVibGljIGV4cG9uZW50IGZvciByc2Ega2V5IHR5cGVcbiAgdGhpcy5sb2cgPSBvcHRpb25zLmxvZyB8fCBmYWxzZTtcbiAgLy8gVGhlIHByaXZhdGUgYW5kIHB1YmxpYyBrZXkuXG4gIHRoaXMua2V5ID0gbnVsbDtcbn07XG5cbi8qKlxuICogTWV0aG9kIHRvIHNldCB0aGUgcnNhIGtleSBwYXJhbWV0ZXIgKG9uZSBtZXRob2QgaXMgZW5vdWdoIHRvIHNldCBib3RoIHRoZSBwdWJsaWNcbiAqIGFuZCB0aGUgcHJpdmF0ZSBrZXksIHNpbmNlIHRoZSBwcml2YXRlIGtleSBjb250YWlucyB0aGUgcHVibGljIGtleSBwYXJhbWVudGVycylcbiAqIExvZyBhIHdhcm5pbmcgaWYgbG9ncyBhcmUgZW5hYmxlZFxuICogQHBhcmFtIHtPYmplY3R8c3RyaW5nfSBrZXkgdGhlIHBlbSBlbmNvZGVkIHN0cmluZyBvciBhbiBvYmplY3QgKHdpdGggb3Igd2l0aG91dCBoZWFkZXIvZm9vdGVyKVxuICogQHB1YmxpY1xuICovXG5KU0VuY3J5cHQucHJvdG90eXBlLnNldEtleSA9IGZ1bmN0aW9uIChrZXkpIHtcbiAgaWYgKHRoaXMubG9nICYmIHRoaXMua2V5KSB7XG4gICAgY29uc29sZS53YXJuKCdBIGtleSB3YXMgYWxyZWFkeSBzZXQsIG92ZXJyaWRpbmcgZXhpc3RpbmcuJyk7XG4gIH1cbiAgdGhpcy5rZXkgPSBuZXcgSlNFbmNyeXB0UlNBS2V5KGtleSk7XG59O1xuXG4vKipcbiAqIFByb3h5IG1ldGhvZCBmb3Igc2V0S2V5LCBmb3IgYXBpIGNvbXBhdGliaWxpdHlcbiAqIEBzZWUgc2V0S2V5XG4gKiBAcHVibGljXG4gKi9cbkpTRW5jcnlwdC5wcm90b3R5cGUuc2V0UHJpdmF0ZUtleSA9IGZ1bmN0aW9uIChwcml2a2V5KSB7XG4gIC8vIENyZWF0ZSB0aGUga2V5LlxuICB0aGlzLnNldEtleShwcml2a2V5KTtcbn07XG5cbi8qKlxuICogUHJveHkgbWV0aG9kIGZvciBzZXRLZXksIGZvciBhcGkgY29tcGF0aWJpbGl0eVxuICogQHNlZSBzZXRLZXlcbiAqIEBwdWJsaWNcbiAqL1xuSlNFbmNyeXB0LnByb3RvdHlwZS5zZXRQdWJsaWNLZXkgPSBmdW5jdGlvbiAocHVia2V5KSB7XG4gIC8vIFNldHMgdGhlIHB1YmxpYyBrZXkuXG4gIHRoaXMuc2V0S2V5KHB1YmtleSk7XG59O1xuXG4vKipcbiAqIFByb3h5IG1ldGhvZCBmb3IgUlNBS2V5IG9iamVjdCdzIGRlY3J5cHQsIGRlY3J5cHQgdGhlIHN0cmluZyB1c2luZyB0aGUgcHJpdmF0ZVxuICogY29tcG9uZW50cyBvZiB0aGUgcnNhIGtleSBvYmplY3QuIE5vdGUgdGhhdCBpZiB0aGUgb2JqZWN0IHdhcyBub3Qgc2V0IHdpbGwgYmUgY3JlYXRlZFxuICogb24gdGhlIGZseSAoYnkgdGhlIGdldEtleSBtZXRob2QpIHVzaW5nIHRoZSBwYXJhbWV0ZXJzIHBhc3NlZCBpbiB0aGUgSlNFbmNyeXB0IGNvbnN0cnVjdG9yXG4gKiBAcGFyYW0ge3N0cmluZ30gc3RyaW5nIGJhc2U2NCBlbmNvZGVkIGNyeXB0ZWQgc3RyaW5nIHRvIGRlY3J5cHRcbiAqIEByZXR1cm4ge3N0cmluZ30gdGhlIGRlY3J5cHRlZCBzdHJpbmdcbiAqIEBwdWJsaWNcbiAqL1xuSlNFbmNyeXB0LnByb3RvdHlwZS5kZWNyeXB0ID0gZnVuY3Rpb24gKHN0cmluZykge1xuICAvLyBSZXR1cm4gdGhlIGRlY3J5cHRlZCBzdHJpbmcuXG4gIHRyeSB7XG4gICAgcmV0dXJuIHRoaXMuZ2V0S2V5KCkuZGVjcnlwdChiNjR0b2hleChzdHJpbmcpKTtcbiAgfVxuICBjYXRjaCAoZXgpIHtcbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cbn07XG5cbi8qKlxuICogUHJveHkgbWV0aG9kIGZvciBSU0FLZXkgb2JqZWN0J3MgZW5jcnlwdCwgZW5jcnlwdCB0aGUgc3RyaW5nIHVzaW5nIHRoZSBwdWJsaWNcbiAqIGNvbXBvbmVudHMgb2YgdGhlIHJzYSBrZXkgb2JqZWN0LiBOb3RlIHRoYXQgaWYgdGhlIG9iamVjdCB3YXMgbm90IHNldCB3aWxsIGJlIGNyZWF0ZWRcbiAqIG9uIHRoZSBmbHkgKGJ5IHRoZSBnZXRLZXkgbWV0aG9kKSB1c2luZyB0aGUgcGFyYW1ldGVycyBwYXNzZWQgaW4gdGhlIEpTRW5jcnlwdCBjb25zdHJ1Y3RvclxuICogQHBhcmFtIHtzdHJpbmd9IHN0cmluZyB0aGUgc3RyaW5nIHRvIGVuY3J5cHRcbiAqIEByZXR1cm4ge3N0cmluZ30gdGhlIGVuY3J5cHRlZCBzdHJpbmcgZW5jb2RlZCBpbiBiYXNlNjRcbiAqIEBwdWJsaWNcbiAqL1xuSlNFbmNyeXB0LnByb3RvdHlwZS5lbmNyeXB0ID0gZnVuY3Rpb24gKHN0cmluZykge1xuICAvLyBSZXR1cm4gdGhlIGVuY3J5cHRlZCBzdHJpbmcuXG4gIHRyeSB7XG4gICAgcmV0dXJuIGhleDJiNjQodGhpcy5nZXRLZXkoKS5lbmNyeXB0KHN0cmluZykpO1xuICB9XG4gIGNhdGNoIChleCkge1xuICAgIHJldHVybiBmYWxzZTtcbiAgfVxufTtcblxuLyoqXG4gKiBHZXR0ZXIgZm9yIHRoZSBjdXJyZW50IEpTRW5jcnlwdFJTQUtleSBvYmplY3QuIElmIGl0IGRvZXNuJ3QgZXhpc3RzIGEgbmV3IG9iamVjdFxuICogd2lsbCBiZSBjcmVhdGVkIGFuZCByZXR1cm5lZFxuICogQHBhcmFtIHtjYWxsYmFja30gW2NiXSB0aGUgY2FsbGJhY2sgdG8gYmUgY2FsbGVkIGlmIHdlIHdhbnQgdGhlIGtleSB0byBiZSBnZW5lcmF0ZWRcbiAqIGluIGFuIGFzeW5jIGZhc2hpb25cbiAqIEByZXR1cm5zIHtKU0VuY3J5cHRSU0FLZXl9IHRoZSBKU0VuY3J5cHRSU0FLZXkgb2JqZWN0XG4gKiBAcHVibGljXG4gKi9cbkpTRW5jcnlwdC5wcm90b3R5cGUuZ2V0S2V5ID0gZnVuY3Rpb24gKGNiKSB7XG4gIC8vIE9ubHkgY3JlYXRlIG5ldyBpZiBpdCBkb2VzIG5vdCBleGlzdC5cbiAgaWYgKCF0aGlzLmtleSkge1xuICAgIC8vIEdldCBhIG5ldyBwcml2YXRlIGtleS5cbiAgICB0aGlzLmtleSA9IG5ldyBKU0VuY3J5cHRSU0FLZXkoKTtcbiAgICBpZiAoY2IgJiYge30udG9TdHJpbmcuY2FsbChjYikgPT09ICdbb2JqZWN0IEZ1bmN0aW9uXScpIHtcbiAgICAgIHRoaXMua2V5LmdlbmVyYXRlQXN5bmModGhpcy5kZWZhdWx0X2tleV9zaXplLCB0aGlzLmRlZmF1bHRfcHVibGljX2V4cG9uZW50LCBjYik7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIC8vIEdlbmVyYXRlIHRoZSBrZXkuXG4gICAgdGhpcy5rZXkuZ2VuZXJhdGUodGhpcy5kZWZhdWx0X2tleV9zaXplLCB0aGlzLmRlZmF1bHRfcHVibGljX2V4cG9uZW50KTtcbiAgfVxuICByZXR1cm4gdGhpcy5rZXk7XG59O1xuXG4vKipcbiAqIFJldHVybnMgdGhlIHBlbSBlbmNvZGVkIHJlcHJlc2VudGF0aW9uIG9mIHRoZSBwcml2YXRlIGtleVxuICogSWYgdGhlIGtleSBkb2Vzbid0IGV4aXN0cyBhIG5ldyBrZXkgd2lsbCBiZSBjcmVhdGVkXG4gKiBAcmV0dXJucyB7c3RyaW5nfSBwZW0gZW5jb2RlZCByZXByZXNlbnRhdGlvbiBvZiB0aGUgcHJpdmF0ZSBrZXkgV0lUSCBoZWFkZXIgYW5kIGZvb3RlclxuICogQHB1YmxpY1xuICovXG5KU0VuY3J5cHQucHJvdG90eXBlLmdldFByaXZhdGVLZXkgPSBmdW5jdGlvbiAoKSB7XG4gIC8vIFJldHVybiB0aGUgcHJpdmF0ZSByZXByZXNlbnRhdGlvbiBvZiB0aGlzIGtleS5cbiAgcmV0dXJuIHRoaXMuZ2V0S2V5KCkuZ2V0UHJpdmF0ZUtleSgpO1xufTtcblxuLyoqXG4gKiBSZXR1cm5zIHRoZSBwZW0gZW5jb2RlZCByZXByZXNlbnRhdGlvbiBvZiB0aGUgcHJpdmF0ZSBrZXlcbiAqIElmIHRoZSBrZXkgZG9lc24ndCBleGlzdHMgYSBuZXcga2V5IHdpbGwgYmUgY3JlYXRlZFxuICogQHJldHVybnMge3N0cmluZ30gcGVtIGVuY29kZWQgcmVwcmVzZW50YXRpb24gb2YgdGhlIHByaXZhdGUga2V5IFdJVEhPVVQgaGVhZGVyIGFuZCBmb290ZXJcbiAqIEBwdWJsaWNcbiAqL1xuSlNFbmNyeXB0LnByb3RvdHlwZS5nZXRQcml2YXRlS2V5QjY0ID0gZnVuY3Rpb24gKCkge1xuICAvLyBSZXR1cm4gdGhlIHByaXZhdGUgcmVwcmVzZW50YXRpb24gb2YgdGhpcyBrZXkuXG4gIHJldHVybiB0aGlzLmdldEtleSgpLmdldFByaXZhdGVCYXNlS2V5QjY0KCk7XG59O1xuXG5cbi8qKlxuICogUmV0dXJucyB0aGUgcGVtIGVuY29kZWQgcmVwcmVzZW50YXRpb24gb2YgdGhlIHB1YmxpYyBrZXlcbiAqIElmIHRoZSBrZXkgZG9lc24ndCBleGlzdHMgYSBuZXcga2V5IHdpbGwgYmUgY3JlYXRlZFxuICogQHJldHVybnMge3N0cmluZ30gcGVtIGVuY29kZWQgcmVwcmVzZW50YXRpb24gb2YgdGhlIHB1YmxpYyBrZXkgV0lUSCBoZWFkZXIgYW5kIGZvb3RlclxuICogQHB1YmxpY1xuICovXG5KU0VuY3J5cHQucHJvdG90eXBlLmdldFB1YmxpY0tleSA9IGZ1bmN0aW9uICgpIHtcbiAgLy8gUmV0dXJuIHRoZSBwcml2YXRlIHJlcHJlc2VudGF0aW9uIG9mIHRoaXMga2V5LlxuICByZXR1cm4gdGhpcy5nZXRLZXkoKS5nZXRQdWJsaWNLZXkoKTtcbn07XG5cbi8qKlxuICogUmV0dXJucyB0aGUgcGVtIGVuY29kZWQgcmVwcmVzZW50YXRpb24gb2YgdGhlIHB1YmxpYyBrZXlcbiAqIElmIHRoZSBrZXkgZG9lc24ndCBleGlzdHMgYSBuZXcga2V5IHdpbGwgYmUgY3JlYXRlZFxuICogQHJldHVybnMge3N0cmluZ30gcGVtIGVuY29kZWQgcmVwcmVzZW50YXRpb24gb2YgdGhlIHB1YmxpYyBrZXkgV0lUSE9VVCBoZWFkZXIgYW5kIGZvb3RlclxuICogQHB1YmxpY1xuICovXG5KU0VuY3J5cHQucHJvdG90eXBlLmdldFB1YmxpY0tleUI2NCA9IGZ1bmN0aW9uICgpIHtcbiAgLy8gUmV0dXJuIHRoZSBwcml2YXRlIHJlcHJlc2VudGF0aW9uIG9mIHRoaXMga2V5LlxuICByZXR1cm4gdGhpcy5nZXRLZXkoKS5nZXRQdWJsaWNCYXNlS2V5QjY0KCk7XG59O1xuXG5cbiAgSlNFbmNyeXB0LnZlcnNpb24gPSAnMi4zLjEnO1xuICBleHBvcnRzLkpTRW5jcnlwdCA9IEpTRW5jcnlwdDtcbn0pOyJdfQ==
