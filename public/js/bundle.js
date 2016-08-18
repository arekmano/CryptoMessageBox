(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
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
},{}],2:[function(require,module,exports){
/*jshint multistr: true */

module.exports = {
  public_key: "-----BEGIN PUBLIC KEY-----\
              MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuj9SZS3++QeQWdueiU2J\
              w4qf9BMTYHNyKY0pbNBQYl7ScpUc6QGWDpyAPPfwHaQ+nxtefFfhZfgJWlzZ7E0G\
              JvYeORCHv0P88OcXI1B/7/WsU6y6j/zb2zm/B6qiyJls6zla6WfdfBS0exIDmcxj\
              xcFYf9n9JyfL5oDakf5CD442LBENp7wBHxYYbbi9S3tNiQLcqrWvbCd64n02kgnM\
              HTiFv5ww5mTPE15GBPRP4m1Cf4F0PbuLSO6pHro2rgaIlWieDDw6fDAjJ6FsAPIR\
              ZhKcwUDO/I8D3gk0DTI3Bo4iG7/hAI+0lMDOPjpaHyuU4gkf7tdW3oRukQF+342q\
              9QIDAQAB\
              -----END PUBLIC KEY-----"
}

},{}],3:[function(require,module,exports){
/*jshint multistr: true */
JSEncrypt = require('jsencrypt').JSEncrypt;
Constants = require('../constants');

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

},{"../constants":2,"jsencrypt":1}]},{},[3])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJub2RlX21vZHVsZXMvanNlbmNyeXB0L2Jpbi9qc2VuY3J5cHQuanMiLCJwdWJsaWMvY29uc3RhbnRzLmpzIiwicHVibGljL2pzL2FwcGxpY2F0aW9uLmpzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBO0FDQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDOXZJQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ2JBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBIiwiZmlsZSI6ImdlbmVyYXRlZC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzQ29udGVudCI6WyIoZnVuY3Rpb24gZSh0LG4scil7ZnVuY3Rpb24gcyhvLHUpe2lmKCFuW29dKXtpZighdFtvXSl7dmFyIGE9dHlwZW9mIHJlcXVpcmU9PVwiZnVuY3Rpb25cIiYmcmVxdWlyZTtpZighdSYmYSlyZXR1cm4gYShvLCEwKTtpZihpKXJldHVybiBpKG8sITApO3ZhciBmPW5ldyBFcnJvcihcIkNhbm5vdCBmaW5kIG1vZHVsZSAnXCIrbytcIidcIik7dGhyb3cgZi5jb2RlPVwiTU9EVUxFX05PVF9GT1VORFwiLGZ9dmFyIGw9bltvXT17ZXhwb3J0czp7fX07dFtvXVswXS5jYWxsKGwuZXhwb3J0cyxmdW5jdGlvbihlKXt2YXIgbj10W29dWzFdW2VdO3JldHVybiBzKG4/bjplKX0sbCxsLmV4cG9ydHMsZSx0LG4scil9cmV0dXJuIG5bb10uZXhwb3J0c312YXIgaT10eXBlb2YgcmVxdWlyZT09XCJmdW5jdGlvblwiJiZyZXF1aXJlO2Zvcih2YXIgbz0wO288ci5sZW5ndGg7bysrKXMocltvXSk7cmV0dXJuIHN9KSIsIi8qISBKU0VuY3J5cHQgdjIuMy4xIHwgaHR0cHM6Ly9ucG1jZG4uY29tL2pzZW5jcnlwdEAyLjMuMS9MSUNFTlNFLnR4dCAqL1xuKGZ1bmN0aW9uIChyb290LCBmYWN0b3J5KSB7XG4gIGlmICh0eXBlb2YgZGVmaW5lID09PSAnZnVuY3Rpb24nICYmIGRlZmluZS5hbWQpIHtcbiAgICAvLyBBTURcbiAgICBkZWZpbmUoWydleHBvcnRzJ10sIGZhY3RvcnkpO1xuICB9IGVsc2UgaWYgKHR5cGVvZiBleHBvcnRzID09PSAnb2JqZWN0JyAmJiB0eXBlb2YgZXhwb3J0cy5ub2RlTmFtZSAhPT0gJ3N0cmluZycpIHtcbiAgICAvLyBOb2RlLCBDb21tb25KUy1saWtlXG4gICAgZmFjdG9yeShtb2R1bGUuZXhwb3J0cyk7XG4gIH0gZWxzZSB7XG4gICAgZmFjdG9yeShyb290KTtcbiAgfVxufSkodGhpcywgZnVuY3Rpb24gKGV4cG9ydHMpIHtcbiAgLy8gQ29weXJpZ2h0IChjKSAyMDA1ICBUb20gV3Vcbi8vIEFsbCBSaWdodHMgUmVzZXJ2ZWQuXG4vLyBTZWUgXCJMSUNFTlNFXCIgZm9yIGRldGFpbHMuXG5cbi8vIEJhc2ljIEphdmFTY3JpcHQgQk4gbGlicmFyeSAtIHN1YnNldCB1c2VmdWwgZm9yIFJTQSBlbmNyeXB0aW9uLlxuXG4vLyBCaXRzIHBlciBkaWdpdFxudmFyIGRiaXRzO1xuXG4vLyBKYXZhU2NyaXB0IGVuZ2luZSBhbmFseXNpc1xudmFyIGNhbmFyeSA9IDB4ZGVhZGJlZWZjYWZlO1xudmFyIGpfbG0gPSAoKGNhbmFyeSYweGZmZmZmZik9PTB4ZWZjYWZlKTtcblxuLy8gKHB1YmxpYykgQ29uc3RydWN0b3JcbmZ1bmN0aW9uIEJpZ0ludGVnZXIoYSxiLGMpIHtcbiAgaWYoYSAhPSBudWxsKVxuICAgIGlmKFwibnVtYmVyXCIgPT0gdHlwZW9mIGEpIHRoaXMuZnJvbU51bWJlcihhLGIsYyk7XG4gICAgZWxzZSBpZihiID09IG51bGwgJiYgXCJzdHJpbmdcIiAhPSB0eXBlb2YgYSkgdGhpcy5mcm9tU3RyaW5nKGEsMjU2KTtcbiAgICBlbHNlIHRoaXMuZnJvbVN0cmluZyhhLGIpO1xufVxuXG4vLyByZXR1cm4gbmV3LCB1bnNldCBCaWdJbnRlZ2VyXG5mdW5jdGlvbiBuYmkoKSB7IHJldHVybiBuZXcgQmlnSW50ZWdlcihudWxsKTsgfVxuXG4vLyBhbTogQ29tcHV0ZSB3X2ogKz0gKHgqdGhpc19pKSwgcHJvcGFnYXRlIGNhcnJpZXMsXG4vLyBjIGlzIGluaXRpYWwgY2FycnksIHJldHVybnMgZmluYWwgY2FycnkuXG4vLyBjIDwgMypkdmFsdWUsIHggPCAyKmR2YWx1ZSwgdGhpc19pIDwgZHZhbHVlXG4vLyBXZSBuZWVkIHRvIHNlbGVjdCB0aGUgZmFzdGVzdCBvbmUgdGhhdCB3b3JrcyBpbiB0aGlzIGVudmlyb25tZW50LlxuXG4vLyBhbTE6IHVzZSBhIHNpbmdsZSBtdWx0IGFuZCBkaXZpZGUgdG8gZ2V0IHRoZSBoaWdoIGJpdHMsXG4vLyBtYXggZGlnaXQgYml0cyBzaG91bGQgYmUgMjYgYmVjYXVzZVxuLy8gbWF4IGludGVybmFsIHZhbHVlID0gMipkdmFsdWVeMi0yKmR2YWx1ZSAoPCAyXjUzKVxuZnVuY3Rpb24gYW0xKGkseCx3LGosYyxuKSB7XG4gIHdoaWxlKC0tbiA+PSAwKSB7XG4gICAgdmFyIHYgPSB4KnRoaXNbaSsrXSt3W2pdK2M7XG4gICAgYyA9IE1hdGguZmxvb3Iodi8weDQwMDAwMDApO1xuICAgIHdbaisrXSA9IHYmMHgzZmZmZmZmO1xuICB9XG4gIHJldHVybiBjO1xufVxuLy8gYW0yIGF2b2lkcyBhIGJpZyBtdWx0LWFuZC1leHRyYWN0IGNvbXBsZXRlbHkuXG4vLyBNYXggZGlnaXQgYml0cyBzaG91bGQgYmUgPD0gMzAgYmVjYXVzZSB3ZSBkbyBiaXR3aXNlIG9wc1xuLy8gb24gdmFsdWVzIHVwIHRvIDIqaGR2YWx1ZV4yLWhkdmFsdWUtMSAoPCAyXjMxKVxuZnVuY3Rpb24gYW0yKGkseCx3LGosYyxuKSB7XG4gIHZhciB4bCA9IHgmMHg3ZmZmLCB4aCA9IHg+PjE1O1xuICB3aGlsZSgtLW4gPj0gMCkge1xuICAgIHZhciBsID0gdGhpc1tpXSYweDdmZmY7XG4gICAgdmFyIGggPSB0aGlzW2krK10+PjE1O1xuICAgIHZhciBtID0geGgqbCtoKnhsO1xuICAgIGwgPSB4bCpsKygobSYweDdmZmYpPDwxNSkrd1tqXSsoYyYweDNmZmZmZmZmKTtcbiAgICBjID0gKGw+Pj4zMCkrKG0+Pj4xNSkreGgqaCsoYz4+PjMwKTtcbiAgICB3W2orK10gPSBsJjB4M2ZmZmZmZmY7XG4gIH1cbiAgcmV0dXJuIGM7XG59XG4vLyBBbHRlcm5hdGVseSwgc2V0IG1heCBkaWdpdCBiaXRzIHRvIDI4IHNpbmNlIHNvbWVcbi8vIGJyb3dzZXJzIHNsb3cgZG93biB3aGVuIGRlYWxpbmcgd2l0aCAzMi1iaXQgbnVtYmVycy5cbmZ1bmN0aW9uIGFtMyhpLHgsdyxqLGMsbikge1xuICB2YXIgeGwgPSB4JjB4M2ZmZiwgeGggPSB4Pj4xNDtcbiAgd2hpbGUoLS1uID49IDApIHtcbiAgICB2YXIgbCA9IHRoaXNbaV0mMHgzZmZmO1xuICAgIHZhciBoID0gdGhpc1tpKytdPj4xNDtcbiAgICB2YXIgbSA9IHhoKmwraCp4bDtcbiAgICBsID0geGwqbCsoKG0mMHgzZmZmKTw8MTQpK3dbal0rYztcbiAgICBjID0gKGw+PjI4KSsobT4+MTQpK3hoKmg7XG4gICAgd1tqKytdID0gbCYweGZmZmZmZmY7XG4gIH1cbiAgcmV0dXJuIGM7XG59XG5pZihqX2xtICYmIChuYXZpZ2F0b3IuYXBwTmFtZSA9PSBcIk1pY3Jvc29mdCBJbnRlcm5ldCBFeHBsb3JlclwiKSkge1xuICBCaWdJbnRlZ2VyLnByb3RvdHlwZS5hbSA9IGFtMjtcbiAgZGJpdHMgPSAzMDtcbn1cbmVsc2UgaWYoal9sbSAmJiAobmF2aWdhdG9yLmFwcE5hbWUgIT0gXCJOZXRzY2FwZVwiKSkge1xuICBCaWdJbnRlZ2VyLnByb3RvdHlwZS5hbSA9IGFtMTtcbiAgZGJpdHMgPSAyNjtcbn1cbmVsc2UgeyAvLyBNb3ppbGxhL05ldHNjYXBlIHNlZW1zIHRvIHByZWZlciBhbTNcbiAgQmlnSW50ZWdlci5wcm90b3R5cGUuYW0gPSBhbTM7XG4gIGRiaXRzID0gMjg7XG59XG5cbkJpZ0ludGVnZXIucHJvdG90eXBlLkRCID0gZGJpdHM7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5ETSA9ICgoMTw8ZGJpdHMpLTEpO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuRFYgPSAoMTw8ZGJpdHMpO1xuXG52YXIgQklfRlAgPSA1MjtcbkJpZ0ludGVnZXIucHJvdG90eXBlLkZWID0gTWF0aC5wb3coMixCSV9GUCk7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5GMSA9IEJJX0ZQLWRiaXRzO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuRjIgPSAyKmRiaXRzLUJJX0ZQO1xuXG4vLyBEaWdpdCBjb252ZXJzaW9uc1xudmFyIEJJX1JNID0gXCIwMTIzNDU2Nzg5YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpcIjtcbnZhciBCSV9SQyA9IG5ldyBBcnJheSgpO1xudmFyIHJyLHZ2O1xucnIgPSBcIjBcIi5jaGFyQ29kZUF0KDApO1xuZm9yKHZ2ID0gMDsgdnYgPD0gOTsgKyt2dikgQklfUkNbcnIrK10gPSB2djtcbnJyID0gXCJhXCIuY2hhckNvZGVBdCgwKTtcbmZvcih2diA9IDEwOyB2diA8IDM2OyArK3Z2KSBCSV9SQ1tycisrXSA9IHZ2O1xucnIgPSBcIkFcIi5jaGFyQ29kZUF0KDApO1xuZm9yKHZ2ID0gMTA7IHZ2IDwgMzY7ICsrdnYpIEJJX1JDW3JyKytdID0gdnY7XG5cbmZ1bmN0aW9uIGludDJjaGFyKG4pIHsgcmV0dXJuIEJJX1JNLmNoYXJBdChuKTsgfVxuZnVuY3Rpb24gaW50QXQocyxpKSB7XG4gIHZhciBjID0gQklfUkNbcy5jaGFyQ29kZUF0KGkpXTtcbiAgcmV0dXJuIChjPT1udWxsKT8tMTpjO1xufVxuXG4vLyAocHJvdGVjdGVkKSBjb3B5IHRoaXMgdG8gclxuZnVuY3Rpb24gYm5wQ29weVRvKHIpIHtcbiAgZm9yKHZhciBpID0gdGhpcy50LTE7IGkgPj0gMDsgLS1pKSByW2ldID0gdGhpc1tpXTtcbiAgci50ID0gdGhpcy50O1xuICByLnMgPSB0aGlzLnM7XG59XG5cbi8vIChwcm90ZWN0ZWQpIHNldCBmcm9tIGludGVnZXIgdmFsdWUgeCwgLURWIDw9IHggPCBEVlxuZnVuY3Rpb24gYm5wRnJvbUludCh4KSB7XG4gIHRoaXMudCA9IDE7XG4gIHRoaXMucyA9ICh4PDApPy0xOjA7XG4gIGlmKHggPiAwKSB0aGlzWzBdID0geDtcbiAgZWxzZSBpZih4IDwgLTEpIHRoaXNbMF0gPSB4K3RoaXMuRFY7XG4gIGVsc2UgdGhpcy50ID0gMDtcbn1cblxuLy8gcmV0dXJuIGJpZ2ludCBpbml0aWFsaXplZCB0byB2YWx1ZVxuZnVuY3Rpb24gbmJ2KGkpIHsgdmFyIHIgPSBuYmkoKTsgci5mcm9tSW50KGkpOyByZXR1cm4gcjsgfVxuXG4vLyAocHJvdGVjdGVkKSBzZXQgZnJvbSBzdHJpbmcgYW5kIHJhZGl4XG5mdW5jdGlvbiBibnBGcm9tU3RyaW5nKHMsYikge1xuICB2YXIgaztcbiAgaWYoYiA9PSAxNikgayA9IDQ7XG4gIGVsc2UgaWYoYiA9PSA4KSBrID0gMztcbiAgZWxzZSBpZihiID09IDI1NikgayA9IDg7IC8vIGJ5dGUgYXJyYXlcbiAgZWxzZSBpZihiID09IDIpIGsgPSAxO1xuICBlbHNlIGlmKGIgPT0gMzIpIGsgPSA1O1xuICBlbHNlIGlmKGIgPT0gNCkgayA9IDI7XG4gIGVsc2UgeyB0aGlzLmZyb21SYWRpeChzLGIpOyByZXR1cm47IH1cbiAgdGhpcy50ID0gMDtcbiAgdGhpcy5zID0gMDtcbiAgdmFyIGkgPSBzLmxlbmd0aCwgbWkgPSBmYWxzZSwgc2ggPSAwO1xuICB3aGlsZSgtLWkgPj0gMCkge1xuICAgIHZhciB4ID0gKGs9PTgpP3NbaV0mMHhmZjppbnRBdChzLGkpO1xuICAgIGlmKHggPCAwKSB7XG4gICAgICBpZihzLmNoYXJBdChpKSA9PSBcIi1cIikgbWkgPSB0cnVlO1xuICAgICAgY29udGludWU7XG4gICAgfVxuICAgIG1pID0gZmFsc2U7XG4gICAgaWYoc2ggPT0gMClcbiAgICAgIHRoaXNbdGhpcy50KytdID0geDtcbiAgICBlbHNlIGlmKHNoK2sgPiB0aGlzLkRCKSB7XG4gICAgICB0aGlzW3RoaXMudC0xXSB8PSAoeCYoKDE8PCh0aGlzLkRCLXNoKSktMSkpPDxzaDtcbiAgICAgIHRoaXNbdGhpcy50KytdID0gKHg+Pih0aGlzLkRCLXNoKSk7XG4gICAgfVxuICAgIGVsc2VcbiAgICAgIHRoaXNbdGhpcy50LTFdIHw9IHg8PHNoO1xuICAgIHNoICs9IGs7XG4gICAgaWYoc2ggPj0gdGhpcy5EQikgc2ggLT0gdGhpcy5EQjtcbiAgfVxuICBpZihrID09IDggJiYgKHNbMF0mMHg4MCkgIT0gMCkge1xuICAgIHRoaXMucyA9IC0xO1xuICAgIGlmKHNoID4gMCkgdGhpc1t0aGlzLnQtMV0gfD0gKCgxPDwodGhpcy5EQi1zaCkpLTEpPDxzaDtcbiAgfVxuICB0aGlzLmNsYW1wKCk7XG4gIGlmKG1pKSBCaWdJbnRlZ2VyLlpFUk8uc3ViVG8odGhpcyx0aGlzKTtcbn1cblxuLy8gKHByb3RlY3RlZCkgY2xhbXAgb2ZmIGV4Y2VzcyBoaWdoIHdvcmRzXG5mdW5jdGlvbiBibnBDbGFtcCgpIHtcbiAgdmFyIGMgPSB0aGlzLnMmdGhpcy5ETTtcbiAgd2hpbGUodGhpcy50ID4gMCAmJiB0aGlzW3RoaXMudC0xXSA9PSBjKSAtLXRoaXMudDtcbn1cblxuLy8gKHB1YmxpYykgcmV0dXJuIHN0cmluZyByZXByZXNlbnRhdGlvbiBpbiBnaXZlbiByYWRpeFxuZnVuY3Rpb24gYm5Ub1N0cmluZyhiKSB7XG4gIGlmKHRoaXMucyA8IDApIHJldHVybiBcIi1cIit0aGlzLm5lZ2F0ZSgpLnRvU3RyaW5nKGIpO1xuICB2YXIgaztcbiAgaWYoYiA9PSAxNikgayA9IDQ7XG4gIGVsc2UgaWYoYiA9PSA4KSBrID0gMztcbiAgZWxzZSBpZihiID09IDIpIGsgPSAxO1xuICBlbHNlIGlmKGIgPT0gMzIpIGsgPSA1O1xuICBlbHNlIGlmKGIgPT0gNCkgayA9IDI7XG4gIGVsc2UgcmV0dXJuIHRoaXMudG9SYWRpeChiKTtcbiAgdmFyIGttID0gKDE8PGspLTEsIGQsIG0gPSBmYWxzZSwgciA9IFwiXCIsIGkgPSB0aGlzLnQ7XG4gIHZhciBwID0gdGhpcy5EQi0oaSp0aGlzLkRCKSVrO1xuICBpZihpLS0gPiAwKSB7XG4gICAgaWYocCA8IHRoaXMuREIgJiYgKGQgPSB0aGlzW2ldPj5wKSA+IDApIHsgbSA9IHRydWU7IHIgPSBpbnQyY2hhcihkKTsgfVxuICAgIHdoaWxlKGkgPj0gMCkge1xuICAgICAgaWYocCA8IGspIHtcbiAgICAgICAgZCA9ICh0aGlzW2ldJigoMTw8cCktMSkpPDwoay1wKTtcbiAgICAgICAgZCB8PSB0aGlzWy0taV0+PihwKz10aGlzLkRCLWspO1xuICAgICAgfVxuICAgICAgZWxzZSB7XG4gICAgICAgIGQgPSAodGhpc1tpXT4+KHAtPWspKSZrbTtcbiAgICAgICAgaWYocCA8PSAwKSB7IHAgKz0gdGhpcy5EQjsgLS1pOyB9XG4gICAgICB9XG4gICAgICBpZihkID4gMCkgbSA9IHRydWU7XG4gICAgICBpZihtKSByICs9IGludDJjaGFyKGQpO1xuICAgIH1cbiAgfVxuICByZXR1cm4gbT9yOlwiMFwiO1xufVxuXG4vLyAocHVibGljKSAtdGhpc1xuZnVuY3Rpb24gYm5OZWdhdGUoKSB7IHZhciByID0gbmJpKCk7IEJpZ0ludGVnZXIuWkVSTy5zdWJUbyh0aGlzLHIpOyByZXR1cm4gcjsgfVxuXG4vLyAocHVibGljKSB8dGhpc3xcbmZ1bmN0aW9uIGJuQWJzKCkgeyByZXR1cm4gKHRoaXMuczwwKT90aGlzLm5lZ2F0ZSgpOnRoaXM7IH1cblxuLy8gKHB1YmxpYykgcmV0dXJuICsgaWYgdGhpcyA+IGEsIC0gaWYgdGhpcyA8IGEsIDAgaWYgZXF1YWxcbmZ1bmN0aW9uIGJuQ29tcGFyZVRvKGEpIHtcbiAgdmFyIHIgPSB0aGlzLnMtYS5zO1xuICBpZihyICE9IDApIHJldHVybiByO1xuICB2YXIgaSA9IHRoaXMudDtcbiAgciA9IGktYS50O1xuICBpZihyICE9IDApIHJldHVybiAodGhpcy5zPDApPy1yOnI7XG4gIHdoaWxlKC0taSA+PSAwKSBpZigocj10aGlzW2ldLWFbaV0pICE9IDApIHJldHVybiByO1xuICByZXR1cm4gMDtcbn1cblxuLy8gcmV0dXJucyBiaXQgbGVuZ3RoIG9mIHRoZSBpbnRlZ2VyIHhcbmZ1bmN0aW9uIG5iaXRzKHgpIHtcbiAgdmFyIHIgPSAxLCB0O1xuICBpZigodD14Pj4+MTYpICE9IDApIHsgeCA9IHQ7IHIgKz0gMTY7IH1cbiAgaWYoKHQ9eD4+OCkgIT0gMCkgeyB4ID0gdDsgciArPSA4OyB9XG4gIGlmKCh0PXg+PjQpICE9IDApIHsgeCA9IHQ7IHIgKz0gNDsgfVxuICBpZigodD14Pj4yKSAhPSAwKSB7IHggPSB0OyByICs9IDI7IH1cbiAgaWYoKHQ9eD4+MSkgIT0gMCkgeyB4ID0gdDsgciArPSAxOyB9XG4gIHJldHVybiByO1xufVxuXG4vLyAocHVibGljKSByZXR1cm4gdGhlIG51bWJlciBvZiBiaXRzIGluIFwidGhpc1wiXG5mdW5jdGlvbiBibkJpdExlbmd0aCgpIHtcbiAgaWYodGhpcy50IDw9IDApIHJldHVybiAwO1xuICByZXR1cm4gdGhpcy5EQioodGhpcy50LTEpK25iaXRzKHRoaXNbdGhpcy50LTFdXih0aGlzLnMmdGhpcy5ETSkpO1xufVxuXG4vLyAocHJvdGVjdGVkKSByID0gdGhpcyA8PCBuKkRCXG5mdW5jdGlvbiBibnBETFNoaWZ0VG8obixyKSB7XG4gIHZhciBpO1xuICBmb3IoaSA9IHRoaXMudC0xOyBpID49IDA7IC0taSkgcltpK25dID0gdGhpc1tpXTtcbiAgZm9yKGkgPSBuLTE7IGkgPj0gMDsgLS1pKSByW2ldID0gMDtcbiAgci50ID0gdGhpcy50K247XG4gIHIucyA9IHRoaXMucztcbn1cblxuLy8gKHByb3RlY3RlZCkgciA9IHRoaXMgPj4gbipEQlxuZnVuY3Rpb24gYm5wRFJTaGlmdFRvKG4scikge1xuICBmb3IodmFyIGkgPSBuOyBpIDwgdGhpcy50OyArK2kpIHJbaS1uXSA9IHRoaXNbaV07XG4gIHIudCA9IE1hdGgubWF4KHRoaXMudC1uLDApO1xuICByLnMgPSB0aGlzLnM7XG59XG5cbi8vIChwcm90ZWN0ZWQpIHIgPSB0aGlzIDw8IG5cbmZ1bmN0aW9uIGJucExTaGlmdFRvKG4scikge1xuICB2YXIgYnMgPSBuJXRoaXMuREI7XG4gIHZhciBjYnMgPSB0aGlzLkRCLWJzO1xuICB2YXIgYm0gPSAoMTw8Y2JzKS0xO1xuICB2YXIgZHMgPSBNYXRoLmZsb29yKG4vdGhpcy5EQiksIGMgPSAodGhpcy5zPDxicykmdGhpcy5ETSwgaTtcbiAgZm9yKGkgPSB0aGlzLnQtMTsgaSA+PSAwOyAtLWkpIHtcbiAgICByW2krZHMrMV0gPSAodGhpc1tpXT4+Y2JzKXxjO1xuICAgIGMgPSAodGhpc1tpXSZibSk8PGJzO1xuICB9XG4gIGZvcihpID0gZHMtMTsgaSA+PSAwOyAtLWkpIHJbaV0gPSAwO1xuICByW2RzXSA9IGM7XG4gIHIudCA9IHRoaXMudCtkcysxO1xuICByLnMgPSB0aGlzLnM7XG4gIHIuY2xhbXAoKTtcbn1cblxuLy8gKHByb3RlY3RlZCkgciA9IHRoaXMgPj4gblxuZnVuY3Rpb24gYm5wUlNoaWZ0VG8obixyKSB7XG4gIHIucyA9IHRoaXMucztcbiAgdmFyIGRzID0gTWF0aC5mbG9vcihuL3RoaXMuREIpO1xuICBpZihkcyA+PSB0aGlzLnQpIHsgci50ID0gMDsgcmV0dXJuOyB9XG4gIHZhciBicyA9IG4ldGhpcy5EQjtcbiAgdmFyIGNicyA9IHRoaXMuREItYnM7XG4gIHZhciBibSA9ICgxPDxicyktMTtcbiAgclswXSA9IHRoaXNbZHNdPj5icztcbiAgZm9yKHZhciBpID0gZHMrMTsgaSA8IHRoaXMudDsgKytpKSB7XG4gICAgcltpLWRzLTFdIHw9ICh0aGlzW2ldJmJtKTw8Y2JzO1xuICAgIHJbaS1kc10gPSB0aGlzW2ldPj5icztcbiAgfVxuICBpZihicyA+IDApIHJbdGhpcy50LWRzLTFdIHw9ICh0aGlzLnMmYm0pPDxjYnM7XG4gIHIudCA9IHRoaXMudC1kcztcbiAgci5jbGFtcCgpO1xufVxuXG4vLyAocHJvdGVjdGVkKSByID0gdGhpcyAtIGFcbmZ1bmN0aW9uIGJucFN1YlRvKGEscikge1xuICB2YXIgaSA9IDAsIGMgPSAwLCBtID0gTWF0aC5taW4oYS50LHRoaXMudCk7XG4gIHdoaWxlKGkgPCBtKSB7XG4gICAgYyArPSB0aGlzW2ldLWFbaV07XG4gICAgcltpKytdID0gYyZ0aGlzLkRNO1xuICAgIGMgPj49IHRoaXMuREI7XG4gIH1cbiAgaWYoYS50IDwgdGhpcy50KSB7XG4gICAgYyAtPSBhLnM7XG4gICAgd2hpbGUoaSA8IHRoaXMudCkge1xuICAgICAgYyArPSB0aGlzW2ldO1xuICAgICAgcltpKytdID0gYyZ0aGlzLkRNO1xuICAgICAgYyA+Pj0gdGhpcy5EQjtcbiAgICB9XG4gICAgYyArPSB0aGlzLnM7XG4gIH1cbiAgZWxzZSB7XG4gICAgYyArPSB0aGlzLnM7XG4gICAgd2hpbGUoaSA8IGEudCkge1xuICAgICAgYyAtPSBhW2ldO1xuICAgICAgcltpKytdID0gYyZ0aGlzLkRNO1xuICAgICAgYyA+Pj0gdGhpcy5EQjtcbiAgICB9XG4gICAgYyAtPSBhLnM7XG4gIH1cbiAgci5zID0gKGM8MCk/LTE6MDtcbiAgaWYoYyA8IC0xKSByW2krK10gPSB0aGlzLkRWK2M7XG4gIGVsc2UgaWYoYyA+IDApIHJbaSsrXSA9IGM7XG4gIHIudCA9IGk7XG4gIHIuY2xhbXAoKTtcbn1cblxuLy8gKHByb3RlY3RlZCkgciA9IHRoaXMgKiBhLCByICE9IHRoaXMsYSAoSEFDIDE0LjEyKVxuLy8gXCJ0aGlzXCIgc2hvdWxkIGJlIHRoZSBsYXJnZXIgb25lIGlmIGFwcHJvcHJpYXRlLlxuZnVuY3Rpb24gYm5wTXVsdGlwbHlUbyhhLHIpIHtcbiAgdmFyIHggPSB0aGlzLmFicygpLCB5ID0gYS5hYnMoKTtcbiAgdmFyIGkgPSB4LnQ7XG4gIHIudCA9IGkreS50O1xuICB3aGlsZSgtLWkgPj0gMCkgcltpXSA9IDA7XG4gIGZvcihpID0gMDsgaSA8IHkudDsgKytpKSByW2kreC50XSA9IHguYW0oMCx5W2ldLHIsaSwwLHgudCk7XG4gIHIucyA9IDA7XG4gIHIuY2xhbXAoKTtcbiAgaWYodGhpcy5zICE9IGEucykgQmlnSW50ZWdlci5aRVJPLnN1YlRvKHIscik7XG59XG5cbi8vIChwcm90ZWN0ZWQpIHIgPSB0aGlzXjIsIHIgIT0gdGhpcyAoSEFDIDE0LjE2KVxuZnVuY3Rpb24gYm5wU3F1YXJlVG8ocikge1xuICB2YXIgeCA9IHRoaXMuYWJzKCk7XG4gIHZhciBpID0gci50ID0gMip4LnQ7XG4gIHdoaWxlKC0taSA+PSAwKSByW2ldID0gMDtcbiAgZm9yKGkgPSAwOyBpIDwgeC50LTE7ICsraSkge1xuICAgIHZhciBjID0geC5hbShpLHhbaV0sciwyKmksMCwxKTtcbiAgICBpZigocltpK3gudF0rPXguYW0oaSsxLDIqeFtpXSxyLDIqaSsxLGMseC50LWktMSkpID49IHguRFYpIHtcbiAgICAgIHJbaSt4LnRdIC09IHguRFY7XG4gICAgICByW2kreC50KzFdID0gMTtcbiAgICB9XG4gIH1cbiAgaWYoci50ID4gMCkgcltyLnQtMV0gKz0geC5hbShpLHhbaV0sciwyKmksMCwxKTtcbiAgci5zID0gMDtcbiAgci5jbGFtcCgpO1xufVxuXG4vLyAocHJvdGVjdGVkKSBkaXZpZGUgdGhpcyBieSBtLCBxdW90aWVudCBhbmQgcmVtYWluZGVyIHRvIHEsIHIgKEhBQyAxNC4yMClcbi8vIHIgIT0gcSwgdGhpcyAhPSBtLiAgcSBvciByIG1heSBiZSBudWxsLlxuZnVuY3Rpb24gYm5wRGl2UmVtVG8obSxxLHIpIHtcbiAgdmFyIHBtID0gbS5hYnMoKTtcbiAgaWYocG0udCA8PSAwKSByZXR1cm47XG4gIHZhciBwdCA9IHRoaXMuYWJzKCk7XG4gIGlmKHB0LnQgPCBwbS50KSB7XG4gICAgaWYocSAhPSBudWxsKSBxLmZyb21JbnQoMCk7XG4gICAgaWYociAhPSBudWxsKSB0aGlzLmNvcHlUbyhyKTtcbiAgICByZXR1cm47XG4gIH1cbiAgaWYociA9PSBudWxsKSByID0gbmJpKCk7XG4gIHZhciB5ID0gbmJpKCksIHRzID0gdGhpcy5zLCBtcyA9IG0ucztcbiAgdmFyIG5zaCA9IHRoaXMuREItbmJpdHMocG1bcG0udC0xXSk7XHQvLyBub3JtYWxpemUgbW9kdWx1c1xuICBpZihuc2ggPiAwKSB7IHBtLmxTaGlmdFRvKG5zaCx5KTsgcHQubFNoaWZ0VG8obnNoLHIpOyB9XG4gIGVsc2UgeyBwbS5jb3B5VG8oeSk7IHB0LmNvcHlUbyhyKTsgfVxuICB2YXIgeXMgPSB5LnQ7XG4gIHZhciB5MCA9IHlbeXMtMV07XG4gIGlmKHkwID09IDApIHJldHVybjtcbiAgdmFyIHl0ID0geTAqKDE8PHRoaXMuRjEpKygoeXM+MSk/eVt5cy0yXT4+dGhpcy5GMjowKTtcbiAgdmFyIGQxID0gdGhpcy5GVi95dCwgZDIgPSAoMTw8dGhpcy5GMSkveXQsIGUgPSAxPDx0aGlzLkYyO1xuICB2YXIgaSA9IHIudCwgaiA9IGkteXMsIHQgPSAocT09bnVsbCk/bmJpKCk6cTtcbiAgeS5kbFNoaWZ0VG8oaix0KTtcbiAgaWYoci5jb21wYXJlVG8odCkgPj0gMCkge1xuICAgIHJbci50KytdID0gMTtcbiAgICByLnN1YlRvKHQscik7XG4gIH1cbiAgQmlnSW50ZWdlci5PTkUuZGxTaGlmdFRvKHlzLHQpO1xuICB0LnN1YlRvKHkseSk7XHQvLyBcIm5lZ2F0aXZlXCIgeSBzbyB3ZSBjYW4gcmVwbGFjZSBzdWIgd2l0aCBhbSBsYXRlclxuICB3aGlsZSh5LnQgPCB5cykgeVt5LnQrK10gPSAwO1xuICB3aGlsZSgtLWogPj0gMCkge1xuICAgIC8vIEVzdGltYXRlIHF1b3RpZW50IGRpZ2l0XG4gICAgdmFyIHFkID0gKHJbLS1pXT09eTApP3RoaXMuRE06TWF0aC5mbG9vcihyW2ldKmQxKyhyW2ktMV0rZSkqZDIpO1xuICAgIGlmKChyW2ldKz15LmFtKDAscWQscixqLDAseXMpKSA8IHFkKSB7XHQvLyBUcnkgaXQgb3V0XG4gICAgICB5LmRsU2hpZnRUbyhqLHQpO1xuICAgICAgci5zdWJUbyh0LHIpO1xuICAgICAgd2hpbGUocltpXSA8IC0tcWQpIHIuc3ViVG8odCxyKTtcbiAgICB9XG4gIH1cbiAgaWYocSAhPSBudWxsKSB7XG4gICAgci5kclNoaWZ0VG8oeXMscSk7XG4gICAgaWYodHMgIT0gbXMpIEJpZ0ludGVnZXIuWkVSTy5zdWJUbyhxLHEpO1xuICB9XG4gIHIudCA9IHlzO1xuICByLmNsYW1wKCk7XG4gIGlmKG5zaCA+IDApIHIuclNoaWZ0VG8obnNoLHIpO1x0Ly8gRGVub3JtYWxpemUgcmVtYWluZGVyXG4gIGlmKHRzIDwgMCkgQmlnSW50ZWdlci5aRVJPLnN1YlRvKHIscik7XG59XG5cbi8vIChwdWJsaWMpIHRoaXMgbW9kIGFcbmZ1bmN0aW9uIGJuTW9kKGEpIHtcbiAgdmFyIHIgPSBuYmkoKTtcbiAgdGhpcy5hYnMoKS5kaXZSZW1UbyhhLG51bGwscik7XG4gIGlmKHRoaXMucyA8IDAgJiYgci5jb21wYXJlVG8oQmlnSW50ZWdlci5aRVJPKSA+IDApIGEuc3ViVG8ocixyKTtcbiAgcmV0dXJuIHI7XG59XG5cbi8vIE1vZHVsYXIgcmVkdWN0aW9uIHVzaW5nIFwiY2xhc3NpY1wiIGFsZ29yaXRobVxuZnVuY3Rpb24gQ2xhc3NpYyhtKSB7IHRoaXMubSA9IG07IH1cbmZ1bmN0aW9uIGNDb252ZXJ0KHgpIHtcbiAgaWYoeC5zIDwgMCB8fCB4LmNvbXBhcmVUbyh0aGlzLm0pID49IDApIHJldHVybiB4Lm1vZCh0aGlzLm0pO1xuICBlbHNlIHJldHVybiB4O1xufVxuZnVuY3Rpb24gY1JldmVydCh4KSB7IHJldHVybiB4OyB9XG5mdW5jdGlvbiBjUmVkdWNlKHgpIHsgeC5kaXZSZW1Ubyh0aGlzLm0sbnVsbCx4KTsgfVxuZnVuY3Rpb24gY011bFRvKHgseSxyKSB7IHgubXVsdGlwbHlUbyh5LHIpOyB0aGlzLnJlZHVjZShyKTsgfVxuZnVuY3Rpb24gY1NxclRvKHgscikgeyB4LnNxdWFyZVRvKHIpOyB0aGlzLnJlZHVjZShyKTsgfVxuXG5DbGFzc2ljLnByb3RvdHlwZS5jb252ZXJ0ID0gY0NvbnZlcnQ7XG5DbGFzc2ljLnByb3RvdHlwZS5yZXZlcnQgPSBjUmV2ZXJ0O1xuQ2xhc3NpYy5wcm90b3R5cGUucmVkdWNlID0gY1JlZHVjZTtcbkNsYXNzaWMucHJvdG90eXBlLm11bFRvID0gY011bFRvO1xuQ2xhc3NpYy5wcm90b3R5cGUuc3FyVG8gPSBjU3FyVG87XG5cbi8vIChwcm90ZWN0ZWQpIHJldHVybiBcIi0xL3RoaXMgJSAyXkRCXCI7IHVzZWZ1bCBmb3IgTW9udC4gcmVkdWN0aW9uXG4vLyBqdXN0aWZpY2F0aW9uOlxuLy8gICAgICAgICB4eSA9PSAxIChtb2QgbSlcbi8vICAgICAgICAgeHkgPSAgMStrbVxuLy8gICB4eSgyLXh5KSA9ICgxK2ttKSgxLWttKVxuLy8geFt5KDIteHkpXSA9IDEta14ybV4yXG4vLyB4W3koMi14eSldID09IDEgKG1vZCBtXjIpXG4vLyBpZiB5IGlzIDEveCBtb2QgbSwgdGhlbiB5KDIteHkpIGlzIDEveCBtb2QgbV4yXG4vLyBzaG91bGQgcmVkdWNlIHggYW5kIHkoMi14eSkgYnkgbV4yIGF0IGVhY2ggc3RlcCB0byBrZWVwIHNpemUgYm91bmRlZC5cbi8vIEpTIG11bHRpcGx5IFwib3ZlcmZsb3dzXCIgZGlmZmVyZW50bHkgZnJvbSBDL0MrKywgc28gY2FyZSBpcyBuZWVkZWQgaGVyZS5cbmZ1bmN0aW9uIGJucEludkRpZ2l0KCkge1xuICBpZih0aGlzLnQgPCAxKSByZXR1cm4gMDtcbiAgdmFyIHggPSB0aGlzWzBdO1xuICBpZigoeCYxKSA9PSAwKSByZXR1cm4gMDtcbiAgdmFyIHkgPSB4JjM7XHRcdC8vIHkgPT0gMS94IG1vZCAyXjJcbiAgeSA9ICh5KigyLSh4JjB4ZikqeSkpJjB4ZjtcdC8vIHkgPT0gMS94IG1vZCAyXjRcbiAgeSA9ICh5KigyLSh4JjB4ZmYpKnkpKSYweGZmO1x0Ly8geSA9PSAxL3ggbW9kIDJeOFxuICB5ID0gKHkqKDItKCgoeCYweGZmZmYpKnkpJjB4ZmZmZikpKSYweGZmZmY7XHQvLyB5ID09IDEveCBtb2QgMl4xNlxuICAvLyBsYXN0IHN0ZXAgLSBjYWxjdWxhdGUgaW52ZXJzZSBtb2QgRFYgZGlyZWN0bHk7XG4gIC8vIGFzc3VtZXMgMTYgPCBEQiA8PSAzMiBhbmQgYXNzdW1lcyBhYmlsaXR5IHRvIGhhbmRsZSA0OC1iaXQgaW50c1xuICB5ID0gKHkqKDIteCp5JXRoaXMuRFYpKSV0aGlzLkRWO1x0XHQvLyB5ID09IDEveCBtb2QgMl5kYml0c1xuICAvLyB3ZSByZWFsbHkgd2FudCB0aGUgbmVnYXRpdmUgaW52ZXJzZSwgYW5kIC1EViA8IHkgPCBEVlxuICByZXR1cm4gKHk+MCk/dGhpcy5EVi15Oi15O1xufVxuXG4vLyBNb250Z29tZXJ5IHJlZHVjdGlvblxuZnVuY3Rpb24gTW9udGdvbWVyeShtKSB7XG4gIHRoaXMubSA9IG07XG4gIHRoaXMubXAgPSBtLmludkRpZ2l0KCk7XG4gIHRoaXMubXBsID0gdGhpcy5tcCYweDdmZmY7XG4gIHRoaXMubXBoID0gdGhpcy5tcD4+MTU7XG4gIHRoaXMudW0gPSAoMTw8KG0uREItMTUpKS0xO1xuICB0aGlzLm10MiA9IDIqbS50O1xufVxuXG4vLyB4UiBtb2QgbVxuZnVuY3Rpb24gbW9udENvbnZlcnQoeCkge1xuICB2YXIgciA9IG5iaSgpO1xuICB4LmFicygpLmRsU2hpZnRUbyh0aGlzLm0udCxyKTtcbiAgci5kaXZSZW1Ubyh0aGlzLm0sbnVsbCxyKTtcbiAgaWYoeC5zIDwgMCAmJiByLmNvbXBhcmVUbyhCaWdJbnRlZ2VyLlpFUk8pID4gMCkgdGhpcy5tLnN1YlRvKHIscik7XG4gIHJldHVybiByO1xufVxuXG4vLyB4L1IgbW9kIG1cbmZ1bmN0aW9uIG1vbnRSZXZlcnQoeCkge1xuICB2YXIgciA9IG5iaSgpO1xuICB4LmNvcHlUbyhyKTtcbiAgdGhpcy5yZWR1Y2Uocik7XG4gIHJldHVybiByO1xufVxuXG4vLyB4ID0geC9SIG1vZCBtIChIQUMgMTQuMzIpXG5mdW5jdGlvbiBtb250UmVkdWNlKHgpIHtcbiAgd2hpbGUoeC50IDw9IHRoaXMubXQyKVx0Ly8gcGFkIHggc28gYW0gaGFzIGVub3VnaCByb29tIGxhdGVyXG4gICAgeFt4LnQrK10gPSAwO1xuICBmb3IodmFyIGkgPSAwOyBpIDwgdGhpcy5tLnQ7ICsraSkge1xuICAgIC8vIGZhc3RlciB3YXkgb2YgY2FsY3VsYXRpbmcgdTAgPSB4W2ldKm1wIG1vZCBEVlxuICAgIHZhciBqID0geFtpXSYweDdmZmY7XG4gICAgdmFyIHUwID0gKGoqdGhpcy5tcGwrKCgoaip0aGlzLm1waCsoeFtpXT4+MTUpKnRoaXMubXBsKSZ0aGlzLnVtKTw8MTUpKSZ4LkRNO1xuICAgIC8vIHVzZSBhbSB0byBjb21iaW5lIHRoZSBtdWx0aXBseS1zaGlmdC1hZGQgaW50byBvbmUgY2FsbFxuICAgIGogPSBpK3RoaXMubS50O1xuICAgIHhbal0gKz0gdGhpcy5tLmFtKDAsdTAseCxpLDAsdGhpcy5tLnQpO1xuICAgIC8vIHByb3BhZ2F0ZSBjYXJyeVxuICAgIHdoaWxlKHhbal0gPj0geC5EVikgeyB4W2pdIC09IHguRFY7IHhbKytqXSsrOyB9XG4gIH1cbiAgeC5jbGFtcCgpO1xuICB4LmRyU2hpZnRUbyh0aGlzLm0udCx4KTtcbiAgaWYoeC5jb21wYXJlVG8odGhpcy5tKSA+PSAwKSB4LnN1YlRvKHRoaXMubSx4KTtcbn1cblxuLy8gciA9IFwieF4yL1IgbW9kIG1cIjsgeCAhPSByXG5mdW5jdGlvbiBtb250U3FyVG8oeCxyKSB7IHguc3F1YXJlVG8ocik7IHRoaXMucmVkdWNlKHIpOyB9XG5cbi8vIHIgPSBcInh5L1IgbW9kIG1cIjsgeCx5ICE9IHJcbmZ1bmN0aW9uIG1vbnRNdWxUbyh4LHkscikgeyB4Lm11bHRpcGx5VG8oeSxyKTsgdGhpcy5yZWR1Y2Uocik7IH1cblxuTW9udGdvbWVyeS5wcm90b3R5cGUuY29udmVydCA9IG1vbnRDb252ZXJ0O1xuTW9udGdvbWVyeS5wcm90b3R5cGUucmV2ZXJ0ID0gbW9udFJldmVydDtcbk1vbnRnb21lcnkucHJvdG90eXBlLnJlZHVjZSA9IG1vbnRSZWR1Y2U7XG5Nb250Z29tZXJ5LnByb3RvdHlwZS5tdWxUbyA9IG1vbnRNdWxUbztcbk1vbnRnb21lcnkucHJvdG90eXBlLnNxclRvID0gbW9udFNxclRvO1xuXG4vLyAocHJvdGVjdGVkKSB0cnVlIGlmZiB0aGlzIGlzIGV2ZW5cbmZ1bmN0aW9uIGJucElzRXZlbigpIHsgcmV0dXJuICgodGhpcy50PjApPyh0aGlzWzBdJjEpOnRoaXMucykgPT0gMDsgfVxuXG4vLyAocHJvdGVjdGVkKSB0aGlzXmUsIGUgPCAyXjMyLCBkb2luZyBzcXIgYW5kIG11bCB3aXRoIFwiclwiIChIQUMgMTQuNzkpXG5mdW5jdGlvbiBibnBFeHAoZSx6KSB7XG4gIGlmKGUgPiAweGZmZmZmZmZmIHx8IGUgPCAxKSByZXR1cm4gQmlnSW50ZWdlci5PTkU7XG4gIHZhciByID0gbmJpKCksIHIyID0gbmJpKCksIGcgPSB6LmNvbnZlcnQodGhpcyksIGkgPSBuYml0cyhlKS0xO1xuICBnLmNvcHlUbyhyKTtcbiAgd2hpbGUoLS1pID49IDApIHtcbiAgICB6LnNxclRvKHIscjIpO1xuICAgIGlmKChlJigxPDxpKSkgPiAwKSB6Lm11bFRvKHIyLGcscik7XG4gICAgZWxzZSB7IHZhciB0ID0gcjsgciA9IHIyOyByMiA9IHQ7IH1cbiAgfVxuICByZXR1cm4gei5yZXZlcnQocik7XG59XG5cbi8vIChwdWJsaWMpIHRoaXNeZSAlIG0sIDAgPD0gZSA8IDJeMzJcbmZ1bmN0aW9uIGJuTW9kUG93SW50KGUsbSkge1xuICB2YXIgejtcbiAgaWYoZSA8IDI1NiB8fCBtLmlzRXZlbigpKSB6ID0gbmV3IENsYXNzaWMobSk7IGVsc2UgeiA9IG5ldyBNb250Z29tZXJ5KG0pO1xuICByZXR1cm4gdGhpcy5leHAoZSx6KTtcbn1cblxuLy8gcHJvdGVjdGVkXG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5jb3B5VG8gPSBibnBDb3B5VG87XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5mcm9tSW50ID0gYm5wRnJvbUludDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmZyb21TdHJpbmcgPSBibnBGcm9tU3RyaW5nO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuY2xhbXAgPSBibnBDbGFtcDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmRsU2hpZnRUbyA9IGJucERMU2hpZnRUbztcbkJpZ0ludGVnZXIucHJvdG90eXBlLmRyU2hpZnRUbyA9IGJucERSU2hpZnRUbztcbkJpZ0ludGVnZXIucHJvdG90eXBlLmxTaGlmdFRvID0gYm5wTFNoaWZ0VG87XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5yU2hpZnRUbyA9IGJucFJTaGlmdFRvO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuc3ViVG8gPSBibnBTdWJUbztcbkJpZ0ludGVnZXIucHJvdG90eXBlLm11bHRpcGx5VG8gPSBibnBNdWx0aXBseVRvO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuc3F1YXJlVG8gPSBibnBTcXVhcmVUbztcbkJpZ0ludGVnZXIucHJvdG90eXBlLmRpdlJlbVRvID0gYm5wRGl2UmVtVG87XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5pbnZEaWdpdCA9IGJucEludkRpZ2l0O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuaXNFdmVuID0gYm5wSXNFdmVuO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZXhwID0gYm5wRXhwO1xuXG4vLyBwdWJsaWNcbkJpZ0ludGVnZXIucHJvdG90eXBlLnRvU3RyaW5nID0gYm5Ub1N0cmluZztcbkJpZ0ludGVnZXIucHJvdG90eXBlLm5lZ2F0ZSA9IGJuTmVnYXRlO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuYWJzID0gYm5BYnM7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5jb21wYXJlVG8gPSBibkNvbXBhcmVUbztcbkJpZ0ludGVnZXIucHJvdG90eXBlLmJpdExlbmd0aCA9IGJuQml0TGVuZ3RoO1xuQmlnSW50ZWdlci5wcm90b3R5cGUubW9kID0gYm5Nb2Q7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5tb2RQb3dJbnQgPSBibk1vZFBvd0ludDtcblxuLy8gXCJjb25zdGFudHNcIlxuQmlnSW50ZWdlci5aRVJPID0gbmJ2KDApO1xuQmlnSW50ZWdlci5PTkUgPSBuYnYoMSk7XG5cbi8vIENvcHlyaWdodCAoYykgMjAwNS0yMDA5ICBUb20gV3Vcbi8vIEFsbCBSaWdodHMgUmVzZXJ2ZWQuXG4vLyBTZWUgXCJMSUNFTlNFXCIgZm9yIGRldGFpbHMuXG5cbi8vIEV4dGVuZGVkIEphdmFTY3JpcHQgQk4gZnVuY3Rpb25zLCByZXF1aXJlZCBmb3IgUlNBIHByaXZhdGUgb3BzLlxuXG4vLyBWZXJzaW9uIDEuMTogbmV3IEJpZ0ludGVnZXIoXCIwXCIsIDEwKSByZXR1cm5zIFwicHJvcGVyXCIgemVyb1xuLy8gVmVyc2lvbiAxLjI6IHNxdWFyZSgpIEFQSSwgaXNQcm9iYWJsZVByaW1lIGZpeFxuXG4vLyAocHVibGljKVxuZnVuY3Rpb24gYm5DbG9uZSgpIHsgdmFyIHIgPSBuYmkoKTsgdGhpcy5jb3B5VG8ocik7IHJldHVybiByOyB9XG5cbi8vIChwdWJsaWMpIHJldHVybiB2YWx1ZSBhcyBpbnRlZ2VyXG5mdW5jdGlvbiBibkludFZhbHVlKCkge1xuICBpZih0aGlzLnMgPCAwKSB7XG4gICAgaWYodGhpcy50ID09IDEpIHJldHVybiB0aGlzWzBdLXRoaXMuRFY7XG4gICAgZWxzZSBpZih0aGlzLnQgPT0gMCkgcmV0dXJuIC0xO1xuICB9XG4gIGVsc2UgaWYodGhpcy50ID09IDEpIHJldHVybiB0aGlzWzBdO1xuICBlbHNlIGlmKHRoaXMudCA9PSAwKSByZXR1cm4gMDtcbiAgLy8gYXNzdW1lcyAxNiA8IERCIDwgMzJcbiAgcmV0dXJuICgodGhpc1sxXSYoKDE8PCgzMi10aGlzLkRCKSktMSkpPDx0aGlzLkRCKXx0aGlzWzBdO1xufVxuXG4vLyAocHVibGljKSByZXR1cm4gdmFsdWUgYXMgYnl0ZVxuZnVuY3Rpb24gYm5CeXRlVmFsdWUoKSB7IHJldHVybiAodGhpcy50PT0wKT90aGlzLnM6KHRoaXNbMF08PDI0KT4+MjQ7IH1cblxuLy8gKHB1YmxpYykgcmV0dXJuIHZhbHVlIGFzIHNob3J0IChhc3N1bWVzIERCPj0xNilcbmZ1bmN0aW9uIGJuU2hvcnRWYWx1ZSgpIHsgcmV0dXJuICh0aGlzLnQ9PTApP3RoaXMuczoodGhpc1swXTw8MTYpPj4xNjsgfVxuXG4vLyAocHJvdGVjdGVkKSByZXR1cm4geCBzLnQuIHJeeCA8IERWXG5mdW5jdGlvbiBibnBDaHVua1NpemUocikgeyByZXR1cm4gTWF0aC5mbG9vcihNYXRoLkxOMip0aGlzLkRCL01hdGgubG9nKHIpKTsgfVxuXG4vLyAocHVibGljKSAwIGlmIHRoaXMgPT0gMCwgMSBpZiB0aGlzID4gMFxuZnVuY3Rpb24gYm5TaWdOdW0oKSB7XG4gIGlmKHRoaXMucyA8IDApIHJldHVybiAtMTtcbiAgZWxzZSBpZih0aGlzLnQgPD0gMCB8fCAodGhpcy50ID09IDEgJiYgdGhpc1swXSA8PSAwKSkgcmV0dXJuIDA7XG4gIGVsc2UgcmV0dXJuIDE7XG59XG5cbi8vIChwcm90ZWN0ZWQpIGNvbnZlcnQgdG8gcmFkaXggc3RyaW5nXG5mdW5jdGlvbiBibnBUb1JhZGl4KGIpIHtcbiAgaWYoYiA9PSBudWxsKSBiID0gMTA7XG4gIGlmKHRoaXMuc2lnbnVtKCkgPT0gMCB8fCBiIDwgMiB8fCBiID4gMzYpIHJldHVybiBcIjBcIjtcbiAgdmFyIGNzID0gdGhpcy5jaHVua1NpemUoYik7XG4gIHZhciBhID0gTWF0aC5wb3coYixjcyk7XG4gIHZhciBkID0gbmJ2KGEpLCB5ID0gbmJpKCksIHogPSBuYmkoKSwgciA9IFwiXCI7XG4gIHRoaXMuZGl2UmVtVG8oZCx5LHopO1xuICB3aGlsZSh5LnNpZ251bSgpID4gMCkge1xuICAgIHIgPSAoYSt6LmludFZhbHVlKCkpLnRvU3RyaW5nKGIpLnN1YnN0cigxKSArIHI7XG4gICAgeS5kaXZSZW1UbyhkLHkseik7XG4gIH1cbiAgcmV0dXJuIHouaW50VmFsdWUoKS50b1N0cmluZyhiKSArIHI7XG59XG5cbi8vIChwcm90ZWN0ZWQpIGNvbnZlcnQgZnJvbSByYWRpeCBzdHJpbmdcbmZ1bmN0aW9uIGJucEZyb21SYWRpeChzLGIpIHtcbiAgdGhpcy5mcm9tSW50KDApO1xuICBpZihiID09IG51bGwpIGIgPSAxMDtcbiAgdmFyIGNzID0gdGhpcy5jaHVua1NpemUoYik7XG4gIHZhciBkID0gTWF0aC5wb3coYixjcyksIG1pID0gZmFsc2UsIGogPSAwLCB3ID0gMDtcbiAgZm9yKHZhciBpID0gMDsgaSA8IHMubGVuZ3RoOyArK2kpIHtcbiAgICB2YXIgeCA9IGludEF0KHMsaSk7XG4gICAgaWYoeCA8IDApIHtcbiAgICAgIGlmKHMuY2hhckF0KGkpID09IFwiLVwiICYmIHRoaXMuc2lnbnVtKCkgPT0gMCkgbWkgPSB0cnVlO1xuICAgICAgY29udGludWU7XG4gICAgfVxuICAgIHcgPSBiKncreDtcbiAgICBpZigrK2ogPj0gY3MpIHtcbiAgICAgIHRoaXMuZE11bHRpcGx5KGQpO1xuICAgICAgdGhpcy5kQWRkT2Zmc2V0KHcsMCk7XG4gICAgICBqID0gMDtcbiAgICAgIHcgPSAwO1xuICAgIH1cbiAgfVxuICBpZihqID4gMCkge1xuICAgIHRoaXMuZE11bHRpcGx5KE1hdGgucG93KGIsaikpO1xuICAgIHRoaXMuZEFkZE9mZnNldCh3LDApO1xuICB9XG4gIGlmKG1pKSBCaWdJbnRlZ2VyLlpFUk8uc3ViVG8odGhpcyx0aGlzKTtcbn1cblxuLy8gKHByb3RlY3RlZCkgYWx0ZXJuYXRlIGNvbnN0cnVjdG9yXG5mdW5jdGlvbiBibnBGcm9tTnVtYmVyKGEsYixjKSB7XG4gIGlmKFwibnVtYmVyXCIgPT0gdHlwZW9mIGIpIHtcbiAgICAvLyBuZXcgQmlnSW50ZWdlcihpbnQsaW50LFJORylcbiAgICBpZihhIDwgMikgdGhpcy5mcm9tSW50KDEpO1xuICAgIGVsc2Uge1xuICAgICAgdGhpcy5mcm9tTnVtYmVyKGEsYyk7XG4gICAgICBpZighdGhpcy50ZXN0Qml0KGEtMSkpXHQvLyBmb3JjZSBNU0Igc2V0XG4gICAgICAgIHRoaXMuYml0d2lzZVRvKEJpZ0ludGVnZXIuT05FLnNoaWZ0TGVmdChhLTEpLG9wX29yLHRoaXMpO1xuICAgICAgaWYodGhpcy5pc0V2ZW4oKSkgdGhpcy5kQWRkT2Zmc2V0KDEsMCk7IC8vIGZvcmNlIG9kZFxuICAgICAgd2hpbGUoIXRoaXMuaXNQcm9iYWJsZVByaW1lKGIpKSB7XG4gICAgICAgIHRoaXMuZEFkZE9mZnNldCgyLDApO1xuICAgICAgICBpZih0aGlzLmJpdExlbmd0aCgpID4gYSkgdGhpcy5zdWJUbyhCaWdJbnRlZ2VyLk9ORS5zaGlmdExlZnQoYS0xKSx0aGlzKTtcbiAgICAgIH1cbiAgICB9XG4gIH1cbiAgZWxzZSB7XG4gICAgLy8gbmV3IEJpZ0ludGVnZXIoaW50LFJORylcbiAgICB2YXIgeCA9IG5ldyBBcnJheSgpLCB0ID0gYSY3O1xuICAgIHgubGVuZ3RoID0gKGE+PjMpKzE7XG4gICAgYi5uZXh0Qnl0ZXMoeCk7XG4gICAgaWYodCA+IDApIHhbMF0gJj0gKCgxPDx0KS0xKTsgZWxzZSB4WzBdID0gMDtcbiAgICB0aGlzLmZyb21TdHJpbmcoeCwyNTYpO1xuICB9XG59XG5cbi8vIChwdWJsaWMpIGNvbnZlcnQgdG8gYmlnZW5kaWFuIGJ5dGUgYXJyYXlcbmZ1bmN0aW9uIGJuVG9CeXRlQXJyYXkoKSB7XG4gIHZhciBpID0gdGhpcy50LCByID0gbmV3IEFycmF5KCk7XG4gIHJbMF0gPSB0aGlzLnM7XG4gIHZhciBwID0gdGhpcy5EQi0oaSp0aGlzLkRCKSU4LCBkLCBrID0gMDtcbiAgaWYoaS0tID4gMCkge1xuICAgIGlmKHAgPCB0aGlzLkRCICYmIChkID0gdGhpc1tpXT4+cCkgIT0gKHRoaXMucyZ0aGlzLkRNKT4+cClcbiAgICAgIHJbaysrXSA9IGR8KHRoaXMuczw8KHRoaXMuREItcCkpO1xuICAgIHdoaWxlKGkgPj0gMCkge1xuICAgICAgaWYocCA8IDgpIHtcbiAgICAgICAgZCA9ICh0aGlzW2ldJigoMTw8cCktMSkpPDwoOC1wKTtcbiAgICAgICAgZCB8PSB0aGlzWy0taV0+PihwKz10aGlzLkRCLTgpO1xuICAgICAgfVxuICAgICAgZWxzZSB7XG4gICAgICAgIGQgPSAodGhpc1tpXT4+KHAtPTgpKSYweGZmO1xuICAgICAgICBpZihwIDw9IDApIHsgcCArPSB0aGlzLkRCOyAtLWk7IH1cbiAgICAgIH1cbiAgICAgIGlmKChkJjB4ODApICE9IDApIGQgfD0gLTI1NjtcbiAgICAgIGlmKGsgPT0gMCAmJiAodGhpcy5zJjB4ODApICE9IChkJjB4ODApKSArK2s7XG4gICAgICBpZihrID4gMCB8fCBkICE9IHRoaXMucykgcltrKytdID0gZDtcbiAgICB9XG4gIH1cbiAgcmV0dXJuIHI7XG59XG5cbmZ1bmN0aW9uIGJuRXF1YWxzKGEpIHsgcmV0dXJuKHRoaXMuY29tcGFyZVRvKGEpPT0wKTsgfVxuZnVuY3Rpb24gYm5NaW4oYSkgeyByZXR1cm4odGhpcy5jb21wYXJlVG8oYSk8MCk/dGhpczphOyB9XG5mdW5jdGlvbiBibk1heChhKSB7IHJldHVybih0aGlzLmNvbXBhcmVUbyhhKT4wKT90aGlzOmE7IH1cblxuLy8gKHByb3RlY3RlZCkgciA9IHRoaXMgb3AgYSAoYml0d2lzZSlcbmZ1bmN0aW9uIGJucEJpdHdpc2VUbyhhLG9wLHIpIHtcbiAgdmFyIGksIGYsIG0gPSBNYXRoLm1pbihhLnQsdGhpcy50KTtcbiAgZm9yKGkgPSAwOyBpIDwgbTsgKytpKSByW2ldID0gb3AodGhpc1tpXSxhW2ldKTtcbiAgaWYoYS50IDwgdGhpcy50KSB7XG4gICAgZiA9IGEucyZ0aGlzLkRNO1xuICAgIGZvcihpID0gbTsgaSA8IHRoaXMudDsgKytpKSByW2ldID0gb3AodGhpc1tpXSxmKTtcbiAgICByLnQgPSB0aGlzLnQ7XG4gIH1cbiAgZWxzZSB7XG4gICAgZiA9IHRoaXMucyZ0aGlzLkRNO1xuICAgIGZvcihpID0gbTsgaSA8IGEudDsgKytpKSByW2ldID0gb3AoZixhW2ldKTtcbiAgICByLnQgPSBhLnQ7XG4gIH1cbiAgci5zID0gb3AodGhpcy5zLGEucyk7XG4gIHIuY2xhbXAoKTtcbn1cblxuLy8gKHB1YmxpYykgdGhpcyAmIGFcbmZ1bmN0aW9uIG9wX2FuZCh4LHkpIHsgcmV0dXJuIHgmeTsgfVxuZnVuY3Rpb24gYm5BbmQoYSkgeyB2YXIgciA9IG5iaSgpOyB0aGlzLmJpdHdpc2VUbyhhLG9wX2FuZCxyKTsgcmV0dXJuIHI7IH1cblxuLy8gKHB1YmxpYykgdGhpcyB8IGFcbmZ1bmN0aW9uIG9wX29yKHgseSkgeyByZXR1cm4geHx5OyB9XG5mdW5jdGlvbiBibk9yKGEpIHsgdmFyIHIgPSBuYmkoKTsgdGhpcy5iaXR3aXNlVG8oYSxvcF9vcixyKTsgcmV0dXJuIHI7IH1cblxuLy8gKHB1YmxpYykgdGhpcyBeIGFcbmZ1bmN0aW9uIG9wX3hvcih4LHkpIHsgcmV0dXJuIHheeTsgfVxuZnVuY3Rpb24gYm5Yb3IoYSkgeyB2YXIgciA9IG5iaSgpOyB0aGlzLmJpdHdpc2VUbyhhLG9wX3hvcixyKTsgcmV0dXJuIHI7IH1cblxuLy8gKHB1YmxpYykgdGhpcyAmIH5hXG5mdW5jdGlvbiBvcF9hbmRub3QoeCx5KSB7IHJldHVybiB4Jn55OyB9XG5mdW5jdGlvbiBibkFuZE5vdChhKSB7IHZhciByID0gbmJpKCk7IHRoaXMuYml0d2lzZVRvKGEsb3BfYW5kbm90LHIpOyByZXR1cm4gcjsgfVxuXG4vLyAocHVibGljKSB+dGhpc1xuZnVuY3Rpb24gYm5Ob3QoKSB7XG4gIHZhciByID0gbmJpKCk7XG4gIGZvcih2YXIgaSA9IDA7IGkgPCB0aGlzLnQ7ICsraSkgcltpXSA9IHRoaXMuRE0mfnRoaXNbaV07XG4gIHIudCA9IHRoaXMudDtcbiAgci5zID0gfnRoaXMucztcbiAgcmV0dXJuIHI7XG59XG5cbi8vIChwdWJsaWMpIHRoaXMgPDwgblxuZnVuY3Rpb24gYm5TaGlmdExlZnQobikge1xuICB2YXIgciA9IG5iaSgpO1xuICBpZihuIDwgMCkgdGhpcy5yU2hpZnRUbygtbixyKTsgZWxzZSB0aGlzLmxTaGlmdFRvKG4scik7XG4gIHJldHVybiByO1xufVxuXG4vLyAocHVibGljKSB0aGlzID4+IG5cbmZ1bmN0aW9uIGJuU2hpZnRSaWdodChuKSB7XG4gIHZhciByID0gbmJpKCk7XG4gIGlmKG4gPCAwKSB0aGlzLmxTaGlmdFRvKC1uLHIpOyBlbHNlIHRoaXMuclNoaWZ0VG8obixyKTtcbiAgcmV0dXJuIHI7XG59XG5cbi8vIHJldHVybiBpbmRleCBvZiBsb3dlc3QgMS1iaXQgaW4geCwgeCA8IDJeMzFcbmZ1bmN0aW9uIGxiaXQoeCkge1xuICBpZih4ID09IDApIHJldHVybiAtMTtcbiAgdmFyIHIgPSAwO1xuICBpZigoeCYweGZmZmYpID09IDApIHsgeCA+Pj0gMTY7IHIgKz0gMTY7IH1cbiAgaWYoKHgmMHhmZikgPT0gMCkgeyB4ID4+PSA4OyByICs9IDg7IH1cbiAgaWYoKHgmMHhmKSA9PSAwKSB7IHggPj49IDQ7IHIgKz0gNDsgfVxuICBpZigoeCYzKSA9PSAwKSB7IHggPj49IDI7IHIgKz0gMjsgfVxuICBpZigoeCYxKSA9PSAwKSArK3I7XG4gIHJldHVybiByO1xufVxuXG4vLyAocHVibGljKSByZXR1cm5zIGluZGV4IG9mIGxvd2VzdCAxLWJpdCAob3IgLTEgaWYgbm9uZSlcbmZ1bmN0aW9uIGJuR2V0TG93ZXN0U2V0Qml0KCkge1xuICBmb3IodmFyIGkgPSAwOyBpIDwgdGhpcy50OyArK2kpXG4gICAgaWYodGhpc1tpXSAhPSAwKSByZXR1cm4gaSp0aGlzLkRCK2xiaXQodGhpc1tpXSk7XG4gIGlmKHRoaXMucyA8IDApIHJldHVybiB0aGlzLnQqdGhpcy5EQjtcbiAgcmV0dXJuIC0xO1xufVxuXG4vLyByZXR1cm4gbnVtYmVyIG9mIDEgYml0cyBpbiB4XG5mdW5jdGlvbiBjYml0KHgpIHtcbiAgdmFyIHIgPSAwO1xuICB3aGlsZSh4ICE9IDApIHsgeCAmPSB4LTE7ICsrcjsgfVxuICByZXR1cm4gcjtcbn1cblxuLy8gKHB1YmxpYykgcmV0dXJuIG51bWJlciBvZiBzZXQgYml0c1xuZnVuY3Rpb24gYm5CaXRDb3VudCgpIHtcbiAgdmFyIHIgPSAwLCB4ID0gdGhpcy5zJnRoaXMuRE07XG4gIGZvcih2YXIgaSA9IDA7IGkgPCB0aGlzLnQ7ICsraSkgciArPSBjYml0KHRoaXNbaV1eeCk7XG4gIHJldHVybiByO1xufVxuXG4vLyAocHVibGljKSB0cnVlIGlmZiBudGggYml0IGlzIHNldFxuZnVuY3Rpb24gYm5UZXN0Qml0KG4pIHtcbiAgdmFyIGogPSBNYXRoLmZsb29yKG4vdGhpcy5EQik7XG4gIGlmKGogPj0gdGhpcy50KSByZXR1cm4odGhpcy5zIT0wKTtcbiAgcmV0dXJuKCh0aGlzW2pdJigxPDwobiV0aGlzLkRCKSkpIT0wKTtcbn1cblxuLy8gKHByb3RlY3RlZCkgdGhpcyBvcCAoMTw8bilcbmZ1bmN0aW9uIGJucENoYW5nZUJpdChuLG9wKSB7XG4gIHZhciByID0gQmlnSW50ZWdlci5PTkUuc2hpZnRMZWZ0KG4pO1xuICB0aGlzLmJpdHdpc2VUbyhyLG9wLHIpO1xuICByZXR1cm4gcjtcbn1cblxuLy8gKHB1YmxpYykgdGhpcyB8ICgxPDxuKVxuZnVuY3Rpb24gYm5TZXRCaXQobikgeyByZXR1cm4gdGhpcy5jaGFuZ2VCaXQobixvcF9vcik7IH1cblxuLy8gKHB1YmxpYykgdGhpcyAmIH4oMTw8bilcbmZ1bmN0aW9uIGJuQ2xlYXJCaXQobikgeyByZXR1cm4gdGhpcy5jaGFuZ2VCaXQobixvcF9hbmRub3QpOyB9XG5cbi8vIChwdWJsaWMpIHRoaXMgXiAoMTw8bilcbmZ1bmN0aW9uIGJuRmxpcEJpdChuKSB7IHJldHVybiB0aGlzLmNoYW5nZUJpdChuLG9wX3hvcik7IH1cblxuLy8gKHByb3RlY3RlZCkgciA9IHRoaXMgKyBhXG5mdW5jdGlvbiBibnBBZGRUbyhhLHIpIHtcbiAgdmFyIGkgPSAwLCBjID0gMCwgbSA9IE1hdGgubWluKGEudCx0aGlzLnQpO1xuICB3aGlsZShpIDwgbSkge1xuICAgIGMgKz0gdGhpc1tpXSthW2ldO1xuICAgIHJbaSsrXSA9IGMmdGhpcy5ETTtcbiAgICBjID4+PSB0aGlzLkRCO1xuICB9XG4gIGlmKGEudCA8IHRoaXMudCkge1xuICAgIGMgKz0gYS5zO1xuICAgIHdoaWxlKGkgPCB0aGlzLnQpIHtcbiAgICAgIGMgKz0gdGhpc1tpXTtcbiAgICAgIHJbaSsrXSA9IGMmdGhpcy5ETTtcbiAgICAgIGMgPj49IHRoaXMuREI7XG4gICAgfVxuICAgIGMgKz0gdGhpcy5zO1xuICB9XG4gIGVsc2Uge1xuICAgIGMgKz0gdGhpcy5zO1xuICAgIHdoaWxlKGkgPCBhLnQpIHtcbiAgICAgIGMgKz0gYVtpXTtcbiAgICAgIHJbaSsrXSA9IGMmdGhpcy5ETTtcbiAgICAgIGMgPj49IHRoaXMuREI7XG4gICAgfVxuICAgIGMgKz0gYS5zO1xuICB9XG4gIHIucyA9IChjPDApPy0xOjA7XG4gIGlmKGMgPiAwKSByW2krK10gPSBjO1xuICBlbHNlIGlmKGMgPCAtMSkgcltpKytdID0gdGhpcy5EVitjO1xuICByLnQgPSBpO1xuICByLmNsYW1wKCk7XG59XG5cbi8vIChwdWJsaWMpIHRoaXMgKyBhXG5mdW5jdGlvbiBibkFkZChhKSB7IHZhciByID0gbmJpKCk7IHRoaXMuYWRkVG8oYSxyKTsgcmV0dXJuIHI7IH1cblxuLy8gKHB1YmxpYykgdGhpcyAtIGFcbmZ1bmN0aW9uIGJuU3VidHJhY3QoYSkgeyB2YXIgciA9IG5iaSgpOyB0aGlzLnN1YlRvKGEscik7IHJldHVybiByOyB9XG5cbi8vIChwdWJsaWMpIHRoaXMgKiBhXG5mdW5jdGlvbiBibk11bHRpcGx5KGEpIHsgdmFyIHIgPSBuYmkoKTsgdGhpcy5tdWx0aXBseVRvKGEscik7IHJldHVybiByOyB9XG5cbi8vIChwdWJsaWMpIHRoaXNeMlxuZnVuY3Rpb24gYm5TcXVhcmUoKSB7IHZhciByID0gbmJpKCk7IHRoaXMuc3F1YXJlVG8ocik7IHJldHVybiByOyB9XG5cbi8vIChwdWJsaWMpIHRoaXMgLyBhXG5mdW5jdGlvbiBibkRpdmlkZShhKSB7IHZhciByID0gbmJpKCk7IHRoaXMuZGl2UmVtVG8oYSxyLG51bGwpOyByZXR1cm4gcjsgfVxuXG4vLyAocHVibGljKSB0aGlzICUgYVxuZnVuY3Rpb24gYm5SZW1haW5kZXIoYSkgeyB2YXIgciA9IG5iaSgpOyB0aGlzLmRpdlJlbVRvKGEsbnVsbCxyKTsgcmV0dXJuIHI7IH1cblxuLy8gKHB1YmxpYykgW3RoaXMvYSx0aGlzJWFdXG5mdW5jdGlvbiBibkRpdmlkZUFuZFJlbWFpbmRlcihhKSB7XG4gIHZhciBxID0gbmJpKCksIHIgPSBuYmkoKTtcbiAgdGhpcy5kaXZSZW1UbyhhLHEscik7XG4gIHJldHVybiBuZXcgQXJyYXkocSxyKTtcbn1cblxuLy8gKHByb3RlY3RlZCkgdGhpcyAqPSBuLCB0aGlzID49IDAsIDEgPCBuIDwgRFZcbmZ1bmN0aW9uIGJucERNdWx0aXBseShuKSB7XG4gIHRoaXNbdGhpcy50XSA9IHRoaXMuYW0oMCxuLTEsdGhpcywwLDAsdGhpcy50KTtcbiAgKyt0aGlzLnQ7XG4gIHRoaXMuY2xhbXAoKTtcbn1cblxuLy8gKHByb3RlY3RlZCkgdGhpcyArPSBuIDw8IHcgd29yZHMsIHRoaXMgPj0gMFxuZnVuY3Rpb24gYm5wREFkZE9mZnNldChuLHcpIHtcbiAgaWYobiA9PSAwKSByZXR1cm47XG4gIHdoaWxlKHRoaXMudCA8PSB3KSB0aGlzW3RoaXMudCsrXSA9IDA7XG4gIHRoaXNbd10gKz0gbjtcbiAgd2hpbGUodGhpc1t3XSA+PSB0aGlzLkRWKSB7XG4gICAgdGhpc1t3XSAtPSB0aGlzLkRWO1xuICAgIGlmKCsrdyA+PSB0aGlzLnQpIHRoaXNbdGhpcy50KytdID0gMDtcbiAgICArK3RoaXNbd107XG4gIH1cbn1cblxuLy8gQSBcIm51bGxcIiByZWR1Y2VyXG5mdW5jdGlvbiBOdWxsRXhwKCkge31cbmZ1bmN0aW9uIG5Ob3AoeCkgeyByZXR1cm4geDsgfVxuZnVuY3Rpb24gbk11bFRvKHgseSxyKSB7IHgubXVsdGlwbHlUbyh5LHIpOyB9XG5mdW5jdGlvbiBuU3FyVG8oeCxyKSB7IHguc3F1YXJlVG8ocik7IH1cblxuTnVsbEV4cC5wcm90b3R5cGUuY29udmVydCA9IG5Ob3A7XG5OdWxsRXhwLnByb3RvdHlwZS5yZXZlcnQgPSBuTm9wO1xuTnVsbEV4cC5wcm90b3R5cGUubXVsVG8gPSBuTXVsVG87XG5OdWxsRXhwLnByb3RvdHlwZS5zcXJUbyA9IG5TcXJUbztcblxuLy8gKHB1YmxpYykgdGhpc15lXG5mdW5jdGlvbiBiblBvdyhlKSB7IHJldHVybiB0aGlzLmV4cChlLG5ldyBOdWxsRXhwKCkpOyB9XG5cbi8vIChwcm90ZWN0ZWQpIHIgPSBsb3dlciBuIHdvcmRzIG9mIFwidGhpcyAqIGFcIiwgYS50IDw9IG5cbi8vIFwidGhpc1wiIHNob3VsZCBiZSB0aGUgbGFyZ2VyIG9uZSBpZiBhcHByb3ByaWF0ZS5cbmZ1bmN0aW9uIGJucE11bHRpcGx5TG93ZXJUbyhhLG4scikge1xuICB2YXIgaSA9IE1hdGgubWluKHRoaXMudCthLnQsbik7XG4gIHIucyA9IDA7IC8vIGFzc3VtZXMgYSx0aGlzID49IDBcbiAgci50ID0gaTtcbiAgd2hpbGUoaSA+IDApIHJbLS1pXSA9IDA7XG4gIHZhciBqO1xuICBmb3IoaiA9IHIudC10aGlzLnQ7IGkgPCBqOyArK2kpIHJbaSt0aGlzLnRdID0gdGhpcy5hbSgwLGFbaV0scixpLDAsdGhpcy50KTtcbiAgZm9yKGogPSBNYXRoLm1pbihhLnQsbik7IGkgPCBqOyArK2kpIHRoaXMuYW0oMCxhW2ldLHIsaSwwLG4taSk7XG4gIHIuY2xhbXAoKTtcbn1cblxuLy8gKHByb3RlY3RlZCkgciA9IFwidGhpcyAqIGFcIiB3aXRob3V0IGxvd2VyIG4gd29yZHMsIG4gPiAwXG4vLyBcInRoaXNcIiBzaG91bGQgYmUgdGhlIGxhcmdlciBvbmUgaWYgYXBwcm9wcmlhdGUuXG5mdW5jdGlvbiBibnBNdWx0aXBseVVwcGVyVG8oYSxuLHIpIHtcbiAgLS1uO1xuICB2YXIgaSA9IHIudCA9IHRoaXMudCthLnQtbjtcbiAgci5zID0gMDsgLy8gYXNzdW1lcyBhLHRoaXMgPj0gMFxuICB3aGlsZSgtLWkgPj0gMCkgcltpXSA9IDA7XG4gIGZvcihpID0gTWF0aC5tYXgobi10aGlzLnQsMCk7IGkgPCBhLnQ7ICsraSlcbiAgICByW3RoaXMudCtpLW5dID0gdGhpcy5hbShuLWksYVtpXSxyLDAsMCx0aGlzLnQraS1uKTtcbiAgci5jbGFtcCgpO1xuICByLmRyU2hpZnRUbygxLHIpO1xufVxuXG4vLyBCYXJyZXR0IG1vZHVsYXIgcmVkdWN0aW9uXG5mdW5jdGlvbiBCYXJyZXR0KG0pIHtcbiAgLy8gc2V0dXAgQmFycmV0dFxuICB0aGlzLnIyID0gbmJpKCk7XG4gIHRoaXMucTMgPSBuYmkoKTtcbiAgQmlnSW50ZWdlci5PTkUuZGxTaGlmdFRvKDIqbS50LHRoaXMucjIpO1xuICB0aGlzLm11ID0gdGhpcy5yMi5kaXZpZGUobSk7XG4gIHRoaXMubSA9IG07XG59XG5cbmZ1bmN0aW9uIGJhcnJldHRDb252ZXJ0KHgpIHtcbiAgaWYoeC5zIDwgMCB8fCB4LnQgPiAyKnRoaXMubS50KSByZXR1cm4geC5tb2QodGhpcy5tKTtcbiAgZWxzZSBpZih4LmNvbXBhcmVUbyh0aGlzLm0pIDwgMCkgcmV0dXJuIHg7XG4gIGVsc2UgeyB2YXIgciA9IG5iaSgpOyB4LmNvcHlUbyhyKTsgdGhpcy5yZWR1Y2Uocik7IHJldHVybiByOyB9XG59XG5cbmZ1bmN0aW9uIGJhcnJldHRSZXZlcnQoeCkgeyByZXR1cm4geDsgfVxuXG4vLyB4ID0geCBtb2QgbSAoSEFDIDE0LjQyKVxuZnVuY3Rpb24gYmFycmV0dFJlZHVjZSh4KSB7XG4gIHguZHJTaGlmdFRvKHRoaXMubS50LTEsdGhpcy5yMik7XG4gIGlmKHgudCA+IHRoaXMubS50KzEpIHsgeC50ID0gdGhpcy5tLnQrMTsgeC5jbGFtcCgpOyB9XG4gIHRoaXMubXUubXVsdGlwbHlVcHBlclRvKHRoaXMucjIsdGhpcy5tLnQrMSx0aGlzLnEzKTtcbiAgdGhpcy5tLm11bHRpcGx5TG93ZXJUbyh0aGlzLnEzLHRoaXMubS50KzEsdGhpcy5yMik7XG4gIHdoaWxlKHguY29tcGFyZVRvKHRoaXMucjIpIDwgMCkgeC5kQWRkT2Zmc2V0KDEsdGhpcy5tLnQrMSk7XG4gIHguc3ViVG8odGhpcy5yMix4KTtcbiAgd2hpbGUoeC5jb21wYXJlVG8odGhpcy5tKSA+PSAwKSB4LnN1YlRvKHRoaXMubSx4KTtcbn1cblxuLy8gciA9IHheMiBtb2QgbTsgeCAhPSByXG5mdW5jdGlvbiBiYXJyZXR0U3FyVG8oeCxyKSB7IHguc3F1YXJlVG8ocik7IHRoaXMucmVkdWNlKHIpOyB9XG5cbi8vIHIgPSB4KnkgbW9kIG07IHgseSAhPSByXG5mdW5jdGlvbiBiYXJyZXR0TXVsVG8oeCx5LHIpIHsgeC5tdWx0aXBseVRvKHkscik7IHRoaXMucmVkdWNlKHIpOyB9XG5cbkJhcnJldHQucHJvdG90eXBlLmNvbnZlcnQgPSBiYXJyZXR0Q29udmVydDtcbkJhcnJldHQucHJvdG90eXBlLnJldmVydCA9IGJhcnJldHRSZXZlcnQ7XG5CYXJyZXR0LnByb3RvdHlwZS5yZWR1Y2UgPSBiYXJyZXR0UmVkdWNlO1xuQmFycmV0dC5wcm90b3R5cGUubXVsVG8gPSBiYXJyZXR0TXVsVG87XG5CYXJyZXR0LnByb3RvdHlwZS5zcXJUbyA9IGJhcnJldHRTcXJUbztcblxuLy8gKHB1YmxpYykgdGhpc15lICUgbSAoSEFDIDE0Ljg1KVxuZnVuY3Rpb24gYm5Nb2RQb3coZSxtKSB7XG4gIHZhciBpID0gZS5iaXRMZW5ndGgoKSwgaywgciA9IG5idigxKSwgejtcbiAgaWYoaSA8PSAwKSByZXR1cm4gcjtcbiAgZWxzZSBpZihpIDwgMTgpIGsgPSAxO1xuICBlbHNlIGlmKGkgPCA0OCkgayA9IDM7XG4gIGVsc2UgaWYoaSA8IDE0NCkgayA9IDQ7XG4gIGVsc2UgaWYoaSA8IDc2OCkgayA9IDU7XG4gIGVsc2UgayA9IDY7XG4gIGlmKGkgPCA4KVxuICAgIHogPSBuZXcgQ2xhc3NpYyhtKTtcbiAgZWxzZSBpZihtLmlzRXZlbigpKVxuICAgIHogPSBuZXcgQmFycmV0dChtKTtcbiAgZWxzZVxuICAgIHogPSBuZXcgTW9udGdvbWVyeShtKTtcblxuICAvLyBwcmVjb21wdXRhdGlvblxuICB2YXIgZyA9IG5ldyBBcnJheSgpLCBuID0gMywgazEgPSBrLTEsIGttID0gKDE8PGspLTE7XG4gIGdbMV0gPSB6LmNvbnZlcnQodGhpcyk7XG4gIGlmKGsgPiAxKSB7XG4gICAgdmFyIGcyID0gbmJpKCk7XG4gICAgei5zcXJUbyhnWzFdLGcyKTtcbiAgICB3aGlsZShuIDw9IGttKSB7XG4gICAgICBnW25dID0gbmJpKCk7XG4gICAgICB6Lm11bFRvKGcyLGdbbi0yXSxnW25dKTtcbiAgICAgIG4gKz0gMjtcbiAgICB9XG4gIH1cblxuICB2YXIgaiA9IGUudC0xLCB3LCBpczEgPSB0cnVlLCByMiA9IG5iaSgpLCB0O1xuICBpID0gbmJpdHMoZVtqXSktMTtcbiAgd2hpbGUoaiA+PSAwKSB7XG4gICAgaWYoaSA+PSBrMSkgdyA9IChlW2pdPj4oaS1rMSkpJmttO1xuICAgIGVsc2Uge1xuICAgICAgdyA9IChlW2pdJigoMTw8KGkrMSkpLTEpKTw8KGsxLWkpO1xuICAgICAgaWYoaiA+IDApIHcgfD0gZVtqLTFdPj4odGhpcy5EQitpLWsxKTtcbiAgICB9XG5cbiAgICBuID0gaztcbiAgICB3aGlsZSgodyYxKSA9PSAwKSB7IHcgPj49IDE7IC0tbjsgfVxuICAgIGlmKChpIC09IG4pIDwgMCkgeyBpICs9IHRoaXMuREI7IC0tajsgfVxuICAgIGlmKGlzMSkge1x0Ly8gcmV0ID09IDEsIGRvbid0IGJvdGhlciBzcXVhcmluZyBvciBtdWx0aXBseWluZyBpdFxuICAgICAgZ1t3XS5jb3B5VG8ocik7XG4gICAgICBpczEgPSBmYWxzZTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICB3aGlsZShuID4gMSkgeyB6LnNxclRvKHIscjIpOyB6LnNxclRvKHIyLHIpOyBuIC09IDI7IH1cbiAgICAgIGlmKG4gPiAwKSB6LnNxclRvKHIscjIpOyBlbHNlIHsgdCA9IHI7IHIgPSByMjsgcjIgPSB0OyB9XG4gICAgICB6Lm11bFRvKHIyLGdbd10scik7XG4gICAgfVxuXG4gICAgd2hpbGUoaiA+PSAwICYmIChlW2pdJigxPDxpKSkgPT0gMCkge1xuICAgICAgei5zcXJUbyhyLHIyKTsgdCA9IHI7IHIgPSByMjsgcjIgPSB0O1xuICAgICAgaWYoLS1pIDwgMCkgeyBpID0gdGhpcy5EQi0xOyAtLWo7IH1cbiAgICB9XG4gIH1cbiAgcmV0dXJuIHoucmV2ZXJ0KHIpO1xufVxuXG4vLyAocHVibGljKSBnY2QodGhpcyxhKSAoSEFDIDE0LjU0KVxuZnVuY3Rpb24gYm5HQ0QoYSkge1xuICB2YXIgeCA9ICh0aGlzLnM8MCk/dGhpcy5uZWdhdGUoKTp0aGlzLmNsb25lKCk7XG4gIHZhciB5ID0gKGEuczwwKT9hLm5lZ2F0ZSgpOmEuY2xvbmUoKTtcbiAgaWYoeC5jb21wYXJlVG8oeSkgPCAwKSB7IHZhciB0ID0geDsgeCA9IHk7IHkgPSB0OyB9XG4gIHZhciBpID0geC5nZXRMb3dlc3RTZXRCaXQoKSwgZyA9IHkuZ2V0TG93ZXN0U2V0Qml0KCk7XG4gIGlmKGcgPCAwKSByZXR1cm4geDtcbiAgaWYoaSA8IGcpIGcgPSBpO1xuICBpZihnID4gMCkge1xuICAgIHguclNoaWZ0VG8oZyx4KTtcbiAgICB5LnJTaGlmdFRvKGcseSk7XG4gIH1cbiAgd2hpbGUoeC5zaWdudW0oKSA+IDApIHtcbiAgICBpZigoaSA9IHguZ2V0TG93ZXN0U2V0Qml0KCkpID4gMCkgeC5yU2hpZnRUbyhpLHgpO1xuICAgIGlmKChpID0geS5nZXRMb3dlc3RTZXRCaXQoKSkgPiAwKSB5LnJTaGlmdFRvKGkseSk7XG4gICAgaWYoeC5jb21wYXJlVG8oeSkgPj0gMCkge1xuICAgICAgeC5zdWJUbyh5LHgpO1xuICAgICAgeC5yU2hpZnRUbygxLHgpO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgIHkuc3ViVG8oeCx5KTtcbiAgICAgIHkuclNoaWZ0VG8oMSx5KTtcbiAgICB9XG4gIH1cbiAgaWYoZyA+IDApIHkubFNoaWZ0VG8oZyx5KTtcbiAgcmV0dXJuIHk7XG59XG5cbi8vIChwcm90ZWN0ZWQpIHRoaXMgJSBuLCBuIDwgMl4yNlxuZnVuY3Rpb24gYm5wTW9kSW50KG4pIHtcbiAgaWYobiA8PSAwKSByZXR1cm4gMDtcbiAgdmFyIGQgPSB0aGlzLkRWJW4sIHIgPSAodGhpcy5zPDApP24tMTowO1xuICBpZih0aGlzLnQgPiAwKVxuICAgIGlmKGQgPT0gMCkgciA9IHRoaXNbMF0lbjtcbiAgICBlbHNlIGZvcih2YXIgaSA9IHRoaXMudC0xOyBpID49IDA7IC0taSkgciA9IChkKnIrdGhpc1tpXSklbjtcbiAgcmV0dXJuIHI7XG59XG5cbi8vIChwdWJsaWMpIDEvdGhpcyAlIG0gKEhBQyAxNC42MSlcbmZ1bmN0aW9uIGJuTW9kSW52ZXJzZShtKSB7XG4gIHZhciBhYyA9IG0uaXNFdmVuKCk7XG4gIGlmKCh0aGlzLmlzRXZlbigpICYmIGFjKSB8fCBtLnNpZ251bSgpID09IDApIHJldHVybiBCaWdJbnRlZ2VyLlpFUk87XG4gIHZhciB1ID0gbS5jbG9uZSgpLCB2ID0gdGhpcy5jbG9uZSgpO1xuICB2YXIgYSA9IG5idigxKSwgYiA9IG5idigwKSwgYyA9IG5idigwKSwgZCA9IG5idigxKTtcbiAgd2hpbGUodS5zaWdudW0oKSAhPSAwKSB7XG4gICAgd2hpbGUodS5pc0V2ZW4oKSkge1xuICAgICAgdS5yU2hpZnRUbygxLHUpO1xuICAgICAgaWYoYWMpIHtcbiAgICAgICAgaWYoIWEuaXNFdmVuKCkgfHwgIWIuaXNFdmVuKCkpIHsgYS5hZGRUbyh0aGlzLGEpOyBiLnN1YlRvKG0sYik7IH1cbiAgICAgICAgYS5yU2hpZnRUbygxLGEpO1xuICAgICAgfVxuICAgICAgZWxzZSBpZighYi5pc0V2ZW4oKSkgYi5zdWJUbyhtLGIpO1xuICAgICAgYi5yU2hpZnRUbygxLGIpO1xuICAgIH1cbiAgICB3aGlsZSh2LmlzRXZlbigpKSB7XG4gICAgICB2LnJTaGlmdFRvKDEsdik7XG4gICAgICBpZihhYykge1xuICAgICAgICBpZighYy5pc0V2ZW4oKSB8fCAhZC5pc0V2ZW4oKSkgeyBjLmFkZFRvKHRoaXMsYyk7IGQuc3ViVG8obSxkKTsgfVxuICAgICAgICBjLnJTaGlmdFRvKDEsYyk7XG4gICAgICB9XG4gICAgICBlbHNlIGlmKCFkLmlzRXZlbigpKSBkLnN1YlRvKG0sZCk7XG4gICAgICBkLnJTaGlmdFRvKDEsZCk7XG4gICAgfVxuICAgIGlmKHUuY29tcGFyZVRvKHYpID49IDApIHtcbiAgICAgIHUuc3ViVG8odix1KTtcbiAgICAgIGlmKGFjKSBhLnN1YlRvKGMsYSk7XG4gICAgICBiLnN1YlRvKGQsYik7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgdi5zdWJUbyh1LHYpO1xuICAgICAgaWYoYWMpIGMuc3ViVG8oYSxjKTtcbiAgICAgIGQuc3ViVG8oYixkKTtcbiAgICB9XG4gIH1cbiAgaWYodi5jb21wYXJlVG8oQmlnSW50ZWdlci5PTkUpICE9IDApIHJldHVybiBCaWdJbnRlZ2VyLlpFUk87XG4gIGlmKGQuY29tcGFyZVRvKG0pID49IDApIHJldHVybiBkLnN1YnRyYWN0KG0pO1xuICBpZihkLnNpZ251bSgpIDwgMCkgZC5hZGRUbyhtLGQpOyBlbHNlIHJldHVybiBkO1xuICBpZihkLnNpZ251bSgpIDwgMCkgcmV0dXJuIGQuYWRkKG0pOyBlbHNlIHJldHVybiBkO1xufVxuXG52YXIgbG93cHJpbWVzID0gWzIsMyw1LDcsMTEsMTMsMTcsMTksMjMsMjksMzEsMzcsNDEsNDMsNDcsNTMsNTksNjEsNjcsNzEsNzMsNzksODMsODksOTcsMTAxLDEwMywxMDcsMTA5LDExMywxMjcsMTMxLDEzNywxMzksMTQ5LDE1MSwxNTcsMTYzLDE2NywxNzMsMTc5LDE4MSwxOTEsMTkzLDE5NywxOTksMjExLDIyMywyMjcsMjI5LDIzMywyMzksMjQxLDI1MSwyNTcsMjYzLDI2OSwyNzEsMjc3LDI4MSwyODMsMjkzLDMwNywzMTEsMzEzLDMxNywzMzEsMzM3LDM0NywzNDksMzUzLDM1OSwzNjcsMzczLDM3OSwzODMsMzg5LDM5Nyw0MDEsNDA5LDQxOSw0MjEsNDMxLDQzMyw0MzksNDQzLDQ0OSw0NTcsNDYxLDQ2Myw0NjcsNDc5LDQ4Nyw0OTEsNDk5LDUwMyw1MDksNTIxLDUyMyw1NDEsNTQ3LDU1Nyw1NjMsNTY5LDU3MSw1NzcsNTg3LDU5Myw1OTksNjAxLDYwNyw2MTMsNjE3LDYxOSw2MzEsNjQxLDY0Myw2NDcsNjUzLDY1OSw2NjEsNjczLDY3Nyw2ODMsNjkxLDcwMSw3MDksNzE5LDcyNyw3MzMsNzM5LDc0Myw3NTEsNzU3LDc2MSw3NjksNzczLDc4Nyw3OTcsODA5LDgxMSw4MjEsODIzLDgyNyw4MjksODM5LDg1Myw4NTcsODU5LDg2Myw4NzcsODgxLDg4Myw4ODcsOTA3LDkxMSw5MTksOTI5LDkzNyw5NDEsOTQ3LDk1Myw5NjcsOTcxLDk3Nyw5ODMsOTkxLDk5N107XG52YXIgbHBsaW0gPSAoMTw8MjYpL2xvd3ByaW1lc1tsb3dwcmltZXMubGVuZ3RoLTFdO1xuXG4vLyAocHVibGljKSB0ZXN0IHByaW1hbGl0eSB3aXRoIGNlcnRhaW50eSA+PSAxLS41XnRcbmZ1bmN0aW9uIGJuSXNQcm9iYWJsZVByaW1lKHQpIHtcbiAgdmFyIGksIHggPSB0aGlzLmFicygpO1xuICBpZih4LnQgPT0gMSAmJiB4WzBdIDw9IGxvd3ByaW1lc1tsb3dwcmltZXMubGVuZ3RoLTFdKSB7XG4gICAgZm9yKGkgPSAwOyBpIDwgbG93cHJpbWVzLmxlbmd0aDsgKytpKVxuICAgICAgaWYoeFswXSA9PSBsb3dwcmltZXNbaV0pIHJldHVybiB0cnVlO1xuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuICBpZih4LmlzRXZlbigpKSByZXR1cm4gZmFsc2U7XG4gIGkgPSAxO1xuICB3aGlsZShpIDwgbG93cHJpbWVzLmxlbmd0aCkge1xuICAgIHZhciBtID0gbG93cHJpbWVzW2ldLCBqID0gaSsxO1xuICAgIHdoaWxlKGogPCBsb3dwcmltZXMubGVuZ3RoICYmIG0gPCBscGxpbSkgbSAqPSBsb3dwcmltZXNbaisrXTtcbiAgICBtID0geC5tb2RJbnQobSk7XG4gICAgd2hpbGUoaSA8IGopIGlmKG0lbG93cHJpbWVzW2krK10gPT0gMCkgcmV0dXJuIGZhbHNlO1xuICB9XG4gIHJldHVybiB4Lm1pbGxlclJhYmluKHQpO1xufVxuXG4vLyAocHJvdGVjdGVkKSB0cnVlIGlmIHByb2JhYmx5IHByaW1lIChIQUMgNC4yNCwgTWlsbGVyLVJhYmluKVxuZnVuY3Rpb24gYm5wTWlsbGVyUmFiaW4odCkge1xuICB2YXIgbjEgPSB0aGlzLnN1YnRyYWN0KEJpZ0ludGVnZXIuT05FKTtcbiAgdmFyIGsgPSBuMS5nZXRMb3dlc3RTZXRCaXQoKTtcbiAgaWYoayA8PSAwKSByZXR1cm4gZmFsc2U7XG4gIHZhciByID0gbjEuc2hpZnRSaWdodChrKTtcbiAgdCA9ICh0KzEpPj4xO1xuICBpZih0ID4gbG93cHJpbWVzLmxlbmd0aCkgdCA9IGxvd3ByaW1lcy5sZW5ndGg7XG4gIHZhciBhID0gbmJpKCk7XG4gIGZvcih2YXIgaSA9IDA7IGkgPCB0OyArK2kpIHtcbiAgICAvL1BpY2sgYmFzZXMgYXQgcmFuZG9tLCBpbnN0ZWFkIG9mIHN0YXJ0aW5nIGF0IDJcbiAgICBhLmZyb21JbnQobG93cHJpbWVzW01hdGguZmxvb3IoTWF0aC5yYW5kb20oKSpsb3dwcmltZXMubGVuZ3RoKV0pO1xuICAgIHZhciB5ID0gYS5tb2RQb3cocix0aGlzKTtcbiAgICBpZih5LmNvbXBhcmVUbyhCaWdJbnRlZ2VyLk9ORSkgIT0gMCAmJiB5LmNvbXBhcmVUbyhuMSkgIT0gMCkge1xuICAgICAgdmFyIGogPSAxO1xuICAgICAgd2hpbGUoaisrIDwgayAmJiB5LmNvbXBhcmVUbyhuMSkgIT0gMCkge1xuICAgICAgICB5ID0geS5tb2RQb3dJbnQoMix0aGlzKTtcbiAgICAgICAgaWYoeS5jb21wYXJlVG8oQmlnSW50ZWdlci5PTkUpID09IDApIHJldHVybiBmYWxzZTtcbiAgICAgIH1cbiAgICAgIGlmKHkuY29tcGFyZVRvKG4xKSAhPSAwKSByZXR1cm4gZmFsc2U7XG4gICAgfVxuICB9XG4gIHJldHVybiB0cnVlO1xufVxuXG4vLyBwcm90ZWN0ZWRcbkJpZ0ludGVnZXIucHJvdG90eXBlLmNodW5rU2l6ZSA9IGJucENodW5rU2l6ZTtcbkJpZ0ludGVnZXIucHJvdG90eXBlLnRvUmFkaXggPSBibnBUb1JhZGl4O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZnJvbVJhZGl4ID0gYm5wRnJvbVJhZGl4O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZnJvbU51bWJlciA9IGJucEZyb21OdW1iZXI7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5iaXR3aXNlVG8gPSBibnBCaXR3aXNlVG87XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5jaGFuZ2VCaXQgPSBibnBDaGFuZ2VCaXQ7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5hZGRUbyA9IGJucEFkZFRvO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZE11bHRpcGx5ID0gYm5wRE11bHRpcGx5O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZEFkZE9mZnNldCA9IGJucERBZGRPZmZzZXQ7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5tdWx0aXBseUxvd2VyVG8gPSBibnBNdWx0aXBseUxvd2VyVG87XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5tdWx0aXBseVVwcGVyVG8gPSBibnBNdWx0aXBseVVwcGVyVG87XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5tb2RJbnQgPSBibnBNb2RJbnQ7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5taWxsZXJSYWJpbiA9IGJucE1pbGxlclJhYmluO1xuXG4vLyBwdWJsaWNcbkJpZ0ludGVnZXIucHJvdG90eXBlLmNsb25lID0gYm5DbG9uZTtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmludFZhbHVlID0gYm5JbnRWYWx1ZTtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmJ5dGVWYWx1ZSA9IGJuQnl0ZVZhbHVlO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuc2hvcnRWYWx1ZSA9IGJuU2hvcnRWYWx1ZTtcbkJpZ0ludGVnZXIucHJvdG90eXBlLnNpZ251bSA9IGJuU2lnTnVtO1xuQmlnSW50ZWdlci5wcm90b3R5cGUudG9CeXRlQXJyYXkgPSBiblRvQnl0ZUFycmF5O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZXF1YWxzID0gYm5FcXVhbHM7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5taW4gPSBibk1pbjtcbkJpZ0ludGVnZXIucHJvdG90eXBlLm1heCA9IGJuTWF4O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuYW5kID0gYm5BbmQ7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5vciA9IGJuT3I7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS54b3IgPSBiblhvcjtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmFuZE5vdCA9IGJuQW5kTm90O1xuQmlnSW50ZWdlci5wcm90b3R5cGUubm90ID0gYm5Ob3Q7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5zaGlmdExlZnQgPSBiblNoaWZ0TGVmdDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLnNoaWZ0UmlnaHQgPSBiblNoaWZ0UmlnaHQ7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5nZXRMb3dlc3RTZXRCaXQgPSBibkdldExvd2VzdFNldEJpdDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmJpdENvdW50ID0gYm5CaXRDb3VudDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLnRlc3RCaXQgPSBiblRlc3RCaXQ7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5zZXRCaXQgPSBiblNldEJpdDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmNsZWFyQml0ID0gYm5DbGVhckJpdDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmZsaXBCaXQgPSBibkZsaXBCaXQ7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5hZGQgPSBibkFkZDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLnN1YnRyYWN0ID0gYm5TdWJ0cmFjdDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLm11bHRpcGx5ID0gYm5NdWx0aXBseTtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmRpdmlkZSA9IGJuRGl2aWRlO1xuQmlnSW50ZWdlci5wcm90b3R5cGUucmVtYWluZGVyID0gYm5SZW1haW5kZXI7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5kaXZpZGVBbmRSZW1haW5kZXIgPSBibkRpdmlkZUFuZFJlbWFpbmRlcjtcbkJpZ0ludGVnZXIucHJvdG90eXBlLm1vZFBvdyA9IGJuTW9kUG93O1xuQmlnSW50ZWdlci5wcm90b3R5cGUubW9kSW52ZXJzZSA9IGJuTW9kSW52ZXJzZTtcbkJpZ0ludGVnZXIucHJvdG90eXBlLnBvdyA9IGJuUG93O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZ2NkID0gYm5HQ0Q7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5pc1Byb2JhYmxlUHJpbWUgPSBibklzUHJvYmFibGVQcmltZTtcblxuLy8gSlNCTi1zcGVjaWZpYyBleHRlbnNpb25cbkJpZ0ludGVnZXIucHJvdG90eXBlLnNxdWFyZSA9IGJuU3F1YXJlO1xuXG4vLyBCaWdJbnRlZ2VyIGludGVyZmFjZXMgbm90IGltcGxlbWVudGVkIGluIGpzYm46XG5cbi8vIEJpZ0ludGVnZXIoaW50IHNpZ251bSwgYnl0ZVtdIG1hZ25pdHVkZSlcbi8vIGRvdWJsZSBkb3VibGVWYWx1ZSgpXG4vLyBmbG9hdCBmbG9hdFZhbHVlKClcbi8vIGludCBoYXNoQ29kZSgpXG4vLyBsb25nIGxvbmdWYWx1ZSgpXG4vLyBzdGF0aWMgQmlnSW50ZWdlciB2YWx1ZU9mKGxvbmcgdmFsKVxuXG4vLyBwcm5nNC5qcyAtIHVzZXMgQXJjZm91ciBhcyBhIFBSTkdcblxuZnVuY3Rpb24gQXJjZm91cigpIHtcbiAgdGhpcy5pID0gMDtcbiAgdGhpcy5qID0gMDtcbiAgdGhpcy5TID0gbmV3IEFycmF5KCk7XG59XG5cbi8vIEluaXRpYWxpemUgYXJjZm91ciBjb250ZXh0IGZyb20ga2V5LCBhbiBhcnJheSBvZiBpbnRzLCBlYWNoIGZyb20gWzAuLjI1NV1cbmZ1bmN0aW9uIEFSQzRpbml0KGtleSkge1xuICB2YXIgaSwgaiwgdDtcbiAgZm9yKGkgPSAwOyBpIDwgMjU2OyArK2kpXG4gICAgdGhpcy5TW2ldID0gaTtcbiAgaiA9IDA7XG4gIGZvcihpID0gMDsgaSA8IDI1NjsgKytpKSB7XG4gICAgaiA9IChqICsgdGhpcy5TW2ldICsga2V5W2kgJSBrZXkubGVuZ3RoXSkgJiAyNTU7XG4gICAgdCA9IHRoaXMuU1tpXTtcbiAgICB0aGlzLlNbaV0gPSB0aGlzLlNbal07XG4gICAgdGhpcy5TW2pdID0gdDtcbiAgfVxuICB0aGlzLmkgPSAwO1xuICB0aGlzLmogPSAwO1xufVxuXG5mdW5jdGlvbiBBUkM0bmV4dCgpIHtcbiAgdmFyIHQ7XG4gIHRoaXMuaSA9ICh0aGlzLmkgKyAxKSAmIDI1NTtcbiAgdGhpcy5qID0gKHRoaXMuaiArIHRoaXMuU1t0aGlzLmldKSAmIDI1NTtcbiAgdCA9IHRoaXMuU1t0aGlzLmldO1xuICB0aGlzLlNbdGhpcy5pXSA9IHRoaXMuU1t0aGlzLmpdO1xuICB0aGlzLlNbdGhpcy5qXSA9IHQ7XG4gIHJldHVybiB0aGlzLlNbKHQgKyB0aGlzLlNbdGhpcy5pXSkgJiAyNTVdO1xufVxuXG5BcmNmb3VyLnByb3RvdHlwZS5pbml0ID0gQVJDNGluaXQ7XG5BcmNmb3VyLnByb3RvdHlwZS5uZXh0ID0gQVJDNG5leHQ7XG5cbi8vIFBsdWcgaW4geW91ciBSTkcgY29uc3RydWN0b3IgaGVyZVxuZnVuY3Rpb24gcHJuZ19uZXdzdGF0ZSgpIHtcbiAgcmV0dXJuIG5ldyBBcmNmb3VyKCk7XG59XG5cbi8vIFBvb2wgc2l6ZSBtdXN0IGJlIGEgbXVsdGlwbGUgb2YgNCBhbmQgZ3JlYXRlciB0aGFuIDMyLlxuLy8gQW4gYXJyYXkgb2YgYnl0ZXMgdGhlIHNpemUgb2YgdGhlIHBvb2wgd2lsbCBiZSBwYXNzZWQgdG8gaW5pdCgpXG52YXIgcm5nX3BzaXplID0gMjU2O1xuXG4vLyBSYW5kb20gbnVtYmVyIGdlbmVyYXRvciAtIHJlcXVpcmVzIGEgUFJORyBiYWNrZW5kLCBlLmcuIHBybmc0LmpzXG52YXIgcm5nX3N0YXRlO1xudmFyIHJuZ19wb29sO1xudmFyIHJuZ19wcHRyO1xuXG4vLyBJbml0aWFsaXplIHRoZSBwb29sIHdpdGgganVuayBpZiBuZWVkZWQuXG5pZihybmdfcG9vbCA9PSBudWxsKSB7XG4gIHJuZ19wb29sID0gbmV3IEFycmF5KCk7XG4gIHJuZ19wcHRyID0gMDtcbiAgdmFyIHQ7XG4gIGlmKHdpbmRvdy5jcnlwdG8gJiYgd2luZG93LmNyeXB0by5nZXRSYW5kb21WYWx1ZXMpIHtcbiAgICAvLyBFeHRyYWN0IGVudHJvcHkgKDIwNDggYml0cykgZnJvbSBSTkcgaWYgYXZhaWxhYmxlXG4gICAgdmFyIHogPSBuZXcgVWludDMyQXJyYXkoMjU2KTtcbiAgICB3aW5kb3cuY3J5cHRvLmdldFJhbmRvbVZhbHVlcyh6KTtcbiAgICBmb3IgKHQgPSAwOyB0IDwgei5sZW5ndGg7ICsrdClcbiAgICAgIHJuZ19wb29sW3JuZ19wcHRyKytdID0gelt0XSAmIDI1NTtcbiAgfVxuXG4gIC8vIFVzZSBtb3VzZSBldmVudHMgZm9yIGVudHJvcHksIGlmIHdlIGRvIG5vdCBoYXZlIGVub3VnaCBlbnRyb3B5IGJ5IHRoZSB0aW1lXG4gIC8vIHdlIG5lZWQgaXQsIGVudHJvcHkgd2lsbCBiZSBnZW5lcmF0ZWQgYnkgTWF0aC5yYW5kb20uXG4gIHZhciBvbk1vdXNlTW92ZUxpc3RlbmVyID0gZnVuY3Rpb24oZXYpIHtcbiAgICB0aGlzLmNvdW50ID0gdGhpcy5jb3VudCB8fCAwO1xuICAgIGlmICh0aGlzLmNvdW50ID49IDI1NiB8fCBybmdfcHB0ciA+PSBybmdfcHNpemUpIHtcbiAgICAgIGlmICh3aW5kb3cucmVtb3ZlRXZlbnRMaXN0ZW5lcilcbiAgICAgICAgd2luZG93LnJlbW92ZUV2ZW50TGlzdGVuZXIoXCJtb3VzZW1vdmVcIiwgb25Nb3VzZU1vdmVMaXN0ZW5lciwgZmFsc2UpO1xuICAgICAgZWxzZSBpZiAod2luZG93LmRldGFjaEV2ZW50KVxuICAgICAgICB3aW5kb3cuZGV0YWNoRXZlbnQoXCJvbm1vdXNlbW92ZVwiLCBvbk1vdXNlTW92ZUxpc3RlbmVyKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG4gICAgdHJ5IHtcbiAgICAgIHZhciBtb3VzZUNvb3JkaW5hdGVzID0gZXYueCArIGV2Lnk7XG4gICAgICBybmdfcG9vbFtybmdfcHB0cisrXSA9IG1vdXNlQ29vcmRpbmF0ZXMgJiAyNTU7XG4gICAgICB0aGlzLmNvdW50ICs9IDE7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgLy8gU29tZXRpbWVzIEZpcmVmb3ggd2lsbCBkZW55IHBlcm1pc3Npb24gdG8gYWNjZXNzIGV2ZW50IHByb3BlcnRpZXMgZm9yIHNvbWUgcmVhc29uLiBJZ25vcmUuXG4gICAgfVxuICB9O1xuICBpZiAod2luZG93LmFkZEV2ZW50TGlzdGVuZXIpXG4gICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoXCJtb3VzZW1vdmVcIiwgb25Nb3VzZU1vdmVMaXN0ZW5lciwgZmFsc2UpO1xuICBlbHNlIGlmICh3aW5kb3cuYXR0YWNoRXZlbnQpXG4gICAgd2luZG93LmF0dGFjaEV2ZW50KFwib25tb3VzZW1vdmVcIiwgb25Nb3VzZU1vdmVMaXN0ZW5lcik7XG5cbn1cblxuZnVuY3Rpb24gcm5nX2dldF9ieXRlKCkge1xuICBpZihybmdfc3RhdGUgPT0gbnVsbCkge1xuICAgIHJuZ19zdGF0ZSA9IHBybmdfbmV3c3RhdGUoKTtcbiAgICAvLyBBdCB0aGlzIHBvaW50LCB3ZSBtYXkgbm90IGhhdmUgY29sbGVjdGVkIGVub3VnaCBlbnRyb3B5LiAgSWYgbm90LCBmYWxsIGJhY2sgdG8gTWF0aC5yYW5kb21cbiAgICB3aGlsZSAocm5nX3BwdHIgPCBybmdfcHNpemUpIHtcbiAgICAgIHZhciByYW5kb20gPSBNYXRoLmZsb29yKDY1NTM2ICogTWF0aC5yYW5kb20oKSk7XG4gICAgICBybmdfcG9vbFtybmdfcHB0cisrXSA9IHJhbmRvbSAmIDI1NTtcbiAgICB9XG4gICAgcm5nX3N0YXRlLmluaXQocm5nX3Bvb2wpO1xuICAgIGZvcihybmdfcHB0ciA9IDA7IHJuZ19wcHRyIDwgcm5nX3Bvb2wubGVuZ3RoOyArK3JuZ19wcHRyKVxuICAgICAgcm5nX3Bvb2xbcm5nX3BwdHJdID0gMDtcbiAgICBybmdfcHB0ciA9IDA7XG4gIH1cbiAgLy8gVE9ETzogYWxsb3cgcmVzZWVkaW5nIGFmdGVyIGZpcnN0IHJlcXVlc3RcbiAgcmV0dXJuIHJuZ19zdGF0ZS5uZXh0KCk7XG59XG5cbmZ1bmN0aW9uIHJuZ19nZXRfYnl0ZXMoYmEpIHtcbiAgdmFyIGk7XG4gIGZvcihpID0gMDsgaSA8IGJhLmxlbmd0aDsgKytpKSBiYVtpXSA9IHJuZ19nZXRfYnl0ZSgpO1xufVxuXG5mdW5jdGlvbiBTZWN1cmVSYW5kb20oKSB7fVxuXG5TZWN1cmVSYW5kb20ucHJvdG90eXBlLm5leHRCeXRlcyA9IHJuZ19nZXRfYnl0ZXM7XG5cbi8vIERlcGVuZHMgb24ganNibi5qcyBhbmQgcm5nLmpzXG5cbi8vIFZlcnNpb24gMS4xOiBzdXBwb3J0IHV0Zi04IGVuY29kaW5nIGluIHBrY3MxcGFkMlxuXG4vLyBjb252ZXJ0IGEgKGhleCkgc3RyaW5nIHRvIGEgYmlnbnVtIG9iamVjdFxuZnVuY3Rpb24gcGFyc2VCaWdJbnQoc3RyLHIpIHtcbiAgcmV0dXJuIG5ldyBCaWdJbnRlZ2VyKHN0cixyKTtcbn1cblxuZnVuY3Rpb24gbGluZWJyayhzLG4pIHtcbiAgdmFyIHJldCA9IFwiXCI7XG4gIHZhciBpID0gMDtcbiAgd2hpbGUoaSArIG4gPCBzLmxlbmd0aCkge1xuICAgIHJldCArPSBzLnN1YnN0cmluZyhpLGkrbikgKyBcIlxcblwiO1xuICAgIGkgKz0gbjtcbiAgfVxuICByZXR1cm4gcmV0ICsgcy5zdWJzdHJpbmcoaSxzLmxlbmd0aCk7XG59XG5cbmZ1bmN0aW9uIGJ5dGUySGV4KGIpIHtcbiAgaWYoYiA8IDB4MTApXG4gICAgcmV0dXJuIFwiMFwiICsgYi50b1N0cmluZygxNik7XG4gIGVsc2VcbiAgICByZXR1cm4gYi50b1N0cmluZygxNik7XG59XG5cbi8vIFBLQ1MjMSAodHlwZSAyLCByYW5kb20pIHBhZCBpbnB1dCBzdHJpbmcgcyB0byBuIGJ5dGVzLCBhbmQgcmV0dXJuIGEgYmlnaW50XG5mdW5jdGlvbiBwa2NzMXBhZDIocyxuKSB7XG4gIGlmKG4gPCBzLmxlbmd0aCArIDExKSB7IC8vIFRPRE86IGZpeCBmb3IgdXRmLThcbiAgICBjb25zb2xlLmVycm9yKFwiTWVzc2FnZSB0b28gbG9uZyBmb3IgUlNBXCIpO1xuICAgIHJldHVybiBudWxsO1xuICB9XG4gIHZhciBiYSA9IG5ldyBBcnJheSgpO1xuICB2YXIgaSA9IHMubGVuZ3RoIC0gMTtcbiAgd2hpbGUoaSA+PSAwICYmIG4gPiAwKSB7XG4gICAgdmFyIGMgPSBzLmNoYXJDb2RlQXQoaS0tKTtcbiAgICBpZihjIDwgMTI4KSB7IC8vIGVuY29kZSB1c2luZyB1dGYtOFxuICAgICAgYmFbLS1uXSA9IGM7XG4gICAgfVxuICAgIGVsc2UgaWYoKGMgPiAxMjcpICYmIChjIDwgMjA0OCkpIHtcbiAgICAgIGJhWy0tbl0gPSAoYyAmIDYzKSB8IDEyODtcbiAgICAgIGJhWy0tbl0gPSAoYyA+PiA2KSB8IDE5MjtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICBiYVstLW5dID0gKGMgJiA2MykgfCAxMjg7XG4gICAgICBiYVstLW5dID0gKChjID4+IDYpICYgNjMpIHwgMTI4O1xuICAgICAgYmFbLS1uXSA9IChjID4+IDEyKSB8IDIyNDtcbiAgICB9XG4gIH1cbiAgYmFbLS1uXSA9IDA7XG4gIHZhciBybmcgPSBuZXcgU2VjdXJlUmFuZG9tKCk7XG4gIHZhciB4ID0gbmV3IEFycmF5KCk7XG4gIHdoaWxlKG4gPiAyKSB7IC8vIHJhbmRvbSBub24temVybyBwYWRcbiAgICB4WzBdID0gMDtcbiAgICB3aGlsZSh4WzBdID09IDApIHJuZy5uZXh0Qnl0ZXMoeCk7XG4gICAgYmFbLS1uXSA9IHhbMF07XG4gIH1cbiAgYmFbLS1uXSA9IDI7XG4gIGJhWy0tbl0gPSAwO1xuICByZXR1cm4gbmV3IEJpZ0ludGVnZXIoYmEpO1xufVxuXG4vLyBcImVtcHR5XCIgUlNBIGtleSBjb25zdHJ1Y3RvclxuZnVuY3Rpb24gUlNBS2V5KCkge1xuICB0aGlzLm4gPSBudWxsO1xuICB0aGlzLmUgPSAwO1xuICB0aGlzLmQgPSBudWxsO1xuICB0aGlzLnAgPSBudWxsO1xuICB0aGlzLnEgPSBudWxsO1xuICB0aGlzLmRtcDEgPSBudWxsO1xuICB0aGlzLmRtcTEgPSBudWxsO1xuICB0aGlzLmNvZWZmID0gbnVsbDtcbn1cblxuLy8gU2V0IHRoZSBwdWJsaWMga2V5IGZpZWxkcyBOIGFuZCBlIGZyb20gaGV4IHN0cmluZ3NcbmZ1bmN0aW9uIFJTQVNldFB1YmxpYyhOLEUpIHtcbiAgaWYoTiAhPSBudWxsICYmIEUgIT0gbnVsbCAmJiBOLmxlbmd0aCA+IDAgJiYgRS5sZW5ndGggPiAwKSB7XG4gICAgdGhpcy5uID0gcGFyc2VCaWdJbnQoTiwxNik7XG4gICAgdGhpcy5lID0gcGFyc2VJbnQoRSwxNik7XG4gIH1cbiAgZWxzZVxuICAgIGNvbnNvbGUuZXJyb3IoXCJJbnZhbGlkIFJTQSBwdWJsaWMga2V5XCIpO1xufVxuXG4vLyBQZXJmb3JtIHJhdyBwdWJsaWMgb3BlcmF0aW9uIG9uIFwieFwiOiByZXR1cm4geF5lIChtb2QgbilcbmZ1bmN0aW9uIFJTQURvUHVibGljKHgpIHtcbiAgcmV0dXJuIHgubW9kUG93SW50KHRoaXMuZSwgdGhpcy5uKTtcbn1cblxuLy8gUmV0dXJuIHRoZSBQS0NTIzEgUlNBIGVuY3J5cHRpb24gb2YgXCJ0ZXh0XCIgYXMgYW4gZXZlbi1sZW5ndGggaGV4IHN0cmluZ1xuZnVuY3Rpb24gUlNBRW5jcnlwdCh0ZXh0KSB7XG4gIHZhciBtID0gcGtjczFwYWQyKHRleHQsKHRoaXMubi5iaXRMZW5ndGgoKSs3KT4+Myk7XG4gIGlmKG0gPT0gbnVsbCkgcmV0dXJuIG51bGw7XG4gIHZhciBjID0gdGhpcy5kb1B1YmxpYyhtKTtcbiAgaWYoYyA9PSBudWxsKSByZXR1cm4gbnVsbDtcbiAgdmFyIGggPSBjLnRvU3RyaW5nKDE2KTtcbiAgaWYoKGgubGVuZ3RoICYgMSkgPT0gMCkgcmV0dXJuIGg7IGVsc2UgcmV0dXJuIFwiMFwiICsgaDtcbn1cblxuLy8gUmV0dXJuIHRoZSBQS0NTIzEgUlNBIGVuY3J5cHRpb24gb2YgXCJ0ZXh0XCIgYXMgYSBCYXNlNjQtZW5jb2RlZCBzdHJpbmdcbi8vZnVuY3Rpb24gUlNBRW5jcnlwdEI2NCh0ZXh0KSB7XG4vLyAgdmFyIGggPSB0aGlzLmVuY3J5cHQodGV4dCk7XG4vLyAgaWYoaCkgcmV0dXJuIGhleDJiNjQoaCk7IGVsc2UgcmV0dXJuIG51bGw7XG4vL31cblxuLy8gcHJvdGVjdGVkXG5SU0FLZXkucHJvdG90eXBlLmRvUHVibGljID0gUlNBRG9QdWJsaWM7XG5cbi8vIHB1YmxpY1xuUlNBS2V5LnByb3RvdHlwZS5zZXRQdWJsaWMgPSBSU0FTZXRQdWJsaWM7XG5SU0FLZXkucHJvdG90eXBlLmVuY3J5cHQgPSBSU0FFbmNyeXB0O1xuLy9SU0FLZXkucHJvdG90eXBlLmVuY3J5cHRfYjY0ID0gUlNBRW5jcnlwdEI2NDtcblxuLy8gRGVwZW5kcyBvbiByc2EuanMgYW5kIGpzYm4yLmpzXG5cbi8vIFZlcnNpb24gMS4xOiBzdXBwb3J0IHV0Zi04IGRlY29kaW5nIGluIHBrY3MxdW5wYWQyXG5cbi8vIFVuZG8gUEtDUyMxICh0eXBlIDIsIHJhbmRvbSkgcGFkZGluZyBhbmQsIGlmIHZhbGlkLCByZXR1cm4gdGhlIHBsYWludGV4dFxuZnVuY3Rpb24gcGtjczF1bnBhZDIoZCxuKSB7XG4gIHZhciBiID0gZC50b0J5dGVBcnJheSgpO1xuICB2YXIgaSA9IDA7XG4gIHdoaWxlKGkgPCBiLmxlbmd0aCAmJiBiW2ldID09IDApICsraTtcbiAgaWYoYi5sZW5ndGgtaSAhPSBuLTEgfHwgYltpXSAhPSAyKVxuICAgIHJldHVybiBudWxsO1xuICArK2k7XG4gIHdoaWxlKGJbaV0gIT0gMClcbiAgICBpZigrK2kgPj0gYi5sZW5ndGgpIHJldHVybiBudWxsO1xuICB2YXIgcmV0ID0gXCJcIjtcbiAgd2hpbGUoKytpIDwgYi5sZW5ndGgpIHtcbiAgICB2YXIgYyA9IGJbaV0gJiAyNTU7XG4gICAgaWYoYyA8IDEyOCkgeyAvLyB1dGYtOCBkZWNvZGVcbiAgICAgIHJldCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKGMpO1xuICAgIH1cbiAgICBlbHNlIGlmKChjID4gMTkxKSAmJiAoYyA8IDIyNCkpIHtcbiAgICAgIHJldCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKCgoYyAmIDMxKSA8PCA2KSB8IChiW2krMV0gJiA2MykpO1xuICAgICAgKytpO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgIHJldCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKCgoYyAmIDE1KSA8PCAxMikgfCAoKGJbaSsxXSAmIDYzKSA8PCA2KSB8IChiW2krMl0gJiA2MykpO1xuICAgICAgaSArPSAyO1xuICAgIH1cbiAgfVxuICByZXR1cm4gcmV0O1xufVxuXG4vLyBTZXQgdGhlIHByaXZhdGUga2V5IGZpZWxkcyBOLCBlLCBhbmQgZCBmcm9tIGhleCBzdHJpbmdzXG5mdW5jdGlvbiBSU0FTZXRQcml2YXRlKE4sRSxEKSB7XG4gIGlmKE4gIT0gbnVsbCAmJiBFICE9IG51bGwgJiYgTi5sZW5ndGggPiAwICYmIEUubGVuZ3RoID4gMCkge1xuICAgIHRoaXMubiA9IHBhcnNlQmlnSW50KE4sMTYpO1xuICAgIHRoaXMuZSA9IHBhcnNlSW50KEUsMTYpO1xuICAgIHRoaXMuZCA9IHBhcnNlQmlnSW50KEQsMTYpO1xuICB9XG4gIGVsc2VcbiAgICBjb25zb2xlLmVycm9yKFwiSW52YWxpZCBSU0EgcHJpdmF0ZSBrZXlcIik7XG59XG5cbi8vIFNldCB0aGUgcHJpdmF0ZSBrZXkgZmllbGRzIE4sIGUsIGQgYW5kIENSVCBwYXJhbXMgZnJvbSBoZXggc3RyaW5nc1xuZnVuY3Rpb24gUlNBU2V0UHJpdmF0ZUV4KE4sRSxELFAsUSxEUCxEUSxDKSB7XG4gIGlmKE4gIT0gbnVsbCAmJiBFICE9IG51bGwgJiYgTi5sZW5ndGggPiAwICYmIEUubGVuZ3RoID4gMCkge1xuICAgIHRoaXMubiA9IHBhcnNlQmlnSW50KE4sMTYpO1xuICAgIHRoaXMuZSA9IHBhcnNlSW50KEUsMTYpO1xuICAgIHRoaXMuZCA9IHBhcnNlQmlnSW50KEQsMTYpO1xuICAgIHRoaXMucCA9IHBhcnNlQmlnSW50KFAsMTYpO1xuICAgIHRoaXMucSA9IHBhcnNlQmlnSW50KFEsMTYpO1xuICAgIHRoaXMuZG1wMSA9IHBhcnNlQmlnSW50KERQLDE2KTtcbiAgICB0aGlzLmRtcTEgPSBwYXJzZUJpZ0ludChEUSwxNik7XG4gICAgdGhpcy5jb2VmZiA9IHBhcnNlQmlnSW50KEMsMTYpO1xuICB9XG4gIGVsc2VcbiAgICBjb25zb2xlLmVycm9yKFwiSW52YWxpZCBSU0EgcHJpdmF0ZSBrZXlcIik7XG59XG5cbi8vIEdlbmVyYXRlIGEgbmV3IHJhbmRvbSBwcml2YXRlIGtleSBCIGJpdHMgbG9uZywgdXNpbmcgcHVibGljIGV4cHQgRVxuZnVuY3Rpb24gUlNBR2VuZXJhdGUoQixFKSB7XG4gIHZhciBybmcgPSBuZXcgU2VjdXJlUmFuZG9tKCk7XG4gIHZhciBxcyA9IEI+PjE7XG4gIHRoaXMuZSA9IHBhcnNlSW50KEUsMTYpO1xuICB2YXIgZWUgPSBuZXcgQmlnSW50ZWdlcihFLDE2KTtcbiAgZm9yKDs7KSB7XG4gICAgZm9yKDs7KSB7XG4gICAgICB0aGlzLnAgPSBuZXcgQmlnSW50ZWdlcihCLXFzLDEscm5nKTtcbiAgICAgIGlmKHRoaXMucC5zdWJ0cmFjdChCaWdJbnRlZ2VyLk9ORSkuZ2NkKGVlKS5jb21wYXJlVG8oQmlnSW50ZWdlci5PTkUpID09IDAgJiYgdGhpcy5wLmlzUHJvYmFibGVQcmltZSgxMCkpIGJyZWFrO1xuICAgIH1cbiAgICBmb3IoOzspIHtcbiAgICAgIHRoaXMucSA9IG5ldyBCaWdJbnRlZ2VyKHFzLDEscm5nKTtcbiAgICAgIGlmKHRoaXMucS5zdWJ0cmFjdChCaWdJbnRlZ2VyLk9ORSkuZ2NkKGVlKS5jb21wYXJlVG8oQmlnSW50ZWdlci5PTkUpID09IDAgJiYgdGhpcy5xLmlzUHJvYmFibGVQcmltZSgxMCkpIGJyZWFrO1xuICAgIH1cbiAgICBpZih0aGlzLnAuY29tcGFyZVRvKHRoaXMucSkgPD0gMCkge1xuICAgICAgdmFyIHQgPSB0aGlzLnA7XG4gICAgICB0aGlzLnAgPSB0aGlzLnE7XG4gICAgICB0aGlzLnEgPSB0O1xuICAgIH1cbiAgICB2YXIgcDEgPSB0aGlzLnAuc3VidHJhY3QoQmlnSW50ZWdlci5PTkUpO1xuICAgIHZhciBxMSA9IHRoaXMucS5zdWJ0cmFjdChCaWdJbnRlZ2VyLk9ORSk7XG4gICAgdmFyIHBoaSA9IHAxLm11bHRpcGx5KHExKTtcbiAgICBpZihwaGkuZ2NkKGVlKS5jb21wYXJlVG8oQmlnSW50ZWdlci5PTkUpID09IDApIHtcbiAgICAgIHRoaXMubiA9IHRoaXMucC5tdWx0aXBseSh0aGlzLnEpO1xuICAgICAgdGhpcy5kID0gZWUubW9kSW52ZXJzZShwaGkpO1xuICAgICAgdGhpcy5kbXAxID0gdGhpcy5kLm1vZChwMSk7XG4gICAgICB0aGlzLmRtcTEgPSB0aGlzLmQubW9kKHExKTtcbiAgICAgIHRoaXMuY29lZmYgPSB0aGlzLnEubW9kSW52ZXJzZSh0aGlzLnApO1xuICAgICAgYnJlYWs7XG4gICAgfVxuICB9XG59XG5cbi8vIFBlcmZvcm0gcmF3IHByaXZhdGUgb3BlcmF0aW9uIG9uIFwieFwiOiByZXR1cm4geF5kIChtb2QgbilcbmZ1bmN0aW9uIFJTQURvUHJpdmF0ZSh4KSB7XG4gIGlmKHRoaXMucCA9PSBudWxsIHx8IHRoaXMucSA9PSBudWxsKVxuICAgIHJldHVybiB4Lm1vZFBvdyh0aGlzLmQsIHRoaXMubik7XG5cbiAgLy8gVE9ETzogcmUtY2FsY3VsYXRlIGFueSBtaXNzaW5nIENSVCBwYXJhbXNcbiAgdmFyIHhwID0geC5tb2QodGhpcy5wKS5tb2RQb3codGhpcy5kbXAxLCB0aGlzLnApO1xuICB2YXIgeHEgPSB4Lm1vZCh0aGlzLnEpLm1vZFBvdyh0aGlzLmRtcTEsIHRoaXMucSk7XG5cbiAgd2hpbGUoeHAuY29tcGFyZVRvKHhxKSA8IDApXG4gICAgeHAgPSB4cC5hZGQodGhpcy5wKTtcbiAgcmV0dXJuIHhwLnN1YnRyYWN0KHhxKS5tdWx0aXBseSh0aGlzLmNvZWZmKS5tb2QodGhpcy5wKS5tdWx0aXBseSh0aGlzLnEpLmFkZCh4cSk7XG59XG5cbi8vIFJldHVybiB0aGUgUEtDUyMxIFJTQSBkZWNyeXB0aW9uIG9mIFwiY3RleHRcIi5cbi8vIFwiY3RleHRcIiBpcyBhbiBldmVuLWxlbmd0aCBoZXggc3RyaW5nIGFuZCB0aGUgb3V0cHV0IGlzIGEgcGxhaW4gc3RyaW5nLlxuZnVuY3Rpb24gUlNBRGVjcnlwdChjdGV4dCkge1xuICB2YXIgYyA9IHBhcnNlQmlnSW50KGN0ZXh0LCAxNik7XG4gIHZhciBtID0gdGhpcy5kb1ByaXZhdGUoYyk7XG4gIGlmKG0gPT0gbnVsbCkgcmV0dXJuIG51bGw7XG4gIHJldHVybiBwa2NzMXVucGFkMihtLCAodGhpcy5uLmJpdExlbmd0aCgpKzcpPj4zKTtcbn1cblxuLy8gUmV0dXJuIHRoZSBQS0NTIzEgUlNBIGRlY3J5cHRpb24gb2YgXCJjdGV4dFwiLlxuLy8gXCJjdGV4dFwiIGlzIGEgQmFzZTY0LWVuY29kZWQgc3RyaW5nIGFuZCB0aGUgb3V0cHV0IGlzIGEgcGxhaW4gc3RyaW5nLlxuLy9mdW5jdGlvbiBSU0FCNjREZWNyeXB0KGN0ZXh0KSB7XG4vLyAgdmFyIGggPSBiNjR0b2hleChjdGV4dCk7XG4vLyAgaWYoaCkgcmV0dXJuIHRoaXMuZGVjcnlwdChoKTsgZWxzZSByZXR1cm4gbnVsbDtcbi8vfVxuXG4vLyBwcm90ZWN0ZWRcblJTQUtleS5wcm90b3R5cGUuZG9Qcml2YXRlID0gUlNBRG9Qcml2YXRlO1xuXG4vLyBwdWJsaWNcblJTQUtleS5wcm90b3R5cGUuc2V0UHJpdmF0ZSA9IFJTQVNldFByaXZhdGU7XG5SU0FLZXkucHJvdG90eXBlLnNldFByaXZhdGVFeCA9IFJTQVNldFByaXZhdGVFeDtcblJTQUtleS5wcm90b3R5cGUuZ2VuZXJhdGUgPSBSU0FHZW5lcmF0ZTtcblJTQUtleS5wcm90b3R5cGUuZGVjcnlwdCA9IFJTQURlY3J5cHQ7XG4vL1JTQUtleS5wcm90b3R5cGUuYjY0X2RlY3J5cHQgPSBSU0FCNjREZWNyeXB0O1xuXG4vLyBDb3B5cmlnaHQgKGMpIDIwMTEgIEtldmluIE0gQnVybnMgSnIuXG4vLyBBbGwgUmlnaHRzIFJlc2VydmVkLlxuLy8gU2VlIFwiTElDRU5TRVwiIGZvciBkZXRhaWxzLlxuLy9cbi8vIEV4dGVuc2lvbiB0byBqc2JuIHdoaWNoIGFkZHMgZmFjaWxpdGllcyBmb3IgYXN5bmNocm9ub3VzIFJTQSBrZXkgZ2VuZXJhdGlvblxuLy8gUHJpbWFyaWx5IGNyZWF0ZWQgdG8gYXZvaWQgZXhlY3V0aW9uIHRpbWVvdXQgb24gbW9iaWxlIGRldmljZXNcbi8vXG4vLyBodHRwOi8vd3d3LWNzLXN0dWRlbnRzLnN0YW5mb3JkLmVkdS9+dGp3L2pzYm4vXG4vL1xuLy8gLS0tXG5cbihmdW5jdGlvbigpe1xuXG4vLyBHZW5lcmF0ZSBhIG5ldyByYW5kb20gcHJpdmF0ZSBrZXkgQiBiaXRzIGxvbmcsIHVzaW5nIHB1YmxpYyBleHB0IEVcbnZhciBSU0FHZW5lcmF0ZUFzeW5jID0gZnVuY3Rpb24gKEIsIEUsIGNhbGxiYWNrKSB7XG4gICAgLy92YXIgcm5nID0gbmV3IFNlZWRlZFJhbmRvbSgpO1xuICAgIHZhciBybmcgPSBuZXcgU2VjdXJlUmFuZG9tKCk7XG4gICAgdmFyIHFzID0gQiA+PiAxO1xuICAgIHRoaXMuZSA9IHBhcnNlSW50KEUsIDE2KTtcbiAgICB2YXIgZWUgPSBuZXcgQmlnSW50ZWdlcihFLCAxNik7XG4gICAgdmFyIHJzYSA9IHRoaXM7XG4gICAgLy8gVGhlc2UgZnVuY3Rpb25zIGhhdmUgbm9uLWRlc2NyaXB0IG5hbWVzIGJlY2F1c2UgdGhleSB3ZXJlIG9yaWdpbmFsbHkgZm9yKDs7KSBsb29wcy5cbiAgICAvLyBJIGRvbid0IGtub3cgYWJvdXQgY3J5cHRvZ3JhcGh5IHRvIGdpdmUgdGhlbSBiZXR0ZXIgbmFtZXMgdGhhbiBsb29wMS00LlxuICAgIHZhciBsb29wMSA9IGZ1bmN0aW9uKCkge1xuICAgICAgICB2YXIgbG9vcDQgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIGlmIChyc2EucC5jb21wYXJlVG8ocnNhLnEpIDw9IDApIHtcbiAgICAgICAgICAgICAgICB2YXIgdCA9IHJzYS5wO1xuICAgICAgICAgICAgICAgIHJzYS5wID0gcnNhLnE7XG4gICAgICAgICAgICAgICAgcnNhLnEgPSB0O1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgdmFyIHAxID0gcnNhLnAuc3VidHJhY3QoQmlnSW50ZWdlci5PTkUpO1xuICAgICAgICAgICAgdmFyIHExID0gcnNhLnEuc3VidHJhY3QoQmlnSW50ZWdlci5PTkUpO1xuICAgICAgICAgICAgdmFyIHBoaSA9IHAxLm11bHRpcGx5KHExKTtcbiAgICAgICAgICAgIGlmIChwaGkuZ2NkKGVlKS5jb21wYXJlVG8oQmlnSW50ZWdlci5PTkUpID09IDApIHtcbiAgICAgICAgICAgICAgICByc2EubiA9IHJzYS5wLm11bHRpcGx5KHJzYS5xKTtcbiAgICAgICAgICAgICAgICByc2EuZCA9IGVlLm1vZEludmVyc2UocGhpKTtcbiAgICAgICAgICAgICAgICByc2EuZG1wMSA9IHJzYS5kLm1vZChwMSk7XG4gICAgICAgICAgICAgICAgcnNhLmRtcTEgPSByc2EuZC5tb2QocTEpO1xuICAgICAgICAgICAgICAgIHJzYS5jb2VmZiA9IHJzYS5xLm1vZEludmVyc2UocnNhLnApO1xuICAgICAgICAgICAgICAgIHNldFRpbWVvdXQoZnVuY3Rpb24oKXtjYWxsYmFjaygpfSwwKTsgLy8gZXNjYXBlXG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIHNldFRpbWVvdXQobG9vcDEsMCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH07XG4gICAgICAgIHZhciBsb29wMyA9IGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgcnNhLnEgPSBuYmkoKTtcbiAgICAgICAgICAgIHJzYS5xLmZyb21OdW1iZXJBc3luYyhxcywgMSwgcm5nLCBmdW5jdGlvbigpe1xuICAgICAgICAgICAgICAgIHJzYS5xLnN1YnRyYWN0KEJpZ0ludGVnZXIuT05FKS5nY2RhKGVlLCBmdW5jdGlvbihyKXtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHIuY29tcGFyZVRvKEJpZ0ludGVnZXIuT05FKSA9PSAwICYmIHJzYS5xLmlzUHJvYmFibGVQcmltZSgxMCkpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHNldFRpbWVvdXQobG9vcDQsMCk7XG4gICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBzZXRUaW1lb3V0KGxvb3AzLDApO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfTtcbiAgICAgICAgdmFyIGxvb3AyID0gZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICByc2EucCA9IG5iaSgpO1xuICAgICAgICAgICAgcnNhLnAuZnJvbU51bWJlckFzeW5jKEIgLSBxcywgMSwgcm5nLCBmdW5jdGlvbigpe1xuICAgICAgICAgICAgICAgIHJzYS5wLnN1YnRyYWN0KEJpZ0ludGVnZXIuT05FKS5nY2RhKGVlLCBmdW5jdGlvbihyKXtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHIuY29tcGFyZVRvKEJpZ0ludGVnZXIuT05FKSA9PSAwICYmIHJzYS5wLmlzUHJvYmFibGVQcmltZSgxMCkpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHNldFRpbWVvdXQobG9vcDMsMCk7XG4gICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBzZXRUaW1lb3V0KGxvb3AyLDApO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfTtcbiAgICAgICAgc2V0VGltZW91dChsb29wMiwwKTtcbiAgICB9O1xuICAgIHNldFRpbWVvdXQobG9vcDEsMCk7XG59O1xuUlNBS2V5LnByb3RvdHlwZS5nZW5lcmF0ZUFzeW5jID0gUlNBR2VuZXJhdGVBc3luYztcblxuLy8gUHVibGljIEFQSSBtZXRob2RcbnZhciBibkdDREFzeW5jID0gZnVuY3Rpb24gKGEsIGNhbGxiYWNrKSB7XG4gICAgdmFyIHggPSAodGhpcy5zIDwgMCkgPyB0aGlzLm5lZ2F0ZSgpIDogdGhpcy5jbG9uZSgpO1xuICAgIHZhciB5ID0gKGEucyA8IDApID8gYS5uZWdhdGUoKSA6IGEuY2xvbmUoKTtcbiAgICBpZiAoeC5jb21wYXJlVG8oeSkgPCAwKSB7XG4gICAgICAgIHZhciB0ID0geDtcbiAgICAgICAgeCA9IHk7XG4gICAgICAgIHkgPSB0O1xuICAgIH1cbiAgICB2YXIgaSA9IHguZ2V0TG93ZXN0U2V0Qml0KCksXG4gICAgICAgIGcgPSB5LmdldExvd2VzdFNldEJpdCgpO1xuICAgIGlmIChnIDwgMCkge1xuICAgICAgICBjYWxsYmFjayh4KTtcbiAgICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBpZiAoaSA8IGcpIGcgPSBpO1xuICAgIGlmIChnID4gMCkge1xuICAgICAgICB4LnJTaGlmdFRvKGcsIHgpO1xuICAgICAgICB5LnJTaGlmdFRvKGcsIHkpO1xuICAgIH1cbiAgICAvLyBXb3JraG9yc2Ugb2YgdGhlIGFsZ29yaXRobSwgZ2V0cyBjYWxsZWQgMjAwIC0gODAwIHRpbWVzIHBlciA1MTIgYml0IGtleWdlbi5cbiAgICB2YXIgZ2NkYTEgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgaWYgKChpID0geC5nZXRMb3dlc3RTZXRCaXQoKSkgPiAwKXsgeC5yU2hpZnRUbyhpLCB4KTsgfVxuICAgICAgICBpZiAoKGkgPSB5LmdldExvd2VzdFNldEJpdCgpKSA+IDApeyB5LnJTaGlmdFRvKGksIHkpOyB9XG4gICAgICAgIGlmICh4LmNvbXBhcmVUbyh5KSA+PSAwKSB7XG4gICAgICAgICAgICB4LnN1YlRvKHksIHgpO1xuICAgICAgICAgICAgeC5yU2hpZnRUbygxLCB4KTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHkuc3ViVG8oeCwgeSk7XG4gICAgICAgICAgICB5LnJTaGlmdFRvKDEsIHkpO1xuICAgICAgICB9XG4gICAgICAgIGlmKCEoeC5zaWdudW0oKSA+IDApKSB7XG4gICAgICAgICAgICBpZiAoZyA+IDApIHkubFNoaWZ0VG8oZywgeSk7XG4gICAgICAgICAgICBzZXRUaW1lb3V0KGZ1bmN0aW9uKCl7Y2FsbGJhY2soeSl9LDApOyAvLyBlc2NhcGVcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHNldFRpbWVvdXQoZ2NkYTEsMCk7XG4gICAgICAgIH1cbiAgICB9O1xuICAgIHNldFRpbWVvdXQoZ2NkYTEsMTApO1xufTtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmdjZGEgPSBibkdDREFzeW5jO1xuXG4vLyAocHJvdGVjdGVkKSBhbHRlcm5hdGUgY29uc3RydWN0b3JcbnZhciBibnBGcm9tTnVtYmVyQXN5bmMgPSBmdW5jdGlvbiAoYSxiLGMsY2FsbGJhY2spIHtcbiAgaWYoXCJudW1iZXJcIiA9PSB0eXBlb2YgYikge1xuICAgIGlmKGEgPCAyKSB7XG4gICAgICAgIHRoaXMuZnJvbUludCgxKTtcbiAgICB9IGVsc2Uge1xuICAgICAgdGhpcy5mcm9tTnVtYmVyKGEsYyk7XG4gICAgICBpZighdGhpcy50ZXN0Qml0KGEtMSkpe1xuICAgICAgICB0aGlzLmJpdHdpc2VUbyhCaWdJbnRlZ2VyLk9ORS5zaGlmdExlZnQoYS0xKSxvcF9vcix0aGlzKTtcbiAgICAgIH1cbiAgICAgIGlmKHRoaXMuaXNFdmVuKCkpIHtcbiAgICAgICAgdGhpcy5kQWRkT2Zmc2V0KDEsMCk7XG4gICAgICB9XG4gICAgICB2YXIgYm5wID0gdGhpcztcbiAgICAgIHZhciBibnBmbjEgPSBmdW5jdGlvbigpe1xuICAgICAgICBibnAuZEFkZE9mZnNldCgyLDApO1xuICAgICAgICBpZihibnAuYml0TGVuZ3RoKCkgPiBhKSBibnAuc3ViVG8oQmlnSW50ZWdlci5PTkUuc2hpZnRMZWZ0KGEtMSksYm5wKTtcbiAgICAgICAgaWYoYm5wLmlzUHJvYmFibGVQcmltZShiKSkge1xuICAgICAgICAgICAgc2V0VGltZW91dChmdW5jdGlvbigpe2NhbGxiYWNrKCl9LDApOyAvLyBlc2NhcGVcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHNldFRpbWVvdXQoYm5wZm4xLDApO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgICAgc2V0VGltZW91dChibnBmbjEsMCk7XG4gICAgfVxuICB9IGVsc2Uge1xuICAgIHZhciB4ID0gbmV3IEFycmF5KCksIHQgPSBhJjc7XG4gICAgeC5sZW5ndGggPSAoYT4+MykrMTtcbiAgICBiLm5leHRCeXRlcyh4KTtcbiAgICBpZih0ID4gMCkgeFswXSAmPSAoKDE8PHQpLTEpOyBlbHNlIHhbMF0gPSAwO1xuICAgIHRoaXMuZnJvbVN0cmluZyh4LDI1Nik7XG4gIH1cbn07XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5mcm9tTnVtYmVyQXN5bmMgPSBibnBGcm9tTnVtYmVyQXN5bmM7XG5cbn0pKCk7XG52YXIgYjY0bWFwPVwiQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODkrL1wiO1xudmFyIGI2NHBhZD1cIj1cIjtcblxuZnVuY3Rpb24gaGV4MmI2NChoKSB7XG4gIHZhciBpO1xuICB2YXIgYztcbiAgdmFyIHJldCA9IFwiXCI7XG4gIGZvcihpID0gMDsgaSszIDw9IGgubGVuZ3RoOyBpKz0zKSB7XG4gICAgYyA9IHBhcnNlSW50KGguc3Vic3RyaW5nKGksaSszKSwxNik7XG4gICAgcmV0ICs9IGI2NG1hcC5jaGFyQXQoYyA+PiA2KSArIGI2NG1hcC5jaGFyQXQoYyAmIDYzKTtcbiAgfVxuICBpZihpKzEgPT0gaC5sZW5ndGgpIHtcbiAgICBjID0gcGFyc2VJbnQoaC5zdWJzdHJpbmcoaSxpKzEpLDE2KTtcbiAgICByZXQgKz0gYjY0bWFwLmNoYXJBdChjIDw8IDIpO1xuICB9XG4gIGVsc2UgaWYoaSsyID09IGgubGVuZ3RoKSB7XG4gICAgYyA9IHBhcnNlSW50KGguc3Vic3RyaW5nKGksaSsyKSwxNik7XG4gICAgcmV0ICs9IGI2NG1hcC5jaGFyQXQoYyA+PiAyKSArIGI2NG1hcC5jaGFyQXQoKGMgJiAzKSA8PCA0KTtcbiAgfVxuICB3aGlsZSgocmV0Lmxlbmd0aCAmIDMpID4gMCkgcmV0ICs9IGI2NHBhZDtcbiAgcmV0dXJuIHJldDtcbn1cblxuLy8gY29udmVydCBhIGJhc2U2NCBzdHJpbmcgdG8gaGV4XG5mdW5jdGlvbiBiNjR0b2hleChzKSB7XG4gIHZhciByZXQgPSBcIlwiXG4gIHZhciBpO1xuICB2YXIgayA9IDA7IC8vIGI2NCBzdGF0ZSwgMC0zXG4gIHZhciBzbG9wO1xuICBmb3IoaSA9IDA7IGkgPCBzLmxlbmd0aDsgKytpKSB7XG4gICAgaWYocy5jaGFyQXQoaSkgPT0gYjY0cGFkKSBicmVhaztcbiAgICB2ID0gYjY0bWFwLmluZGV4T2Yocy5jaGFyQXQoaSkpO1xuICAgIGlmKHYgPCAwKSBjb250aW51ZTtcbiAgICBpZihrID09IDApIHtcbiAgICAgIHJldCArPSBpbnQyY2hhcih2ID4+IDIpO1xuICAgICAgc2xvcCA9IHYgJiAzO1xuICAgICAgayA9IDE7XG4gICAgfVxuICAgIGVsc2UgaWYoayA9PSAxKSB7XG4gICAgICByZXQgKz0gaW50MmNoYXIoKHNsb3AgPDwgMikgfCAodiA+PiA0KSk7XG4gICAgICBzbG9wID0gdiAmIDB4ZjtcbiAgICAgIGsgPSAyO1xuICAgIH1cbiAgICBlbHNlIGlmKGsgPT0gMikge1xuICAgICAgcmV0ICs9IGludDJjaGFyKHNsb3ApO1xuICAgICAgcmV0ICs9IGludDJjaGFyKHYgPj4gMik7XG4gICAgICBzbG9wID0gdiAmIDM7XG4gICAgICBrID0gMztcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICByZXQgKz0gaW50MmNoYXIoKHNsb3AgPDwgMikgfCAodiA+PiA0KSk7XG4gICAgICByZXQgKz0gaW50MmNoYXIodiAmIDB4Zik7XG4gICAgICBrID0gMDtcbiAgICB9XG4gIH1cbiAgaWYoayA9PSAxKVxuICAgIHJldCArPSBpbnQyY2hhcihzbG9wIDw8IDIpO1xuICByZXR1cm4gcmV0O1xufVxuXG4vLyBjb252ZXJ0IGEgYmFzZTY0IHN0cmluZyB0byBhIGJ5dGUvbnVtYmVyIGFycmF5XG5mdW5jdGlvbiBiNjR0b0JBKHMpIHtcbiAgLy9waWdneWJhY2sgb24gYjY0dG9oZXggZm9yIG5vdywgb3B0aW1pemUgbGF0ZXJcbiAgdmFyIGggPSBiNjR0b2hleChzKTtcbiAgdmFyIGk7XG4gIHZhciBhID0gbmV3IEFycmF5KCk7XG4gIGZvcihpID0gMDsgMippIDwgaC5sZW5ndGg7ICsraSkge1xuICAgIGFbaV0gPSBwYXJzZUludChoLnN1YnN0cmluZygyKmksMippKzIpLDE2KTtcbiAgfVxuICByZXR1cm4gYTtcbn1cblxuLyohIGFzbjEtMS4wLjIuanMgKGMpIDIwMTMgS2VuamkgVXJ1c2hpbWEgfCBranVyLmdpdGh1Yi5jb20vanNyc2FzaWduL2xpY2Vuc2VcbiAqL1xuXG52YXIgSlNYID0gSlNYIHx8IHt9O1xuSlNYLmVudiA9IEpTWC5lbnYgfHwge307XG5cbnZhciBMID0gSlNYLCBPUCA9IE9iamVjdC5wcm90b3R5cGUsIEZVTkNUSU9OX1RPU1RSSU5HID0gJ1tvYmplY3QgRnVuY3Rpb25dJyxBREQgPSBbXCJ0b1N0cmluZ1wiLCBcInZhbHVlT2ZcIl07XG5cbkpTWC5lbnYucGFyc2VVQSA9IGZ1bmN0aW9uKGFnZW50KSB7XG5cbiAgICB2YXIgbnVtYmVyaWZ5ID0gZnVuY3Rpb24ocykge1xuICAgICAgICB2YXIgYyA9IDA7XG4gICAgICAgIHJldHVybiBwYXJzZUZsb2F0KHMucmVwbGFjZSgvXFwuL2csIGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgcmV0dXJuIChjKysgPT0gMSkgPyAnJyA6ICcuJztcbiAgICAgICAgfSkpO1xuICAgIH0sXG5cbiAgICBuYXYgPSBuYXZpZ2F0b3IsXG4gICAgbyA9IHtcbiAgICAgICAgaWU6IDAsXG4gICAgICAgIG9wZXJhOiAwLFxuICAgICAgICBnZWNrbzogMCxcbiAgICAgICAgd2Via2l0OiAwLFxuICAgICAgICBjaHJvbWU6IDAsXG4gICAgICAgIG1vYmlsZTogbnVsbCxcbiAgICAgICAgYWlyOiAwLFxuICAgICAgICBpcGFkOiAwLFxuICAgICAgICBpcGhvbmU6IDAsXG4gICAgICAgIGlwb2Q6IDAsXG4gICAgICAgIGlvczogbnVsbCxcbiAgICAgICAgYW5kcm9pZDogMCxcbiAgICAgICAgd2Vib3M6IDAsXG4gICAgICAgIGNhamE6IG5hdiAmJiBuYXYuY2FqYVZlcnNpb24sXG4gICAgICAgIHNlY3VyZTogZmFsc2UsXG4gICAgICAgIG9zOiBudWxsXG5cbiAgICB9LFxuXG4gICAgdWEgPSBhZ2VudCB8fCAobmF2aWdhdG9yICYmIG5hdmlnYXRvci51c2VyQWdlbnQpLFxuICAgIGxvYyA9IHdpbmRvdyAmJiB3aW5kb3cubG9jYXRpb24sXG4gICAgaHJlZiA9IGxvYyAmJiBsb2MuaHJlZixcbiAgICBtO1xuXG4gICAgby5zZWN1cmUgPSBocmVmICYmIChocmVmLnRvTG93ZXJDYXNlKCkuaW5kZXhPZihcImh0dHBzXCIpID09PSAwKTtcblxuICAgIGlmICh1YSkge1xuXG4gICAgICAgIGlmICgoL3dpbmRvd3N8d2luMzIvaSkudGVzdCh1YSkpIHtcbiAgICAgICAgICAgIG8ub3MgPSAnd2luZG93cyc7XG4gICAgICAgIH0gZWxzZSBpZiAoKC9tYWNpbnRvc2gvaSkudGVzdCh1YSkpIHtcbiAgICAgICAgICAgIG8ub3MgPSAnbWFjaW50b3NoJztcbiAgICAgICAgfSBlbHNlIGlmICgoL3JoaW5vL2kpLnRlc3QodWEpKSB7XG4gICAgICAgICAgICBvLm9zID0gJ3JoaW5vJztcbiAgICAgICAgfVxuICAgICAgICBpZiAoKC9LSFRNTC8pLnRlc3QodWEpKSB7XG4gICAgICAgICAgICBvLndlYmtpdCA9IDE7XG4gICAgICAgIH1cbiAgICAgICAgbSA9IHVhLm1hdGNoKC9BcHBsZVdlYktpdFxcLyhbXlxcc10qKS8pO1xuICAgICAgICBpZiAobSAmJiBtWzFdKSB7XG4gICAgICAgICAgICBvLndlYmtpdCA9IG51bWJlcmlmeShtWzFdKTtcbiAgICAgICAgICAgIGlmICgvIE1vYmlsZVxcLy8udGVzdCh1YSkpIHtcbiAgICAgICAgICAgICAgICBvLm1vYmlsZSA9ICdBcHBsZSc7IC8vIGlQaG9uZSBvciBpUG9kIFRvdWNoXG4gICAgICAgICAgICAgICAgbSA9IHVhLm1hdGNoKC9PUyAoW15cXHNdKikvKTtcbiAgICAgICAgICAgICAgICBpZiAobSAmJiBtWzFdKSB7XG4gICAgICAgICAgICAgICAgICAgIG0gPSBudW1iZXJpZnkobVsxXS5yZXBsYWNlKCdfJywgJy4nKSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIG8uaW9zID0gbTtcbiAgICAgICAgICAgICAgICBvLmlwYWQgPSBvLmlwb2QgPSBvLmlwaG9uZSA9IDA7XG4gICAgICAgICAgICAgICAgbSA9IHVhLm1hdGNoKC9pUGFkfGlQb2R8aVBob25lLyk7XG4gICAgICAgICAgICAgICAgaWYgKG0gJiYgbVswXSkge1xuICAgICAgICAgICAgICAgICAgICBvW21bMF0udG9Mb3dlckNhc2UoKV0gPSBvLmlvcztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIG0gPSB1YS5tYXRjaCgvTm9raWFOW15cXC9dKnxBbmRyb2lkIFxcZFxcLlxcZHx3ZWJPU1xcL1xcZFxcLlxcZC8pO1xuICAgICAgICAgICAgICAgIGlmIChtKSB7XG4gICAgICAgICAgICAgICAgICAgIG8ubW9iaWxlID0gbVswXTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKC93ZWJPUy8udGVzdCh1YSkpIHtcbiAgICAgICAgICAgICAgICAgICAgby5tb2JpbGUgPSAnV2ViT1MnO1xuICAgICAgICAgICAgICAgICAgICBtID0gdWEubWF0Y2goL3dlYk9TXFwvKFteXFxzXSopOy8pO1xuICAgICAgICAgICAgICAgICAgICBpZiAobSAmJiBtWzFdKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBvLndlYm9zID0gbnVtYmVyaWZ5KG1bMV0pO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICgvIEFuZHJvaWQvLnRlc3QodWEpKSB7XG4gICAgICAgICAgICAgICAgICAgIG8ubW9iaWxlID0gJ0FuZHJvaWQnO1xuICAgICAgICAgICAgICAgICAgICBtID0gdWEubWF0Y2goL0FuZHJvaWQgKFteXFxzXSopOy8pO1xuICAgICAgICAgICAgICAgICAgICBpZiAobSAmJiBtWzFdKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBvLmFuZHJvaWQgPSBudW1iZXJpZnkobVsxXSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBtID0gdWEubWF0Y2goL0Nocm9tZVxcLyhbXlxcc10qKS8pO1xuICAgICAgICAgICAgaWYgKG0gJiYgbVsxXSkge1xuICAgICAgICAgICAgICAgIG8uY2hyb21lID0gbnVtYmVyaWZ5KG1bMV0pOyAvLyBDaHJvbWVcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgbSA9IHVhLm1hdGNoKC9BZG9iZUFJUlxcLyhbXlxcc10qKS8pO1xuICAgICAgICAgICAgICAgIGlmIChtKSB7XG4gICAgICAgICAgICAgICAgICAgIG8uYWlyID0gbVswXTsgLy8gQWRvYmUgQUlSIDEuMCBvciBiZXR0ZXJcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgaWYgKCFvLndlYmtpdCkge1xuICAgICAgICAgICAgbSA9IHVhLm1hdGNoKC9PcGVyYVtcXHNcXC9dKFteXFxzXSopLyk7XG4gICAgICAgICAgICBpZiAobSAmJiBtWzFdKSB7XG4gICAgICAgICAgICAgICAgby5vcGVyYSA9IG51bWJlcmlmeShtWzFdKTtcbiAgICAgICAgICAgICAgICBtID0gdWEubWF0Y2goL1ZlcnNpb25cXC8oW15cXHNdKikvKTtcbiAgICAgICAgICAgICAgICBpZiAobSAmJiBtWzFdKSB7XG4gICAgICAgICAgICAgICAgICAgIG8ub3BlcmEgPSBudW1iZXJpZnkobVsxXSk7IC8vIG9wZXJhIDEwK1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBtID0gdWEubWF0Y2goL09wZXJhIE1pbmlbXjtdKi8pO1xuICAgICAgICAgICAgICAgIGlmIChtKSB7XG4gICAgICAgICAgICAgICAgICAgIG8ubW9iaWxlID0gbVswXTsgLy8gZXg6IE9wZXJhIE1pbmkvMi4wLjQ1MDkvMTMxNlxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0gZWxzZSB7IC8vIG5vdCBvcGVyYSBvciB3ZWJraXRcbiAgICAgICAgICAgICAgICBtID0gdWEubWF0Y2goL01TSUVcXHMoW147XSopLyk7XG4gICAgICAgICAgICAgICAgaWYgKG0gJiYgbVsxXSkge1xuICAgICAgICAgICAgICAgICAgICBvLmllID0gbnVtYmVyaWZ5KG1bMV0pO1xuICAgICAgICAgICAgICAgIH0gZWxzZSB7IC8vIG5vdCBvcGVyYSwgd2Via2l0LCBvciBpZVxuICAgICAgICAgICAgICAgICAgICBtID0gdWEubWF0Y2goL0dlY2tvXFwvKFteXFxzXSopLyk7XG4gICAgICAgICAgICAgICAgICAgIGlmIChtKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBvLmdlY2tvID0gMTsgLy8gR2Vja28gZGV0ZWN0ZWQsIGxvb2sgZm9yIHJldmlzaW9uXG4gICAgICAgICAgICAgICAgICAgICAgICBtID0gdWEubWF0Y2goL3J2OihbXlxcc1xcKV0qKS8pO1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKG0gJiYgbVsxXSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG8uZ2Vja28gPSBudW1iZXJpZnkobVsxXSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIG87XG59O1xuXG5KU1guZW52LnVhID0gSlNYLmVudi5wYXJzZVVBKCk7XG5cbkpTWC5pc0Z1bmN0aW9uID0gZnVuY3Rpb24obykge1xuICAgIHJldHVybiAodHlwZW9mIG8gPT09ICdmdW5jdGlvbicpIHx8IE9QLnRvU3RyaW5nLmFwcGx5KG8pID09PSBGVU5DVElPTl9UT1NUUklORztcbn07XG5cbkpTWC5fSUVFbnVtRml4ID0gKEpTWC5lbnYudWEuaWUpID8gZnVuY3Rpb24ociwgcykge1xuICAgIHZhciBpLCBmbmFtZSwgZjtcbiAgICBmb3IgKGk9MDtpPEFERC5sZW5ndGg7aT1pKzEpIHtcblxuICAgICAgICBmbmFtZSA9IEFERFtpXTtcbiAgICAgICAgZiA9IHNbZm5hbWVdO1xuXG4gICAgICAgIGlmIChMLmlzRnVuY3Rpb24oZikgJiYgZiE9T1BbZm5hbWVdKSB7XG4gICAgICAgICAgICByW2ZuYW1lXT1mO1xuICAgICAgICB9XG4gICAgfVxufSA6IGZ1bmN0aW9uKCl7fTtcblxuSlNYLmV4dGVuZCA9IGZ1bmN0aW9uKHN1YmMsIHN1cGVyYywgb3ZlcnJpZGVzKSB7XG4gICAgaWYgKCFzdXBlcmN8fCFzdWJjKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcihcImV4dGVuZCBmYWlsZWQsIHBsZWFzZSBjaGVjayB0aGF0IFwiICtcbiAgICAgICAgICAgICAgICAgICAgICAgIFwiYWxsIGRlcGVuZGVuY2llcyBhcmUgaW5jbHVkZWQuXCIpO1xuICAgIH1cbiAgICB2YXIgRiA9IGZ1bmN0aW9uKCkge30sIGk7XG4gICAgRi5wcm90b3R5cGU9c3VwZXJjLnByb3RvdHlwZTtcbiAgICBzdWJjLnByb3RvdHlwZT1uZXcgRigpO1xuICAgIHN1YmMucHJvdG90eXBlLmNvbnN0cnVjdG9yPXN1YmM7XG4gICAgc3ViYy5zdXBlcmNsYXNzPXN1cGVyYy5wcm90b3R5cGU7XG4gICAgaWYgKHN1cGVyYy5wcm90b3R5cGUuY29uc3RydWN0b3IgPT0gT1AuY29uc3RydWN0b3IpIHtcbiAgICAgICAgc3VwZXJjLnByb3RvdHlwZS5jb25zdHJ1Y3Rvcj1zdXBlcmM7XG4gICAgfVxuXG4gICAgaWYgKG92ZXJyaWRlcykge1xuICAgICAgICBmb3IgKGkgaW4gb3ZlcnJpZGVzKSB7XG4gICAgICAgICAgICBpZiAoTC5oYXNPd25Qcm9wZXJ0eShvdmVycmlkZXMsIGkpKSB7XG4gICAgICAgICAgICAgICAgc3ViYy5wcm90b3R5cGVbaV09b3ZlcnJpZGVzW2ldO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgTC5fSUVFbnVtRml4KHN1YmMucHJvdG90eXBlLCBvdmVycmlkZXMpO1xuICAgIH1cbn07XG5cbi8qXG4gKiBhc24xLmpzIC0gQVNOLjEgREVSIGVuY29kZXIgY2xhc3Nlc1xuICpcbiAqIENvcHlyaWdodCAoYykgMjAxMyBLZW5qaSBVcnVzaGltYSAoa2VuamkudXJ1c2hpbWFAZ21haWwuY29tKVxuICpcbiAqIFRoaXMgc29mdHdhcmUgaXMgbGljZW5zZWQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBNSVQgTGljZW5zZS5cbiAqIGh0dHA6Ly9ranVyLmdpdGh1Yi5jb20vanNyc2FzaWduL2xpY2Vuc2VcbiAqXG4gKiBUaGUgYWJvdmUgY29weXJpZ2h0IGFuZCBsaWNlbnNlIG5vdGljZSBzaGFsbCBiZSBcbiAqIGluY2x1ZGVkIGluIGFsbCBjb3BpZXMgb3Igc3Vic3RhbnRpYWwgcG9ydGlvbnMgb2YgdGhlIFNvZnR3YXJlLlxuICovXG5cbi8qKlxuICogQGZpbGVPdmVydmlld1xuICogQG5hbWUgYXNuMS0xLjAuanNcbiAqIEBhdXRob3IgS2VuamkgVXJ1c2hpbWEga2VuamkudXJ1c2hpbWFAZ21haWwuY29tXG4gKiBAdmVyc2lvbiAxLjAuMiAoMjAxMy1NYXktMzApXG4gKiBAc2luY2UgMi4xXG4gKiBAbGljZW5zZSA8YSBocmVmPVwiaHR0cDovL2tqdXIuZ2l0aHViLmlvL2pzcnNhc2lnbi9saWNlbnNlL1wiPk1JVCBMaWNlbnNlPC9hPlxuICovXG5cbi8qKiBcbiAqIGtqdXIncyBjbGFzcyBsaWJyYXJ5IG5hbWUgc3BhY2VcbiAqIDxwPlxuICogVGhpcyBuYW1lIHNwYWNlIHByb3ZpZGVzIGZvbGxvd2luZyBuYW1lIHNwYWNlczpcbiAqIDx1bD5cbiAqIDxsaT57QGxpbmsgS0pVUi5hc24xfSAtIEFTTi4xIHByaW1pdGl2ZSBoZXhhZGVjaW1hbCBlbmNvZGVyPC9saT5cbiAqIDxsaT57QGxpbmsgS0pVUi5hc24xLng1MDl9IC0gQVNOLjEgc3RydWN0dXJlIGZvciBYLjUwOSBjZXJ0aWZpY2F0ZSBhbmQgQ1JMPC9saT5cbiAqIDxsaT57QGxpbmsgS0pVUi5jcnlwdG99IC0gSmF2YSBDcnlwdG9ncmFwaGljIEV4dGVuc2lvbihKQ0UpIHN0eWxlIE1lc3NhZ2VEaWdlc3QvU2lnbmF0dXJlIFxuICogY2xhc3MgYW5kIHV0aWxpdGllczwvbGk+XG4gKiA8L3VsPlxuICogPC9wPiBcbiAqIE5PVEU6IFBsZWFzZSBpZ25vcmUgbWV0aG9kIHN1bW1hcnkgYW5kIGRvY3VtZW50IG9mIHRoaXMgbmFtZXNwYWNlLiBUaGlzIGNhdXNlZCBieSBhIGJ1ZyBvZiBqc2RvYzIuXG4gICogQG5hbWUgS0pVUlxuICogQG5hbWVzcGFjZSBranVyJ3MgY2xhc3MgbGlicmFyeSBuYW1lIHNwYWNlXG4gKi9cbmlmICh0eXBlb2YgS0pVUiA9PSBcInVuZGVmaW5lZFwiIHx8ICFLSlVSKSBLSlVSID0ge307XG5cbi8qKlxuICoga2p1cidzIEFTTi4xIGNsYXNzIGxpYnJhcnkgbmFtZSBzcGFjZVxuICogPHA+XG4gKiBUaGlzIGlzIElUVS1UIFguNjkwIEFTTi4xIERFUiBlbmNvZGVyIGNsYXNzIGxpYnJhcnkgYW5kXG4gKiBjbGFzcyBzdHJ1Y3R1cmUgYW5kIG1ldGhvZHMgaXMgdmVyeSBzaW1pbGFyIHRvIFxuICogb3JnLmJvdW5jeWNhc3RsZS5hc24xIHBhY2thZ2Ugb2YgXG4gKiB3ZWxsIGtub3duIEJvdW5jeUNhc2x0ZSBDcnlwdG9ncmFwaHkgTGlicmFyeS5cbiAqXG4gKiA8aDQ+UFJPVklESU5HIEFTTi4xIFBSSU1JVElWRVM8L2g0PlxuICogSGVyZSBhcmUgQVNOLjEgREVSIHByaW1pdGl2ZSBjbGFzc2VzLlxuICogPHVsPlxuICogPGxpPntAbGluayBLSlVSLmFzbjEuREVSQm9vbGVhbn08L2xpPlxuICogPGxpPntAbGluayBLSlVSLmFzbjEuREVSSW50ZWdlcn08L2xpPlxuICogPGxpPntAbGluayBLSlVSLmFzbjEuREVSQml0U3RyaW5nfTwvbGk+XG4gKiA8bGk+e0BsaW5rIEtKVVIuYXNuMS5ERVJPY3RldFN0cmluZ308L2xpPlxuICogPGxpPntAbGluayBLSlVSLmFzbjEuREVSTnVsbH08L2xpPlxuICogPGxpPntAbGluayBLSlVSLmFzbjEuREVST2JqZWN0SWRlbnRpZmllcn08L2xpPlxuICogPGxpPntAbGluayBLSlVSLmFzbjEuREVSVVRGOFN0cmluZ308L2xpPlxuICogPGxpPntAbGluayBLSlVSLmFzbjEuREVSTnVtZXJpY1N0cmluZ308L2xpPlxuICogPGxpPntAbGluayBLSlVSLmFzbjEuREVSUHJpbnRhYmxlU3RyaW5nfTwvbGk+XG4gKiA8bGk+e0BsaW5rIEtKVVIuYXNuMS5ERVJUZWxldGV4U3RyaW5nfTwvbGk+XG4gKiA8bGk+e0BsaW5rIEtKVVIuYXNuMS5ERVJJQTVTdHJpbmd9PC9saT5cbiAqIDxsaT57QGxpbmsgS0pVUi5hc24xLkRFUlVUQ1RpbWV9PC9saT5cbiAqIDxsaT57QGxpbmsgS0pVUi5hc24xLkRFUkdlbmVyYWxpemVkVGltZX08L2xpPlxuICogPGxpPntAbGluayBLSlVSLmFzbjEuREVSU2VxdWVuY2V9PC9saT5cbiAqIDxsaT57QGxpbmsgS0pVUi5hc24xLkRFUlNldH08L2xpPlxuICogPC91bD5cbiAqXG4gKiA8aDQ+T1RIRVIgQVNOLjEgQ0xBU1NFUzwvaDQ+XG4gKiA8dWw+XG4gKiA8bGk+e0BsaW5rIEtKVVIuYXNuMS5BU04xT2JqZWN0fTwvbGk+XG4gKiA8bGk+e0BsaW5rIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZ308L2xpPlxuICogPGxpPntAbGluayBLSlVSLmFzbjEuREVSQWJzdHJhY3RUaW1lfTwvbGk+XG4gKiA8bGk+e0BsaW5rIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cnVjdHVyZWR9PC9saT5cbiAqIDxsaT57QGxpbmsgS0pVUi5hc24xLkRFUlRhZ2dlZE9iamVjdH08L2xpPlxuICogPC91bD5cbiAqIDwvcD5cbiAqIE5PVEU6IFBsZWFzZSBpZ25vcmUgbWV0aG9kIHN1bW1hcnkgYW5kIGRvY3VtZW50IG9mIHRoaXMgbmFtZXNwYWNlLiBUaGlzIGNhdXNlZCBieSBhIGJ1ZyBvZiBqc2RvYzIuXG4gKiBAbmFtZSBLSlVSLmFzbjFcbiAqIEBuYW1lc3BhY2VcbiAqL1xuaWYgKHR5cGVvZiBLSlVSLmFzbjEgPT0gXCJ1bmRlZmluZWRcIiB8fCAhS0pVUi5hc24xKSBLSlVSLmFzbjEgPSB7fTtcblxuLyoqXG4gKiBBU04xIHV0aWxpdGllcyBjbGFzc1xuICogQG5hbWUgS0pVUi5hc24xLkFTTjFVdGlsXG4gKiBAY2xhc3NzIEFTTjEgdXRpbGl0aWVzIGNsYXNzXG4gKiBAc2luY2UgYXNuMSAxLjAuMlxuICovXG5LSlVSLmFzbjEuQVNOMVV0aWwgPSBuZXcgZnVuY3Rpb24oKSB7XG4gICAgdGhpcy5pbnRlZ2VyVG9CeXRlSGV4ID0gZnVuY3Rpb24oaSkge1xuXHR2YXIgaCA9IGkudG9TdHJpbmcoMTYpO1xuXHRpZiAoKGgubGVuZ3RoICUgMikgPT0gMSkgaCA9ICcwJyArIGg7XG5cdHJldHVybiBoO1xuICAgIH07XG4gICAgdGhpcy5iaWdJbnRUb01pblR3b3NDb21wbGVtZW50c0hleCA9IGZ1bmN0aW9uKGJpZ0ludGVnZXJWYWx1ZSkge1xuXHR2YXIgaCA9IGJpZ0ludGVnZXJWYWx1ZS50b1N0cmluZygxNik7XG5cdGlmIChoLnN1YnN0cigwLCAxKSAhPSAnLScpIHtcblx0ICAgIGlmIChoLmxlbmd0aCAlIDIgPT0gMSkge1xuXHRcdGggPSAnMCcgKyBoO1xuXHQgICAgfSBlbHNlIHtcblx0XHRpZiAoISBoLm1hdGNoKC9eWzAtN10vKSkge1xuXHRcdCAgICBoID0gJzAwJyArIGg7XG5cdFx0fVxuXHQgICAgfVxuXHR9IGVsc2Uge1xuXHQgICAgdmFyIGhQb3MgPSBoLnN1YnN0cigxKTtcblx0ICAgIHZhciB4b3JMZW4gPSBoUG9zLmxlbmd0aDtcblx0ICAgIGlmICh4b3JMZW4gJSAyID09IDEpIHtcblx0XHR4b3JMZW4gKz0gMTtcblx0ICAgIH0gZWxzZSB7XG5cdFx0aWYgKCEgaC5tYXRjaCgvXlswLTddLykpIHtcblx0XHQgICAgeG9yTGVuICs9IDI7XG5cdFx0fVxuXHQgICAgfVxuXHQgICAgdmFyIGhNYXNrID0gJyc7XG5cdCAgICBmb3IgKHZhciBpID0gMDsgaSA8IHhvckxlbjsgaSsrKSB7XG5cdFx0aE1hc2sgKz0gJ2YnO1xuXHQgICAgfVxuXHQgICAgdmFyIGJpTWFzayA9IG5ldyBCaWdJbnRlZ2VyKGhNYXNrLCAxNik7XG5cdCAgICB2YXIgYmlOZWcgPSBiaU1hc2sueG9yKGJpZ0ludGVnZXJWYWx1ZSkuYWRkKEJpZ0ludGVnZXIuT05FKTtcblx0ICAgIGggPSBiaU5lZy50b1N0cmluZygxNikucmVwbGFjZSgvXi0vLCAnJyk7XG5cdH1cblx0cmV0dXJuIGg7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBnZXQgUEVNIHN0cmluZyBmcm9tIGhleGFkZWNpbWFsIGRhdGEgYW5kIGhlYWRlciBzdHJpbmdcbiAgICAgKiBAbmFtZSBnZXRQRU1TdHJpbmdGcm9tSGV4XG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5BU04xVXRpbFxuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEBwYXJhbSB7U3RyaW5nfSBkYXRhSGV4IGhleGFkZWNpbWFsIHN0cmluZyBvZiBQRU0gYm9keVxuICAgICAqIEBwYXJhbSB7U3RyaW5nfSBwZW1IZWFkZXIgUEVNIGhlYWRlciBzdHJpbmcgKGV4LiAnUlNBIFBSSVZBVEUgS0VZJylcbiAgICAgKiBAcmV0dXJuIHtTdHJpbmd9IFBFTSBmb3JtYXR0ZWQgc3RyaW5nIG9mIGlucHV0IGRhdGFcbiAgICAgKiBAZGVzY3JpcHRpb25cbiAgICAgKiBAZXhhbXBsZVxuICAgICAqIHZhciBwZW0gID0gS0pVUi5hc24xLkFTTjFVdGlsLmdldFBFTVN0cmluZ0Zyb21IZXgoJzYxNjE2MScsICdSU0EgUFJJVkFURSBLRVknKTtcbiAgICAgKiAvLyB2YWx1ZSBvZiBwZW0gd2lsbCBiZTpcbiAgICAgKiAtLS0tLUJFR0lOIFBSSVZBVEUgS0VZLS0tLS1cbiAgICAgKiBZV0ZoXG4gICAgICogLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLVxuICAgICAqL1xuICAgIHRoaXMuZ2V0UEVNU3RyaW5nRnJvbUhleCA9IGZ1bmN0aW9uKGRhdGFIZXgsIHBlbUhlYWRlcikge1xuXHR2YXIgZGF0YVdBID0gQ3J5cHRvSlMuZW5jLkhleC5wYXJzZShkYXRhSGV4KTtcblx0dmFyIGRhdGFCNjQgPSBDcnlwdG9KUy5lbmMuQmFzZTY0LnN0cmluZ2lmeShkYXRhV0EpO1xuXHR2YXIgcGVtQm9keSA9IGRhdGFCNjQucmVwbGFjZSgvKC57NjR9KS9nLCBcIiQxXFxyXFxuXCIpO1xuICAgICAgICBwZW1Cb2R5ID0gcGVtQm9keS5yZXBsYWNlKC9cXHJcXG4kLywgJycpO1xuXHRyZXR1cm4gXCItLS0tLUJFR0lOIFwiICsgcGVtSGVhZGVyICsgXCItLS0tLVxcclxcblwiICsgXG4gICAgICAgICAgICAgICBwZW1Cb2R5ICsgXG4gICAgICAgICAgICAgICBcIlxcclxcbi0tLS0tRU5EIFwiICsgcGVtSGVhZGVyICsgXCItLS0tLVxcclxcblwiO1xuICAgIH07XG59O1xuXG4vLyAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxuLy8gIEFic3RyYWN0IEFTTi4xIENsYXNzZXNcbi8vICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXG5cbi8vICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXG5cbi8qKlxuICogYmFzZSBjbGFzcyBmb3IgQVNOLjEgREVSIGVuY29kZXIgb2JqZWN0XG4gKiBAbmFtZSBLSlVSLmFzbjEuQVNOMU9iamVjdFxuICogQGNsYXNzIGJhc2UgY2xhc3MgZm9yIEFTTi4xIERFUiBlbmNvZGVyIG9iamVjdFxuICogQHByb3BlcnR5IHtCb29sZWFufSBpc01vZGlmaWVkIGZsYWcgd2hldGhlciBpbnRlcm5hbCBkYXRhIHdhcyBjaGFuZ2VkXG4gKiBAcHJvcGVydHkge1N0cmluZ30gaFRMViBoZXhhZGVjaW1hbCBzdHJpbmcgb2YgQVNOLjEgVExWXG4gKiBAcHJvcGVydHkge1N0cmluZ30gaFQgaGV4YWRlY2ltYWwgc3RyaW5nIG9mIEFTTi4xIFRMViB0YWcoVClcbiAqIEBwcm9wZXJ0eSB7U3RyaW5nfSBoTCBoZXhhZGVjaW1hbCBzdHJpbmcgb2YgQVNOLjEgVExWIGxlbmd0aChMKVxuICogQHByb3BlcnR5IHtTdHJpbmd9IGhWIGhleGFkZWNpbWFsIHN0cmluZyBvZiBBU04uMSBUTFYgdmFsdWUoVilcbiAqIEBkZXNjcmlwdGlvblxuICovXG5LSlVSLmFzbjEuQVNOMU9iamVjdCA9IGZ1bmN0aW9uKCkge1xuICAgIHZhciBpc01vZGlmaWVkID0gdHJ1ZTtcbiAgICB2YXIgaFRMViA9IG51bGw7XG4gICAgdmFyIGhUID0gJzAwJ1xuICAgIHZhciBoTCA9ICcwMCc7XG4gICAgdmFyIGhWID0gJyc7XG5cbiAgICAvKipcbiAgICAgKiBnZXQgaGV4YWRlY2ltYWwgQVNOLjEgVExWIGxlbmd0aChMKSBieXRlcyBmcm9tIFRMViB2YWx1ZShWKVxuICAgICAqIEBuYW1lIGdldExlbmd0aEhleEZyb21WYWx1ZVxuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuQVNOMU9iamVjdFxuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEByZXR1cm4ge1N0cmluZ30gaGV4YWRlY2ltYWwgc3RyaW5nIG9mIEFTTi4xIFRMViBsZW5ndGgoTClcbiAgICAgKi9cbiAgICB0aGlzLmdldExlbmd0aEhleEZyb21WYWx1ZSA9IGZ1bmN0aW9uKCkge1xuXHRpZiAodHlwZW9mIHRoaXMuaFYgPT0gXCJ1bmRlZmluZWRcIiB8fCB0aGlzLmhWID09IG51bGwpIHtcblx0ICAgIHRocm93IFwidGhpcy5oViBpcyBudWxsIG9yIHVuZGVmaW5lZC5cIjtcblx0fVxuXHRpZiAodGhpcy5oVi5sZW5ndGggJSAyID09IDEpIHtcblx0ICAgIHRocm93IFwidmFsdWUgaGV4IG11c3QgYmUgZXZlbiBsZW5ndGg6IG49XCIgKyBoVi5sZW5ndGggKyBcIix2PVwiICsgdGhpcy5oVjtcblx0fVxuXHR2YXIgbiA9IHRoaXMuaFYubGVuZ3RoIC8gMjtcblx0dmFyIGhOID0gbi50b1N0cmluZygxNik7XG5cdGlmIChoTi5sZW5ndGggJSAyID09IDEpIHtcblx0ICAgIGhOID0gXCIwXCIgKyBoTjtcblx0fVxuXHRpZiAobiA8IDEyOCkge1xuXHQgICAgcmV0dXJuIGhOO1xuXHR9IGVsc2Uge1xuXHQgICAgdmFyIGhObGVuID0gaE4ubGVuZ3RoIC8gMjtcblx0ICAgIGlmIChoTmxlbiA+IDE1KSB7XG5cdFx0dGhyb3cgXCJBU04uMSBsZW5ndGggdG9vIGxvbmcgdG8gcmVwcmVzZW50IGJ5IDh4OiBuID0gXCIgKyBuLnRvU3RyaW5nKDE2KTtcblx0ICAgIH1cblx0ICAgIHZhciBoZWFkID0gMTI4ICsgaE5sZW47XG5cdCAgICByZXR1cm4gaGVhZC50b1N0cmluZygxNikgKyBoTjtcblx0fVxuICAgIH07XG5cbiAgICAvKipcbiAgICAgKiBnZXQgaGV4YWRlY2ltYWwgc3RyaW5nIG9mIEFTTi4xIFRMViBieXRlc1xuICAgICAqIEBuYW1lIGdldEVuY29kZWRIZXhcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkFTTjFPYmplY3RcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcmV0dXJuIHtTdHJpbmd9IGhleGFkZWNpbWFsIHN0cmluZyBvZiBBU04uMSBUTFZcbiAgICAgKi9cbiAgICB0aGlzLmdldEVuY29kZWRIZXggPSBmdW5jdGlvbigpIHtcblx0aWYgKHRoaXMuaFRMViA9PSBudWxsIHx8IHRoaXMuaXNNb2RpZmllZCkge1xuXHQgICAgdGhpcy5oViA9IHRoaXMuZ2V0RnJlc2hWYWx1ZUhleCgpO1xuXHQgICAgdGhpcy5oTCA9IHRoaXMuZ2V0TGVuZ3RoSGV4RnJvbVZhbHVlKCk7XG5cdCAgICB0aGlzLmhUTFYgPSB0aGlzLmhUICsgdGhpcy5oTCArIHRoaXMuaFY7XG5cdCAgICB0aGlzLmlzTW9kaWZpZWQgPSBmYWxzZTtcblx0ICAgIC8vY29uc29sZS5lcnJvcihcImZpcnN0IHRpbWU6IFwiICsgdGhpcy5oVExWKTtcblx0fVxuXHRyZXR1cm4gdGhpcy5oVExWO1xuICAgIH07XG5cbiAgICAvKipcbiAgICAgKiBnZXQgaGV4YWRlY2ltYWwgc3RyaW5nIG9mIEFTTi4xIFRMViB2YWx1ZShWKSBieXRlc1xuICAgICAqIEBuYW1lIGdldFZhbHVlSGV4XG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5BU04xT2JqZWN0XG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHJldHVybiB7U3RyaW5nfSBoZXhhZGVjaW1hbCBzdHJpbmcgb2YgQVNOLjEgVExWIHZhbHVlKFYpIGJ5dGVzXG4gICAgICovXG4gICAgdGhpcy5nZXRWYWx1ZUhleCA9IGZ1bmN0aW9uKCkge1xuXHR0aGlzLmdldEVuY29kZWRIZXgoKTtcblx0cmV0dXJuIHRoaXMuaFY7XG4gICAgfVxuXG4gICAgdGhpcy5nZXRGcmVzaFZhbHVlSGV4ID0gZnVuY3Rpb24oKSB7XG5cdHJldHVybiAnJztcbiAgICB9O1xufTtcblxuLy8gPT0gQkVHSU4gREVSQWJzdHJhY3RTdHJpbmcgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG4vKipcbiAqIGJhc2UgY2xhc3MgZm9yIEFTTi4xIERFUiBzdHJpbmcgY2xhc3Nlc1xuICogQG5hbWUgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nXG4gKiBAY2xhc3MgYmFzZSBjbGFzcyBmb3IgQVNOLjEgREVSIHN0cmluZyBjbGFzc2VzXG4gKiBAcGFyYW0ge0FycmF5fSBwYXJhbXMgYXNzb2NpYXRpdmUgYXJyYXkgb2YgcGFyYW1ldGVycyAoZXguIHsnc3RyJzogJ2FhYSd9KVxuICogQHByb3BlcnR5IHtTdHJpbmd9IHMgaW50ZXJuYWwgc3RyaW5nIG9mIHZhbHVlXG4gKiBAZXh0ZW5kcyBLSlVSLmFzbjEuQVNOMU9iamVjdFxuICogQGRlc2NyaXB0aW9uXG4gKiA8YnIvPlxuICogQXMgZm9yIGFyZ3VtZW50ICdwYXJhbXMnIGZvciBjb25zdHJ1Y3RvciwgeW91IGNhbiBzcGVjaWZ5IG9uZSBvZlxuICogZm9sbG93aW5nIHByb3BlcnRpZXM6XG4gKiA8dWw+XG4gKiA8bGk+c3RyIC0gc3BlY2lmeSBpbml0aWFsIEFTTi4xIHZhbHVlKFYpIGJ5IGEgc3RyaW5nPC9saT5cbiAqIDxsaT5oZXggLSBzcGVjaWZ5IGluaXRpYWwgQVNOLjEgdmFsdWUoVikgYnkgYSBoZXhhZGVjaW1hbCBzdHJpbmc8L2xpPlxuICogPC91bD5cbiAqIE5PVEU6ICdwYXJhbXMnIGNhbiBiZSBvbWl0dGVkLlxuICovXG5LSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmcgPSBmdW5jdGlvbihwYXJhbXMpIHtcbiAgICBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmcuc3VwZXJjbGFzcy5jb25zdHJ1Y3Rvci5jYWxsKHRoaXMpO1xuICAgIHZhciBzID0gbnVsbDtcbiAgICB2YXIgaFYgPSBudWxsO1xuXG4gICAgLyoqXG4gICAgICogZ2V0IHN0cmluZyB2YWx1ZSBvZiB0aGlzIHN0cmluZyBvYmplY3RcbiAgICAgKiBAbmFtZSBnZXRTdHJpbmdcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nXG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHJldHVybiB7U3RyaW5nfSBzdHJpbmcgdmFsdWUgb2YgdGhpcyBzdHJpbmcgb2JqZWN0XG4gICAgICovXG4gICAgdGhpcy5nZXRTdHJpbmcgPSBmdW5jdGlvbigpIHtcblx0cmV0dXJuIHRoaXMucztcbiAgICB9O1xuXG4gICAgLyoqXG4gICAgICogc2V0IHZhbHVlIGJ5IGEgc3RyaW5nXG4gICAgICogQG5hbWUgc2V0U3RyaW5nXG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZ1xuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEBwYXJhbSB7U3RyaW5nfSBuZXdTIHZhbHVlIGJ5IGEgc3RyaW5nIHRvIHNldFxuICAgICAqL1xuICAgIHRoaXMuc2V0U3RyaW5nID0gZnVuY3Rpb24obmV3Uykge1xuXHR0aGlzLmhUTFYgPSBudWxsO1xuXHR0aGlzLmlzTW9kaWZpZWQgPSB0cnVlO1xuXHR0aGlzLnMgPSBuZXdTO1xuXHR0aGlzLmhWID0gc3RvaGV4KHRoaXMucyk7XG4gICAgfTtcblxuICAgIC8qKlxuICAgICAqIHNldCB2YWx1ZSBieSBhIGhleGFkZWNpbWFsIHN0cmluZ1xuICAgICAqIEBuYW1lIHNldFN0cmluZ0hleFxuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmdcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcGFyYW0ge1N0cmluZ30gbmV3SGV4U3RyaW5nIHZhbHVlIGJ5IGEgaGV4YWRlY2ltYWwgc3RyaW5nIHRvIHNldFxuICAgICAqL1xuICAgIHRoaXMuc2V0U3RyaW5nSGV4ID0gZnVuY3Rpb24obmV3SGV4U3RyaW5nKSB7XG5cdHRoaXMuaFRMViA9IG51bGw7XG5cdHRoaXMuaXNNb2RpZmllZCA9IHRydWU7XG5cdHRoaXMucyA9IG51bGw7XG5cdHRoaXMuaFYgPSBuZXdIZXhTdHJpbmc7XG4gICAgfTtcblxuICAgIHRoaXMuZ2V0RnJlc2hWYWx1ZUhleCA9IGZ1bmN0aW9uKCkge1xuXHRyZXR1cm4gdGhpcy5oVjtcbiAgICB9O1xuXG4gICAgaWYgKHR5cGVvZiBwYXJhbXMgIT0gXCJ1bmRlZmluZWRcIikge1xuXHRpZiAodHlwZW9mIHBhcmFtc1snc3RyJ10gIT0gXCJ1bmRlZmluZWRcIikge1xuXHQgICAgdGhpcy5zZXRTdHJpbmcocGFyYW1zWydzdHInXSk7XG5cdH0gZWxzZSBpZiAodHlwZW9mIHBhcmFtc1snaGV4J10gIT0gXCJ1bmRlZmluZWRcIikge1xuXHQgICAgdGhpcy5zZXRTdHJpbmdIZXgocGFyYW1zWydoZXgnXSk7XG5cdH1cbiAgICB9XG59O1xuSlNYLmV4dGVuZChLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmcsIEtKVVIuYXNuMS5BU04xT2JqZWN0KTtcbi8vID09IEVORCAgIERFUkFic3RyYWN0U3RyaW5nID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxuXG4vLyA9PSBCRUdJTiBERVJBYnN0cmFjdFRpbWUgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cbi8qKlxuICogYmFzZSBjbGFzcyBmb3IgQVNOLjEgREVSIEdlbmVyYWxpemVkL1VUQ1RpbWUgY2xhc3NcbiAqIEBuYW1lIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFRpbWVcbiAqIEBjbGFzcyBiYXNlIGNsYXNzIGZvciBBU04uMSBERVIgR2VuZXJhbGl6ZWQvVVRDVGltZSBjbGFzc1xuICogQHBhcmFtIHtBcnJheX0gcGFyYW1zIGFzc29jaWF0aXZlIGFycmF5IG9mIHBhcmFtZXRlcnMgKGV4LiB7J3N0cic6ICcxMzA0MzAyMzU5NTlaJ30pXG4gKiBAZXh0ZW5kcyBLSlVSLmFzbjEuQVNOMU9iamVjdFxuICogQGRlc2NyaXB0aW9uXG4gKiBAc2VlIEtKVVIuYXNuMS5BU04xT2JqZWN0IC0gc3VwZXJjbGFzc1xuICovXG5LSlVSLmFzbjEuREVSQWJzdHJhY3RUaW1lID0gZnVuY3Rpb24ocGFyYW1zKSB7XG4gICAgS0pVUi5hc24xLkRFUkFic3RyYWN0VGltZS5zdXBlcmNsYXNzLmNvbnN0cnVjdG9yLmNhbGwodGhpcyk7XG4gICAgdmFyIHMgPSBudWxsO1xuICAgIHZhciBkYXRlID0gbnVsbDtcblxuICAgIC8vIC0tLSBQUklWQVRFIE1FVEhPRFMgLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgICB0aGlzLmxvY2FsRGF0ZVRvVVRDID0gZnVuY3Rpb24oZCkge1xuXHR1dGMgPSBkLmdldFRpbWUoKSArIChkLmdldFRpbWV6b25lT2Zmc2V0KCkgKiA2MDAwMCk7XG5cdHZhciB1dGNEYXRlID0gbmV3IERhdGUodXRjKTtcblx0cmV0dXJuIHV0Y0RhdGU7XG4gICAgfTtcblxuICAgIHRoaXMuZm9ybWF0RGF0ZSA9IGZ1bmN0aW9uKGRhdGVPYmplY3QsIHR5cGUpIHtcblx0dmFyIHBhZCA9IHRoaXMuemVyb1BhZGRpbmc7XG5cdHZhciBkID0gdGhpcy5sb2NhbERhdGVUb1VUQyhkYXRlT2JqZWN0KTtcblx0dmFyIHllYXIgPSBTdHJpbmcoZC5nZXRGdWxsWWVhcigpKTtcblx0aWYgKHR5cGUgPT0gJ3V0YycpIHllYXIgPSB5ZWFyLnN1YnN0cigyLCAyKTtcblx0dmFyIG1vbnRoID0gcGFkKFN0cmluZyhkLmdldE1vbnRoKCkgKyAxKSwgMik7XG5cdHZhciBkYXkgPSBwYWQoU3RyaW5nKGQuZ2V0RGF0ZSgpKSwgMik7XG5cdHZhciBob3VyID0gcGFkKFN0cmluZyhkLmdldEhvdXJzKCkpLCAyKTtcblx0dmFyIG1pbiA9IHBhZChTdHJpbmcoZC5nZXRNaW51dGVzKCkpLCAyKTtcblx0dmFyIHNlYyA9IHBhZChTdHJpbmcoZC5nZXRTZWNvbmRzKCkpLCAyKTtcblx0cmV0dXJuIHllYXIgKyBtb250aCArIGRheSArIGhvdXIgKyBtaW4gKyBzZWMgKyAnWic7XG4gICAgfTtcblxuICAgIHRoaXMuemVyb1BhZGRpbmcgPSBmdW5jdGlvbihzLCBsZW4pIHtcblx0aWYgKHMubGVuZ3RoID49IGxlbikgcmV0dXJuIHM7XG5cdHJldHVybiBuZXcgQXJyYXkobGVuIC0gcy5sZW5ndGggKyAxKS5qb2luKCcwJykgKyBzO1xuICAgIH07XG5cbiAgICAvLyAtLS0gUFVCTElDIE1FVEhPRFMgLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgICAvKipcbiAgICAgKiBnZXQgc3RyaW5nIHZhbHVlIG9mIHRoaXMgc3RyaW5nIG9iamVjdFxuICAgICAqIEBuYW1lIGdldFN0cmluZ1xuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuREVSQWJzdHJhY3RUaW1lXG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHJldHVybiB7U3RyaW5nfSBzdHJpbmcgdmFsdWUgb2YgdGhpcyB0aW1lIG9iamVjdFxuICAgICAqL1xuICAgIHRoaXMuZ2V0U3RyaW5nID0gZnVuY3Rpb24oKSB7XG5cdHJldHVybiB0aGlzLnM7XG4gICAgfTtcblxuICAgIC8qKlxuICAgICAqIHNldCB2YWx1ZSBieSBhIHN0cmluZ1xuICAgICAqIEBuYW1lIHNldFN0cmluZ1xuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuREVSQWJzdHJhY3RUaW1lXG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHBhcmFtIHtTdHJpbmd9IG5ld1MgdmFsdWUgYnkgYSBzdHJpbmcgdG8gc2V0IHN1Y2ggbGlrZSBcIjEzMDQzMDIzNTk1OVpcIlxuICAgICAqL1xuICAgIHRoaXMuc2V0U3RyaW5nID0gZnVuY3Rpb24obmV3Uykge1xuXHR0aGlzLmhUTFYgPSBudWxsO1xuXHR0aGlzLmlzTW9kaWZpZWQgPSB0cnVlO1xuXHR0aGlzLnMgPSBuZXdTO1xuXHR0aGlzLmhWID0gc3RvaGV4KHRoaXMucyk7XG4gICAgfTtcblxuICAgIC8qKlxuICAgICAqIHNldCB2YWx1ZSBieSBhIERhdGUgb2JqZWN0XG4gICAgICogQG5hbWUgc2V0QnlEYXRlVmFsdWVcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkRFUkFic3RyYWN0VGltZVxuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEBwYXJhbSB7SW50ZWdlcn0geWVhciB5ZWFyIG9mIGRhdGUgKGV4LiAyMDEzKVxuICAgICAqIEBwYXJhbSB7SW50ZWdlcn0gbW9udGggbW9udGggb2YgZGF0ZSBiZXR3ZWVuIDEgYW5kIDEyIChleC4gMTIpXG4gICAgICogQHBhcmFtIHtJbnRlZ2VyfSBkYXkgZGF5IG9mIG1vbnRoXG4gICAgICogQHBhcmFtIHtJbnRlZ2VyfSBob3VyIGhvdXJzIG9mIGRhdGVcbiAgICAgKiBAcGFyYW0ge0ludGVnZXJ9IG1pbiBtaW51dGVzIG9mIGRhdGVcbiAgICAgKiBAcGFyYW0ge0ludGVnZXJ9IHNlYyBzZWNvbmRzIG9mIGRhdGVcbiAgICAgKi9cbiAgICB0aGlzLnNldEJ5RGF0ZVZhbHVlID0gZnVuY3Rpb24oeWVhciwgbW9udGgsIGRheSwgaG91ciwgbWluLCBzZWMpIHtcblx0dmFyIGRhdGVPYmplY3QgPSBuZXcgRGF0ZShEYXRlLlVUQyh5ZWFyLCBtb250aCAtIDEsIGRheSwgaG91ciwgbWluLCBzZWMsIDApKTtcblx0dGhpcy5zZXRCeURhdGUoZGF0ZU9iamVjdCk7XG4gICAgfTtcblxuICAgIHRoaXMuZ2V0RnJlc2hWYWx1ZUhleCA9IGZ1bmN0aW9uKCkge1xuXHRyZXR1cm4gdGhpcy5oVjtcbiAgICB9O1xufTtcbkpTWC5leHRlbmQoS0pVUi5hc24xLkRFUkFic3RyYWN0VGltZSwgS0pVUi5hc24xLkFTTjFPYmplY3QpO1xuLy8gPT0gRU5EICAgREVSQWJzdHJhY3RUaW1lID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG5cbi8vID09IEJFR0lOIERFUkFic3RyYWN0U3RydWN0dXJlZCA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxuLyoqXG4gKiBiYXNlIGNsYXNzIGZvciBBU04uMSBERVIgc3RydWN0dXJlZCBjbGFzc1xuICogQG5hbWUgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RydWN0dXJlZFxuICogQGNsYXNzIGJhc2UgY2xhc3MgZm9yIEFTTi4xIERFUiBzdHJ1Y3R1cmVkIGNsYXNzXG4gKiBAcHJvcGVydHkge0FycmF5fSBhc24xQXJyYXkgaW50ZXJuYWwgYXJyYXkgb2YgQVNOMU9iamVjdFxuICogQGV4dGVuZHMgS0pVUi5hc24xLkFTTjFPYmplY3RcbiAqIEBkZXNjcmlwdGlvblxuICogQHNlZSBLSlVSLmFzbjEuQVNOMU9iamVjdCAtIHN1cGVyY2xhc3NcbiAqL1xuS0pVUi5hc24xLkRFUkFic3RyYWN0U3RydWN0dXJlZCA9IGZ1bmN0aW9uKHBhcmFtcykge1xuICAgIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZy5zdXBlcmNsYXNzLmNvbnN0cnVjdG9yLmNhbGwodGhpcyk7XG4gICAgdmFyIGFzbjFBcnJheSA9IG51bGw7XG5cbiAgICAvKipcbiAgICAgKiBzZXQgdmFsdWUgYnkgYXJyYXkgb2YgQVNOMU9iamVjdFxuICAgICAqIEBuYW1lIHNldEJ5QVNOMU9iamVjdEFycmF5XG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cnVjdHVyZWRcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcGFyYW0ge2FycmF5fSBhc24xT2JqZWN0QXJyYXkgYXJyYXkgb2YgQVNOMU9iamVjdCB0byBzZXRcbiAgICAgKi9cbiAgICB0aGlzLnNldEJ5QVNOMU9iamVjdEFycmF5ID0gZnVuY3Rpb24oYXNuMU9iamVjdEFycmF5KSB7XG5cdHRoaXMuaFRMViA9IG51bGw7XG5cdHRoaXMuaXNNb2RpZmllZCA9IHRydWU7XG5cdHRoaXMuYXNuMUFycmF5ID0gYXNuMU9iamVjdEFycmF5O1xuICAgIH07XG5cbiAgICAvKipcbiAgICAgKiBhcHBlbmQgYW4gQVNOMU9iamVjdCB0byBpbnRlcm5hbCBhcnJheVxuICAgICAqIEBuYW1lIGFwcGVuZEFTTjFPYmplY3RcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RydWN0dXJlZFxuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEBwYXJhbSB7QVNOMU9iamVjdH0gYXNuMU9iamVjdCB0byBhZGRcbiAgICAgKi9cbiAgICB0aGlzLmFwcGVuZEFTTjFPYmplY3QgPSBmdW5jdGlvbihhc24xT2JqZWN0KSB7XG5cdHRoaXMuaFRMViA9IG51bGw7XG5cdHRoaXMuaXNNb2RpZmllZCA9IHRydWU7XG5cdHRoaXMuYXNuMUFycmF5LnB1c2goYXNuMU9iamVjdCk7XG4gICAgfTtcblxuICAgIHRoaXMuYXNuMUFycmF5ID0gbmV3IEFycmF5KCk7XG4gICAgaWYgKHR5cGVvZiBwYXJhbXMgIT0gXCJ1bmRlZmluZWRcIikge1xuXHRpZiAodHlwZW9mIHBhcmFtc1snYXJyYXknXSAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdCAgICB0aGlzLmFzbjFBcnJheSA9IHBhcmFtc1snYXJyYXknXTtcblx0fVxuICAgIH1cbn07XG5KU1guZXh0ZW5kKEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cnVjdHVyZWQsIEtKVVIuYXNuMS5BU04xT2JqZWN0KTtcblxuXG4vLyAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxuLy8gIEFTTi4xIE9iamVjdCBDbGFzc2VzXG4vLyAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxuXG4vLyAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxuLyoqXG4gKiBjbGFzcyBmb3IgQVNOLjEgREVSIEJvb2xlYW5cbiAqIEBuYW1lIEtKVVIuYXNuMS5ERVJCb29sZWFuXG4gKiBAY2xhc3MgY2xhc3MgZm9yIEFTTi4xIERFUiBCb29sZWFuXG4gKiBAZXh0ZW5kcyBLSlVSLmFzbjEuQVNOMU9iamVjdFxuICogQGRlc2NyaXB0aW9uXG4gKiBAc2VlIEtKVVIuYXNuMS5BU04xT2JqZWN0IC0gc3VwZXJjbGFzc1xuICovXG5LSlVSLmFzbjEuREVSQm9vbGVhbiA9IGZ1bmN0aW9uKCkge1xuICAgIEtKVVIuYXNuMS5ERVJCb29sZWFuLnN1cGVyY2xhc3MuY29uc3RydWN0b3IuY2FsbCh0aGlzKTtcbiAgICB0aGlzLmhUID0gXCIwMVwiO1xuICAgIHRoaXMuaFRMViA9IFwiMDEwMWZmXCI7XG59O1xuSlNYLmV4dGVuZChLSlVSLmFzbjEuREVSQm9vbGVhbiwgS0pVUi5hc24xLkFTTjFPYmplY3QpO1xuXG4vLyAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxuLyoqXG4gKiBjbGFzcyBmb3IgQVNOLjEgREVSIEludGVnZXJcbiAqIEBuYW1lIEtKVVIuYXNuMS5ERVJJbnRlZ2VyXG4gKiBAY2xhc3MgY2xhc3MgZm9yIEFTTi4xIERFUiBJbnRlZ2VyXG4gKiBAZXh0ZW5kcyBLSlVSLmFzbjEuQVNOMU9iamVjdFxuICogQGRlc2NyaXB0aW9uXG4gKiA8YnIvPlxuICogQXMgZm9yIGFyZ3VtZW50ICdwYXJhbXMnIGZvciBjb25zdHJ1Y3RvciwgeW91IGNhbiBzcGVjaWZ5IG9uZSBvZlxuICogZm9sbG93aW5nIHByb3BlcnRpZXM6XG4gKiA8dWw+XG4gKiA8bGk+aW50IC0gc3BlY2lmeSBpbml0aWFsIEFTTi4xIHZhbHVlKFYpIGJ5IGludGVnZXIgdmFsdWU8L2xpPlxuICogPGxpPmJpZ2ludCAtIHNwZWNpZnkgaW5pdGlhbCBBU04uMSB2YWx1ZShWKSBieSBCaWdJbnRlZ2VyIG9iamVjdDwvbGk+XG4gKiA8bGk+aGV4IC0gc3BlY2lmeSBpbml0aWFsIEFTTi4xIHZhbHVlKFYpIGJ5IGEgaGV4YWRlY2ltYWwgc3RyaW5nPC9saT5cbiAqIDwvdWw+XG4gKiBOT1RFOiAncGFyYW1zJyBjYW4gYmUgb21pdHRlZC5cbiAqL1xuS0pVUi5hc24xLkRFUkludGVnZXIgPSBmdW5jdGlvbihwYXJhbXMpIHtcbiAgICBLSlVSLmFzbjEuREVSSW50ZWdlci5zdXBlcmNsYXNzLmNvbnN0cnVjdG9yLmNhbGwodGhpcyk7XG4gICAgdGhpcy5oVCA9IFwiMDJcIjtcblxuICAgIC8qKlxuICAgICAqIHNldCB2YWx1ZSBieSBUb20gV3UncyBCaWdJbnRlZ2VyIG9iamVjdFxuICAgICAqIEBuYW1lIHNldEJ5QmlnSW50ZWdlclxuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuREVSSW50ZWdlclxuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEBwYXJhbSB7QmlnSW50ZWdlcn0gYmlnSW50ZWdlclZhbHVlIHRvIHNldFxuICAgICAqL1xuICAgIHRoaXMuc2V0QnlCaWdJbnRlZ2VyID0gZnVuY3Rpb24oYmlnSW50ZWdlclZhbHVlKSB7XG5cdHRoaXMuaFRMViA9IG51bGw7XG5cdHRoaXMuaXNNb2RpZmllZCA9IHRydWU7XG5cdHRoaXMuaFYgPSBLSlVSLmFzbjEuQVNOMVV0aWwuYmlnSW50VG9NaW5Ud29zQ29tcGxlbWVudHNIZXgoYmlnSW50ZWdlclZhbHVlKTtcbiAgICB9O1xuXG4gICAgLyoqXG4gICAgICogc2V0IHZhbHVlIGJ5IGludGVnZXIgdmFsdWVcbiAgICAgKiBAbmFtZSBzZXRCeUludGVnZXJcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkRFUkludGVnZXJcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcGFyYW0ge0ludGVnZXJ9IGludGVnZXIgdmFsdWUgdG8gc2V0XG4gICAgICovXG4gICAgdGhpcy5zZXRCeUludGVnZXIgPSBmdW5jdGlvbihpbnRWYWx1ZSkge1xuXHR2YXIgYmkgPSBuZXcgQmlnSW50ZWdlcihTdHJpbmcoaW50VmFsdWUpLCAxMCk7XG5cdHRoaXMuc2V0QnlCaWdJbnRlZ2VyKGJpKTtcbiAgICB9O1xuXG4gICAgLyoqXG4gICAgICogc2V0IHZhbHVlIGJ5IGludGVnZXIgdmFsdWVcbiAgICAgKiBAbmFtZSBzZXRWYWx1ZUhleFxuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuREVSSW50ZWdlclxuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEBwYXJhbSB7U3RyaW5nfSBoZXhhZGVjaW1hbCBzdHJpbmcgb2YgaW50ZWdlciB2YWx1ZVxuICAgICAqIEBkZXNjcmlwdGlvblxuICAgICAqIDxici8+XG4gICAgICogTk9URTogVmFsdWUgc2hhbGwgYmUgcmVwcmVzZW50ZWQgYnkgbWluaW11bSBvY3RldCBsZW5ndGggb2ZcbiAgICAgKiB0d28ncyBjb21wbGVtZW50IHJlcHJlc2VudGF0aW9uLlxuICAgICAqL1xuICAgIHRoaXMuc2V0VmFsdWVIZXggPSBmdW5jdGlvbihuZXdIZXhTdHJpbmcpIHtcblx0dGhpcy5oViA9IG5ld0hleFN0cmluZztcbiAgICB9O1xuXG4gICAgdGhpcy5nZXRGcmVzaFZhbHVlSGV4ID0gZnVuY3Rpb24oKSB7XG5cdHJldHVybiB0aGlzLmhWO1xuICAgIH07XG5cbiAgICBpZiAodHlwZW9mIHBhcmFtcyAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdGlmICh0eXBlb2YgcGFyYW1zWydiaWdpbnQnXSAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdCAgICB0aGlzLnNldEJ5QmlnSW50ZWdlcihwYXJhbXNbJ2JpZ2ludCddKTtcblx0fSBlbHNlIGlmICh0eXBlb2YgcGFyYW1zWydpbnQnXSAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdCAgICB0aGlzLnNldEJ5SW50ZWdlcihwYXJhbXNbJ2ludCddKTtcblx0fSBlbHNlIGlmICh0eXBlb2YgcGFyYW1zWydoZXgnXSAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdCAgICB0aGlzLnNldFZhbHVlSGV4KHBhcmFtc1snaGV4J10pO1xuXHR9XG4gICAgfVxufTtcbkpTWC5leHRlbmQoS0pVUi5hc24xLkRFUkludGVnZXIsIEtKVVIuYXNuMS5BU04xT2JqZWN0KTtcblxuLy8gKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcbi8qKlxuICogY2xhc3MgZm9yIEFTTi4xIERFUiBlbmNvZGVkIEJpdFN0cmluZyBwcmltaXRpdmVcbiAqIEBuYW1lIEtKVVIuYXNuMS5ERVJCaXRTdHJpbmdcbiAqIEBjbGFzcyBjbGFzcyBmb3IgQVNOLjEgREVSIGVuY29kZWQgQml0U3RyaW5nIHByaW1pdGl2ZVxuICogQGV4dGVuZHMgS0pVUi5hc24xLkFTTjFPYmplY3RcbiAqIEBkZXNjcmlwdGlvbiBcbiAqIDxici8+XG4gKiBBcyBmb3IgYXJndW1lbnQgJ3BhcmFtcycgZm9yIGNvbnN0cnVjdG9yLCB5b3UgY2FuIHNwZWNpZnkgb25lIG9mXG4gKiBmb2xsb3dpbmcgcHJvcGVydGllczpcbiAqIDx1bD5cbiAqIDxsaT5iaW4gLSBzcGVjaWZ5IGJpbmFyeSBzdHJpbmcgKGV4LiAnMTAxMTEnKTwvbGk+XG4gKiA8bGk+YXJyYXkgLSBzcGVjaWZ5IGFycmF5IG9mIGJvb2xlYW4gKGV4LiBbdHJ1ZSxmYWxzZSx0cnVlLHRydWVdKTwvbGk+XG4gKiA8bGk+aGV4IC0gc3BlY2lmeSBoZXhhZGVjaW1hbCBzdHJpbmcgb2YgQVNOLjEgdmFsdWUoVikgaW5jbHVkaW5nIHVudXNlZCBiaXRzPC9saT5cbiAqIDwvdWw+XG4gKiBOT1RFOiAncGFyYW1zJyBjYW4gYmUgb21pdHRlZC5cbiAqL1xuS0pVUi5hc24xLkRFUkJpdFN0cmluZyA9IGZ1bmN0aW9uKHBhcmFtcykge1xuICAgIEtKVVIuYXNuMS5ERVJCaXRTdHJpbmcuc3VwZXJjbGFzcy5jb25zdHJ1Y3Rvci5jYWxsKHRoaXMpO1xuICAgIHRoaXMuaFQgPSBcIjAzXCI7XG5cbiAgICAvKipcbiAgICAgKiBzZXQgQVNOLjEgdmFsdWUoVikgYnkgYSBoZXhhZGVjaW1hbCBzdHJpbmcgaW5jbHVkaW5nIHVudXNlZCBiaXRzXG4gICAgICogQG5hbWUgc2V0SGV4VmFsdWVJbmNsdWRpbmdVbnVzZWRCaXRzXG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5ERVJCaXRTdHJpbmdcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcGFyYW0ge1N0cmluZ30gbmV3SGV4U3RyaW5nSW5jbHVkaW5nVW51c2VkQml0c1xuICAgICAqL1xuICAgIHRoaXMuc2V0SGV4VmFsdWVJbmNsdWRpbmdVbnVzZWRCaXRzID0gZnVuY3Rpb24obmV3SGV4U3RyaW5nSW5jbHVkaW5nVW51c2VkQml0cykge1xuXHR0aGlzLmhUTFYgPSBudWxsO1xuXHR0aGlzLmlzTW9kaWZpZWQgPSB0cnVlO1xuXHR0aGlzLmhWID0gbmV3SGV4U3RyaW5nSW5jbHVkaW5nVW51c2VkQml0cztcbiAgICB9O1xuXG4gICAgLyoqXG4gICAgICogc2V0IEFTTi4xIHZhbHVlKFYpIGJ5IHVudXNlZCBiaXQgYW5kIGhleGFkZWNpbWFsIHN0cmluZyBvZiB2YWx1ZVxuICAgICAqIEBuYW1lIHNldFVudXNlZEJpdHNBbmRIZXhWYWx1ZVxuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuREVSQml0U3RyaW5nXG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHBhcmFtIHtJbnRlZ2VyfSB1bnVzZWRCaXRzXG4gICAgICogQHBhcmFtIHtTdHJpbmd9IGhWYWx1ZVxuICAgICAqL1xuICAgIHRoaXMuc2V0VW51c2VkQml0c0FuZEhleFZhbHVlID0gZnVuY3Rpb24odW51c2VkQml0cywgaFZhbHVlKSB7XG5cdGlmICh1bnVzZWRCaXRzIDwgMCB8fCA3IDwgdW51c2VkQml0cykge1xuXHQgICAgdGhyb3cgXCJ1bnVzZWQgYml0cyBzaGFsbCBiZSBmcm9tIDAgdG8gNzogdSA9IFwiICsgdW51c2VkQml0cztcblx0fVxuXHR2YXIgaFVudXNlZEJpdHMgPSBcIjBcIiArIHVudXNlZEJpdHM7XG5cdHRoaXMuaFRMViA9IG51bGw7XG5cdHRoaXMuaXNNb2RpZmllZCA9IHRydWU7XG5cdHRoaXMuaFYgPSBoVW51c2VkQml0cyArIGhWYWx1ZTtcbiAgICB9O1xuXG4gICAgLyoqXG4gICAgICogc2V0IEFTTi4xIERFUiBCaXRTdHJpbmcgYnkgYmluYXJ5IHN0cmluZ1xuICAgICAqIEBuYW1lIHNldEJ5QmluYXJ5U3RyaW5nXG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5ERVJCaXRTdHJpbmdcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcGFyYW0ge1N0cmluZ30gYmluYXJ5U3RyaW5nIGJpbmFyeSB2YWx1ZSBzdHJpbmcgKGkuZS4gJzEwMTExJylcbiAgICAgKiBAZGVzY3JpcHRpb25cbiAgICAgKiBJdHMgdW51c2VkIGJpdHMgd2lsbCBiZSBjYWxjdWxhdGVkIGF1dG9tYXRpY2FsbHkgYnkgbGVuZ3RoIG9mIFxuICAgICAqICdiaW5hcnlWYWx1ZScuIDxici8+XG4gICAgICogTk9URTogVHJhaWxpbmcgemVyb3MgJzAnIHdpbGwgYmUgaWdub3JlZC5cbiAgICAgKi9cbiAgICB0aGlzLnNldEJ5QmluYXJ5U3RyaW5nID0gZnVuY3Rpb24oYmluYXJ5U3RyaW5nKSB7XG5cdGJpbmFyeVN0cmluZyA9IGJpbmFyeVN0cmluZy5yZXBsYWNlKC8wKyQvLCAnJyk7XG5cdHZhciB1bnVzZWRCaXRzID0gOCAtIGJpbmFyeVN0cmluZy5sZW5ndGggJSA4O1xuXHRpZiAodW51c2VkQml0cyA9PSA4KSB1bnVzZWRCaXRzID0gMDtcblx0Zm9yICh2YXIgaSA9IDA7IGkgPD0gdW51c2VkQml0czsgaSsrKSB7XG5cdCAgICBiaW5hcnlTdHJpbmcgKz0gJzAnO1xuXHR9XG5cdHZhciBoID0gJyc7XG5cdGZvciAodmFyIGkgPSAwOyBpIDwgYmluYXJ5U3RyaW5nLmxlbmd0aCAtIDE7IGkgKz0gOCkge1xuXHQgICAgdmFyIGIgPSBiaW5hcnlTdHJpbmcuc3Vic3RyKGksIDgpO1xuXHQgICAgdmFyIHggPSBwYXJzZUludChiLCAyKS50b1N0cmluZygxNik7XG5cdCAgICBpZiAoeC5sZW5ndGggPT0gMSkgeCA9ICcwJyArIHg7XG5cdCAgICBoICs9IHg7ICBcblx0fVxuXHR0aGlzLmhUTFYgPSBudWxsO1xuXHR0aGlzLmlzTW9kaWZpZWQgPSB0cnVlO1xuXHR0aGlzLmhWID0gJzAnICsgdW51c2VkQml0cyArIGg7XG4gICAgfTtcblxuICAgIC8qKlxuICAgICAqIHNldCBBU04uMSBUTFYgdmFsdWUoVikgYnkgYW4gYXJyYXkgb2YgYm9vbGVhblxuICAgICAqIEBuYW1lIHNldEJ5Qm9vbGVhbkFycmF5XG4gICAgICogQG1lbWJlck9mIEtKVVIuYXNuMS5ERVJCaXRTdHJpbmdcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcGFyYW0ge2FycmF5fSBib29sZWFuQXJyYXkgYXJyYXkgb2YgYm9vbGVhbiAoZXguIFt0cnVlLCBmYWxzZSwgdHJ1ZV0pXG4gICAgICogQGRlc2NyaXB0aW9uXG4gICAgICogTk9URTogVHJhaWxpbmcgZmFsc2VzIHdpbGwgYmUgaWdub3JlZC5cbiAgICAgKi9cbiAgICB0aGlzLnNldEJ5Qm9vbGVhbkFycmF5ID0gZnVuY3Rpb24oYm9vbGVhbkFycmF5KSB7XG5cdHZhciBzID0gJyc7XG5cdGZvciAodmFyIGkgPSAwOyBpIDwgYm9vbGVhbkFycmF5Lmxlbmd0aDsgaSsrKSB7XG5cdCAgICBpZiAoYm9vbGVhbkFycmF5W2ldID09IHRydWUpIHtcblx0XHRzICs9ICcxJztcblx0ICAgIH0gZWxzZSB7XG5cdFx0cyArPSAnMCc7XG5cdCAgICB9XG5cdH1cblx0dGhpcy5zZXRCeUJpbmFyeVN0cmluZyhzKTtcbiAgICB9O1xuXG4gICAgLyoqXG4gICAgICogZ2VuZXJhdGUgYW4gYXJyYXkgb2YgZmFsc2Ugd2l0aCBzcGVjaWZpZWQgbGVuZ3RoXG4gICAgICogQG5hbWUgbmV3RmFsc2VBcnJheVxuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuREVSQml0U3RyaW5nXG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHBhcmFtIHtJbnRlZ2VyfSBuTGVuZ3RoIGxlbmd0aCBvZiBhcnJheSB0byBnZW5lcmF0ZVxuICAgICAqIEByZXR1cm4ge2FycmF5fSBhcnJheSBvZiBib29sZWFuIGZhbHVzZVxuICAgICAqIEBkZXNjcmlwdGlvblxuICAgICAqIFRoaXMgc3RhdGljIG1ldGhvZCBtYXkgYmUgdXNlZnVsIHRvIGluaXRpYWxpemUgYm9vbGVhbiBhcnJheS5cbiAgICAgKi9cbiAgICB0aGlzLm5ld0ZhbHNlQXJyYXkgPSBmdW5jdGlvbihuTGVuZ3RoKSB7XG5cdHZhciBhID0gbmV3IEFycmF5KG5MZW5ndGgpO1xuXHRmb3IgKHZhciBpID0gMDsgaSA8IG5MZW5ndGg7IGkrKykge1xuXHQgICAgYVtpXSA9IGZhbHNlO1xuXHR9XG5cdHJldHVybiBhO1xuICAgIH07XG5cbiAgICB0aGlzLmdldEZyZXNoVmFsdWVIZXggPSBmdW5jdGlvbigpIHtcblx0cmV0dXJuIHRoaXMuaFY7XG4gICAgfTtcblxuICAgIGlmICh0eXBlb2YgcGFyYW1zICE9IFwidW5kZWZpbmVkXCIpIHtcblx0aWYgKHR5cGVvZiBwYXJhbXNbJ2hleCddICE9IFwidW5kZWZpbmVkXCIpIHtcblx0ICAgIHRoaXMuc2V0SGV4VmFsdWVJbmNsdWRpbmdVbnVzZWRCaXRzKHBhcmFtc1snaGV4J10pO1xuXHR9IGVsc2UgaWYgKHR5cGVvZiBwYXJhbXNbJ2JpbiddICE9IFwidW5kZWZpbmVkXCIpIHtcblx0ICAgIHRoaXMuc2V0QnlCaW5hcnlTdHJpbmcocGFyYW1zWydiaW4nXSk7XG5cdH0gZWxzZSBpZiAodHlwZW9mIHBhcmFtc1snYXJyYXknXSAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdCAgICB0aGlzLnNldEJ5Qm9vbGVhbkFycmF5KHBhcmFtc1snYXJyYXknXSk7XG5cdH1cbiAgICB9XG59O1xuSlNYLmV4dGVuZChLSlVSLmFzbjEuREVSQml0U3RyaW5nLCBLSlVSLmFzbjEuQVNOMU9iamVjdCk7XG5cbi8vICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXG4vKipcbiAqIGNsYXNzIGZvciBBU04uMSBERVIgT2N0ZXRTdHJpbmdcbiAqIEBuYW1lIEtKVVIuYXNuMS5ERVJPY3RldFN0cmluZ1xuICogQGNsYXNzIGNsYXNzIGZvciBBU04uMSBERVIgT2N0ZXRTdHJpbmdcbiAqIEBwYXJhbSB7QXJyYXl9IHBhcmFtcyBhc3NvY2lhdGl2ZSBhcnJheSBvZiBwYXJhbWV0ZXJzIChleC4geydzdHInOiAnYWFhJ30pXG4gKiBAZXh0ZW5kcyBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmdcbiAqIEBkZXNjcmlwdGlvblxuICogQHNlZSBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmcgLSBzdXBlcmNsYXNzXG4gKi9cbktKVVIuYXNuMS5ERVJPY3RldFN0cmluZyA9IGZ1bmN0aW9uKHBhcmFtcykge1xuICAgIEtKVVIuYXNuMS5ERVJPY3RldFN0cmluZy5zdXBlcmNsYXNzLmNvbnN0cnVjdG9yLmNhbGwodGhpcywgcGFyYW1zKTtcbiAgICB0aGlzLmhUID0gXCIwNFwiO1xufTtcbkpTWC5leHRlbmQoS0pVUi5hc24xLkRFUk9jdGV0U3RyaW5nLCBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmcpO1xuXG4vLyAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxuLyoqXG4gKiBjbGFzcyBmb3IgQVNOLjEgREVSIE51bGxcbiAqIEBuYW1lIEtKVVIuYXNuMS5ERVJOdWxsXG4gKiBAY2xhc3MgY2xhc3MgZm9yIEFTTi4xIERFUiBOdWxsXG4gKiBAZXh0ZW5kcyBLSlVSLmFzbjEuQVNOMU9iamVjdFxuICogQGRlc2NyaXB0aW9uXG4gKiBAc2VlIEtKVVIuYXNuMS5BU04xT2JqZWN0IC0gc3VwZXJjbGFzc1xuICovXG5LSlVSLmFzbjEuREVSTnVsbCA9IGZ1bmN0aW9uKCkge1xuICAgIEtKVVIuYXNuMS5ERVJOdWxsLnN1cGVyY2xhc3MuY29uc3RydWN0b3IuY2FsbCh0aGlzKTtcbiAgICB0aGlzLmhUID0gXCIwNVwiO1xuICAgIHRoaXMuaFRMViA9IFwiMDUwMFwiO1xufTtcbkpTWC5leHRlbmQoS0pVUi5hc24xLkRFUk51bGwsIEtKVVIuYXNuMS5BU04xT2JqZWN0KTtcblxuLy8gKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcbi8qKlxuICogY2xhc3MgZm9yIEFTTi4xIERFUiBPYmplY3RJZGVudGlmaWVyXG4gKiBAbmFtZSBLSlVSLmFzbjEuREVST2JqZWN0SWRlbnRpZmllclxuICogQGNsYXNzIGNsYXNzIGZvciBBU04uMSBERVIgT2JqZWN0SWRlbnRpZmllclxuICogQHBhcmFtIHtBcnJheX0gcGFyYW1zIGFzc29jaWF0aXZlIGFycmF5IG9mIHBhcmFtZXRlcnMgKGV4LiB7J29pZCc6ICcyLjUuNC41J30pXG4gKiBAZXh0ZW5kcyBLSlVSLmFzbjEuQVNOMU9iamVjdFxuICogQGRlc2NyaXB0aW9uXG4gKiA8YnIvPlxuICogQXMgZm9yIGFyZ3VtZW50ICdwYXJhbXMnIGZvciBjb25zdHJ1Y3RvciwgeW91IGNhbiBzcGVjaWZ5IG9uZSBvZlxuICogZm9sbG93aW5nIHByb3BlcnRpZXM6XG4gKiA8dWw+XG4gKiA8bGk+b2lkIC0gc3BlY2lmeSBpbml0aWFsIEFTTi4xIHZhbHVlKFYpIGJ5IGEgb2lkIHN0cmluZyAoZXguIDIuNS40LjEzKTwvbGk+XG4gKiA8bGk+aGV4IC0gc3BlY2lmeSBpbml0aWFsIEFTTi4xIHZhbHVlKFYpIGJ5IGEgaGV4YWRlY2ltYWwgc3RyaW5nPC9saT5cbiAqIDwvdWw+XG4gKiBOT1RFOiAncGFyYW1zJyBjYW4gYmUgb21pdHRlZC5cbiAqL1xuS0pVUi5hc24xLkRFUk9iamVjdElkZW50aWZpZXIgPSBmdW5jdGlvbihwYXJhbXMpIHtcbiAgICB2YXIgaXRveCA9IGZ1bmN0aW9uKGkpIHtcblx0dmFyIGggPSBpLnRvU3RyaW5nKDE2KTtcblx0aWYgKGgubGVuZ3RoID09IDEpIGggPSAnMCcgKyBoO1xuXHRyZXR1cm4gaDtcbiAgICB9O1xuICAgIHZhciByb2lkdG94ID0gZnVuY3Rpb24ocm9pZCkge1xuXHR2YXIgaCA9ICcnO1xuXHR2YXIgYmkgPSBuZXcgQmlnSW50ZWdlcihyb2lkLCAxMCk7XG5cdHZhciBiID0gYmkudG9TdHJpbmcoMik7XG5cdHZhciBwYWRMZW4gPSA3IC0gYi5sZW5ndGggJSA3O1xuXHRpZiAocGFkTGVuID09IDcpIHBhZExlbiA9IDA7XG5cdHZhciBiUGFkID0gJyc7XG5cdGZvciAodmFyIGkgPSAwOyBpIDwgcGFkTGVuOyBpKyspIGJQYWQgKz0gJzAnO1xuXHRiID0gYlBhZCArIGI7XG5cdGZvciAodmFyIGkgPSAwOyBpIDwgYi5sZW5ndGggLSAxOyBpICs9IDcpIHtcblx0ICAgIHZhciBiOCA9IGIuc3Vic3RyKGksIDcpO1xuXHQgICAgaWYgKGkgIT0gYi5sZW5ndGggLSA3KSBiOCA9ICcxJyArIGI4O1xuXHQgICAgaCArPSBpdG94KHBhcnNlSW50KGI4LCAyKSk7XG5cdH1cblx0cmV0dXJuIGg7XG4gICAgfVxuXG4gICAgS0pVUi5hc24xLkRFUk9iamVjdElkZW50aWZpZXIuc3VwZXJjbGFzcy5jb25zdHJ1Y3Rvci5jYWxsKHRoaXMpO1xuICAgIHRoaXMuaFQgPSBcIjA2XCI7XG5cbiAgICAvKipcbiAgICAgKiBzZXQgdmFsdWUgYnkgYSBoZXhhZGVjaW1hbCBzdHJpbmdcbiAgICAgKiBAbmFtZSBzZXRWYWx1ZUhleFxuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuREVST2JqZWN0SWRlbnRpZmllclxuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEBwYXJhbSB7U3RyaW5nfSBuZXdIZXhTdHJpbmcgaGV4YWRlY2ltYWwgdmFsdWUgb2YgT0lEIGJ5dGVzXG4gICAgICovXG4gICAgdGhpcy5zZXRWYWx1ZUhleCA9IGZ1bmN0aW9uKG5ld0hleFN0cmluZykge1xuXHR0aGlzLmhUTFYgPSBudWxsO1xuXHR0aGlzLmlzTW9kaWZpZWQgPSB0cnVlO1xuXHR0aGlzLnMgPSBudWxsO1xuXHR0aGlzLmhWID0gbmV3SGV4U3RyaW5nO1xuICAgIH07XG5cbiAgICAvKipcbiAgICAgKiBzZXQgdmFsdWUgYnkgYSBPSUQgc3RyaW5nXG4gICAgICogQG5hbWUgc2V0VmFsdWVPaWRTdHJpbmdcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkRFUk9iamVjdElkZW50aWZpZXJcbiAgICAgKiBAZnVuY3Rpb25cbiAgICAgKiBAcGFyYW0ge1N0cmluZ30gb2lkU3RyaW5nIE9JRCBzdHJpbmcgKGV4LiAyLjUuNC4xMylcbiAgICAgKi9cbiAgICB0aGlzLnNldFZhbHVlT2lkU3RyaW5nID0gZnVuY3Rpb24ob2lkU3RyaW5nKSB7XG5cdGlmICghIG9pZFN0cmluZy5tYXRjaCgvXlswLTkuXSskLykpIHtcblx0ICAgIHRocm93IFwibWFsZm9ybWVkIG9pZCBzdHJpbmc6IFwiICsgb2lkU3RyaW5nO1xuXHR9XG5cdHZhciBoID0gJyc7XG5cdHZhciBhID0gb2lkU3RyaW5nLnNwbGl0KCcuJyk7XG5cdHZhciBpMCA9IHBhcnNlSW50KGFbMF0pICogNDAgKyBwYXJzZUludChhWzFdKTtcblx0aCArPSBpdG94KGkwKTtcblx0YS5zcGxpY2UoMCwgMik7XG5cdGZvciAodmFyIGkgPSAwOyBpIDwgYS5sZW5ndGg7IGkrKykge1xuXHQgICAgaCArPSByb2lkdG94KGFbaV0pO1xuXHR9XG5cdHRoaXMuaFRMViA9IG51bGw7XG5cdHRoaXMuaXNNb2RpZmllZCA9IHRydWU7XG5cdHRoaXMucyA9IG51bGw7XG5cdHRoaXMuaFYgPSBoO1xuICAgIH07XG5cbiAgICAvKipcbiAgICAgKiBzZXQgdmFsdWUgYnkgYSBPSUQgbmFtZVxuICAgICAqIEBuYW1lIHNldFZhbHVlTmFtZVxuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuREVST2JqZWN0SWRlbnRpZmllclxuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEBwYXJhbSB7U3RyaW5nfSBvaWROYW1lIE9JRCBuYW1lIChleC4gJ3NlcnZlckF1dGgnKVxuICAgICAqIEBzaW5jZSAxLjAuMVxuICAgICAqIEBkZXNjcmlwdGlvblxuICAgICAqIE9JRCBuYW1lIHNoYWxsIGJlIGRlZmluZWQgaW4gJ0tKVVIuYXNuMS54NTA5Lk9JRC5uYW1lMm9pZExpc3QnLlxuICAgICAqIE90aGVyd2lzZSByYWlzZSBlcnJvci5cbiAgICAgKi9cbiAgICB0aGlzLnNldFZhbHVlTmFtZSA9IGZ1bmN0aW9uKG9pZE5hbWUpIHtcblx0aWYgKHR5cGVvZiBLSlVSLmFzbjEueDUwOS5PSUQubmFtZTJvaWRMaXN0W29pZE5hbWVdICE9IFwidW5kZWZpbmVkXCIpIHtcblx0ICAgIHZhciBvaWQgPSBLSlVSLmFzbjEueDUwOS5PSUQubmFtZTJvaWRMaXN0W29pZE5hbWVdO1xuXHQgICAgdGhpcy5zZXRWYWx1ZU9pZFN0cmluZyhvaWQpO1xuXHR9IGVsc2Uge1xuXHQgICAgdGhyb3cgXCJERVJPYmplY3RJZGVudGlmaWVyIG9pZE5hbWUgdW5kZWZpbmVkOiBcIiArIG9pZE5hbWU7XG5cdH1cbiAgICB9O1xuXG4gICAgdGhpcy5nZXRGcmVzaFZhbHVlSGV4ID0gZnVuY3Rpb24oKSB7XG5cdHJldHVybiB0aGlzLmhWO1xuICAgIH07XG5cbiAgICBpZiAodHlwZW9mIHBhcmFtcyAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdGlmICh0eXBlb2YgcGFyYW1zWydvaWQnXSAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdCAgICB0aGlzLnNldFZhbHVlT2lkU3RyaW5nKHBhcmFtc1snb2lkJ10pO1xuXHR9IGVsc2UgaWYgKHR5cGVvZiBwYXJhbXNbJ2hleCddICE9IFwidW5kZWZpbmVkXCIpIHtcblx0ICAgIHRoaXMuc2V0VmFsdWVIZXgocGFyYW1zWydoZXgnXSk7XG5cdH0gZWxzZSBpZiAodHlwZW9mIHBhcmFtc1snbmFtZSddICE9IFwidW5kZWZpbmVkXCIpIHtcblx0ICAgIHRoaXMuc2V0VmFsdWVOYW1lKHBhcmFtc1snbmFtZSddKTtcblx0fVxuICAgIH1cbn07XG5KU1guZXh0ZW5kKEtKVVIuYXNuMS5ERVJPYmplY3RJZGVudGlmaWVyLCBLSlVSLmFzbjEuQVNOMU9iamVjdCk7XG5cbi8vICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXG4vKipcbiAqIGNsYXNzIGZvciBBU04uMSBERVIgVVRGOFN0cmluZ1xuICogQG5hbWUgS0pVUi5hc24xLkRFUlVURjhTdHJpbmdcbiAqIEBjbGFzcyBjbGFzcyBmb3IgQVNOLjEgREVSIFVURjhTdHJpbmdcbiAqIEBwYXJhbSB7QXJyYXl9IHBhcmFtcyBhc3NvY2lhdGl2ZSBhcnJheSBvZiBwYXJhbWV0ZXJzIChleC4geydzdHInOiAnYWFhJ30pXG4gKiBAZXh0ZW5kcyBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmdcbiAqIEBkZXNjcmlwdGlvblxuICogQHNlZSBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmcgLSBzdXBlcmNsYXNzXG4gKi9cbktKVVIuYXNuMS5ERVJVVEY4U3RyaW5nID0gZnVuY3Rpb24ocGFyYW1zKSB7XG4gICAgS0pVUi5hc24xLkRFUlVURjhTdHJpbmcuc3VwZXJjbGFzcy5jb25zdHJ1Y3Rvci5jYWxsKHRoaXMsIHBhcmFtcyk7XG4gICAgdGhpcy5oVCA9IFwiMGNcIjtcbn07XG5KU1guZXh0ZW5kKEtKVVIuYXNuMS5ERVJVVEY4U3RyaW5nLCBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmcpO1xuXG4vLyAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxuLyoqXG4gKiBjbGFzcyBmb3IgQVNOLjEgREVSIE51bWVyaWNTdHJpbmdcbiAqIEBuYW1lIEtKVVIuYXNuMS5ERVJOdW1lcmljU3RyaW5nXG4gKiBAY2xhc3MgY2xhc3MgZm9yIEFTTi4xIERFUiBOdW1lcmljU3RyaW5nXG4gKiBAcGFyYW0ge0FycmF5fSBwYXJhbXMgYXNzb2NpYXRpdmUgYXJyYXkgb2YgcGFyYW1ldGVycyAoZXguIHsnc3RyJzogJ2FhYSd9KVxuICogQGV4dGVuZHMgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nXG4gKiBAZGVzY3JpcHRpb25cbiAqIEBzZWUgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nIC0gc3VwZXJjbGFzc1xuICovXG5LSlVSLmFzbjEuREVSTnVtZXJpY1N0cmluZyA9IGZ1bmN0aW9uKHBhcmFtcykge1xuICAgIEtKVVIuYXNuMS5ERVJOdW1lcmljU3RyaW5nLnN1cGVyY2xhc3MuY29uc3RydWN0b3IuY2FsbCh0aGlzLCBwYXJhbXMpO1xuICAgIHRoaXMuaFQgPSBcIjEyXCI7XG59O1xuSlNYLmV4dGVuZChLSlVSLmFzbjEuREVSTnVtZXJpY1N0cmluZywgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nKTtcblxuLy8gKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcbi8qKlxuICogY2xhc3MgZm9yIEFTTi4xIERFUiBQcmludGFibGVTdHJpbmdcbiAqIEBuYW1lIEtKVVIuYXNuMS5ERVJQcmludGFibGVTdHJpbmdcbiAqIEBjbGFzcyBjbGFzcyBmb3IgQVNOLjEgREVSIFByaW50YWJsZVN0cmluZ1xuICogQHBhcmFtIHtBcnJheX0gcGFyYW1zIGFzc29jaWF0aXZlIGFycmF5IG9mIHBhcmFtZXRlcnMgKGV4LiB7J3N0cic6ICdhYWEnfSlcbiAqIEBleHRlbmRzIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZ1xuICogQGRlc2NyaXB0aW9uXG4gKiBAc2VlIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZyAtIHN1cGVyY2xhc3NcbiAqL1xuS0pVUi5hc24xLkRFUlByaW50YWJsZVN0cmluZyA9IGZ1bmN0aW9uKHBhcmFtcykge1xuICAgIEtKVVIuYXNuMS5ERVJQcmludGFibGVTdHJpbmcuc3VwZXJjbGFzcy5jb25zdHJ1Y3Rvci5jYWxsKHRoaXMsIHBhcmFtcyk7XG4gICAgdGhpcy5oVCA9IFwiMTNcIjtcbn07XG5KU1guZXh0ZW5kKEtKVVIuYXNuMS5ERVJQcmludGFibGVTdHJpbmcsIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cmluZyk7XG5cbi8vICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXG4vKipcbiAqIGNsYXNzIGZvciBBU04uMSBERVIgVGVsZXRleFN0cmluZ1xuICogQG5hbWUgS0pVUi5hc24xLkRFUlRlbGV0ZXhTdHJpbmdcbiAqIEBjbGFzcyBjbGFzcyBmb3IgQVNOLjEgREVSIFRlbGV0ZXhTdHJpbmdcbiAqIEBwYXJhbSB7QXJyYXl9IHBhcmFtcyBhc3NvY2lhdGl2ZSBhcnJheSBvZiBwYXJhbWV0ZXJzIChleC4geydzdHInOiAnYWFhJ30pXG4gKiBAZXh0ZW5kcyBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmdcbiAqIEBkZXNjcmlwdGlvblxuICogQHNlZSBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmcgLSBzdXBlcmNsYXNzXG4gKi9cbktKVVIuYXNuMS5ERVJUZWxldGV4U3RyaW5nID0gZnVuY3Rpb24ocGFyYW1zKSB7XG4gICAgS0pVUi5hc24xLkRFUlRlbGV0ZXhTdHJpbmcuc3VwZXJjbGFzcy5jb25zdHJ1Y3Rvci5jYWxsKHRoaXMsIHBhcmFtcyk7XG4gICAgdGhpcy5oVCA9IFwiMTRcIjtcbn07XG5KU1guZXh0ZW5kKEtKVVIuYXNuMS5ERVJUZWxldGV4U3RyaW5nLCBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJpbmcpO1xuXG4vLyAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxuLyoqXG4gKiBjbGFzcyBmb3IgQVNOLjEgREVSIElBNVN0cmluZ1xuICogQG5hbWUgS0pVUi5hc24xLkRFUklBNVN0cmluZ1xuICogQGNsYXNzIGNsYXNzIGZvciBBU04uMSBERVIgSUE1U3RyaW5nXG4gKiBAcGFyYW0ge0FycmF5fSBwYXJhbXMgYXNzb2NpYXRpdmUgYXJyYXkgb2YgcGFyYW1ldGVycyAoZXguIHsnc3RyJzogJ2FhYSd9KVxuICogQGV4dGVuZHMgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nXG4gKiBAZGVzY3JpcHRpb25cbiAqIEBzZWUgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nIC0gc3VwZXJjbGFzc1xuICovXG5LSlVSLmFzbjEuREVSSUE1U3RyaW5nID0gZnVuY3Rpb24ocGFyYW1zKSB7XG4gICAgS0pVUi5hc24xLkRFUklBNVN0cmluZy5zdXBlcmNsYXNzLmNvbnN0cnVjdG9yLmNhbGwodGhpcywgcGFyYW1zKTtcbiAgICB0aGlzLmhUID0gXCIxNlwiO1xufTtcbkpTWC5leHRlbmQoS0pVUi5hc24xLkRFUklBNVN0cmluZywgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RyaW5nKTtcblxuLy8gKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcbi8qKlxuICogY2xhc3MgZm9yIEFTTi4xIERFUiBVVENUaW1lXG4gKiBAbmFtZSBLSlVSLmFzbjEuREVSVVRDVGltZVxuICogQGNsYXNzIGNsYXNzIGZvciBBU04uMSBERVIgVVRDVGltZVxuICogQHBhcmFtIHtBcnJheX0gcGFyYW1zIGFzc29jaWF0aXZlIGFycmF5IG9mIHBhcmFtZXRlcnMgKGV4LiB7J3N0cic6ICcxMzA0MzAyMzU5NTlaJ30pXG4gKiBAZXh0ZW5kcyBLSlVSLmFzbjEuREVSQWJzdHJhY3RUaW1lXG4gKiBAZGVzY3JpcHRpb25cbiAqIDxici8+XG4gKiBBcyBmb3IgYXJndW1lbnQgJ3BhcmFtcycgZm9yIGNvbnN0cnVjdG9yLCB5b3UgY2FuIHNwZWNpZnkgb25lIG9mXG4gKiBmb2xsb3dpbmcgcHJvcGVydGllczpcbiAqIDx1bD5cbiAqIDxsaT5zdHIgLSBzcGVjaWZ5IGluaXRpYWwgQVNOLjEgdmFsdWUoVikgYnkgYSBzdHJpbmcgKGV4LicxMzA0MzAyMzU5NTlaJyk8L2xpPlxuICogPGxpPmhleCAtIHNwZWNpZnkgaW5pdGlhbCBBU04uMSB2YWx1ZShWKSBieSBhIGhleGFkZWNpbWFsIHN0cmluZzwvbGk+XG4gKiA8bGk+ZGF0ZSAtIHNwZWNpZnkgRGF0ZSBvYmplY3QuPC9saT5cbiAqIDwvdWw+XG4gKiBOT1RFOiAncGFyYW1zJyBjYW4gYmUgb21pdHRlZC5cbiAqIDxoND5FWEFNUExFUzwvaDQ+XG4gKiBAZXhhbXBsZVxuICogdmFyIGQxID0gbmV3IEtKVVIuYXNuMS5ERVJVVENUaW1lKCk7XG4gKiBkMS5zZXRTdHJpbmcoJzEzMDQzMDEyNTk1OVonKTtcbiAqXG4gKiB2YXIgZDIgPSBuZXcgS0pVUi5hc24xLkRFUlVUQ1RpbWUoeydzdHInOiAnMTMwNDMwMTI1OTU5Wid9KTtcbiAqXG4gKiB2YXIgZDMgPSBuZXcgS0pVUi5hc24xLkRFUlVUQ1RpbWUoeydkYXRlJzogbmV3IERhdGUoRGF0ZS5VVEMoMjAxNSwgMCwgMzEsIDAsIDAsIDAsIDApKX0pO1xuICovXG5LSlVSLmFzbjEuREVSVVRDVGltZSA9IGZ1bmN0aW9uKHBhcmFtcykge1xuICAgIEtKVVIuYXNuMS5ERVJVVENUaW1lLnN1cGVyY2xhc3MuY29uc3RydWN0b3IuY2FsbCh0aGlzLCBwYXJhbXMpO1xuICAgIHRoaXMuaFQgPSBcIjE3XCI7XG5cbiAgICAvKipcbiAgICAgKiBzZXQgdmFsdWUgYnkgYSBEYXRlIG9iamVjdFxuICAgICAqIEBuYW1lIHNldEJ5RGF0ZVxuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuREVSVVRDVGltZVxuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEBwYXJhbSB7RGF0ZX0gZGF0ZU9iamVjdCBEYXRlIG9iamVjdCB0byBzZXQgQVNOLjEgdmFsdWUoVilcbiAgICAgKi9cbiAgICB0aGlzLnNldEJ5RGF0ZSA9IGZ1bmN0aW9uKGRhdGVPYmplY3QpIHtcblx0dGhpcy5oVExWID0gbnVsbDtcblx0dGhpcy5pc01vZGlmaWVkID0gdHJ1ZTtcblx0dGhpcy5kYXRlID0gZGF0ZU9iamVjdDtcblx0dGhpcy5zID0gdGhpcy5mb3JtYXREYXRlKHRoaXMuZGF0ZSwgJ3V0YycpO1xuXHR0aGlzLmhWID0gc3RvaGV4KHRoaXMucyk7XG4gICAgfTtcblxuICAgIGlmICh0eXBlb2YgcGFyYW1zICE9IFwidW5kZWZpbmVkXCIpIHtcblx0aWYgKHR5cGVvZiBwYXJhbXNbJ3N0ciddICE9IFwidW5kZWZpbmVkXCIpIHtcblx0ICAgIHRoaXMuc2V0U3RyaW5nKHBhcmFtc1snc3RyJ10pO1xuXHR9IGVsc2UgaWYgKHR5cGVvZiBwYXJhbXNbJ2hleCddICE9IFwidW5kZWZpbmVkXCIpIHtcblx0ICAgIHRoaXMuc2V0U3RyaW5nSGV4KHBhcmFtc1snaGV4J10pO1xuXHR9IGVsc2UgaWYgKHR5cGVvZiBwYXJhbXNbJ2RhdGUnXSAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdCAgICB0aGlzLnNldEJ5RGF0ZShwYXJhbXNbJ2RhdGUnXSk7XG5cdH1cbiAgICB9XG59O1xuSlNYLmV4dGVuZChLSlVSLmFzbjEuREVSVVRDVGltZSwgS0pVUi5hc24xLkRFUkFic3RyYWN0VGltZSk7XG5cbi8vICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXG4vKipcbiAqIGNsYXNzIGZvciBBU04uMSBERVIgR2VuZXJhbGl6ZWRUaW1lXG4gKiBAbmFtZSBLSlVSLmFzbjEuREVSR2VuZXJhbGl6ZWRUaW1lXG4gKiBAY2xhc3MgY2xhc3MgZm9yIEFTTi4xIERFUiBHZW5lcmFsaXplZFRpbWVcbiAqIEBwYXJhbSB7QXJyYXl9IHBhcmFtcyBhc3NvY2lhdGl2ZSBhcnJheSBvZiBwYXJhbWV0ZXJzIChleC4geydzdHInOiAnMjAxMzA0MzAyMzU5NTlaJ30pXG4gKiBAZXh0ZW5kcyBLSlVSLmFzbjEuREVSQWJzdHJhY3RUaW1lXG4gKiBAZGVzY3JpcHRpb25cbiAqIDxici8+XG4gKiBBcyBmb3IgYXJndW1lbnQgJ3BhcmFtcycgZm9yIGNvbnN0cnVjdG9yLCB5b3UgY2FuIHNwZWNpZnkgb25lIG9mXG4gKiBmb2xsb3dpbmcgcHJvcGVydGllczpcbiAqIDx1bD5cbiAqIDxsaT5zdHIgLSBzcGVjaWZ5IGluaXRpYWwgQVNOLjEgdmFsdWUoVikgYnkgYSBzdHJpbmcgKGV4LicyMDEzMDQzMDIzNTk1OVonKTwvbGk+XG4gKiA8bGk+aGV4IC0gc3BlY2lmeSBpbml0aWFsIEFTTi4xIHZhbHVlKFYpIGJ5IGEgaGV4YWRlY2ltYWwgc3RyaW5nPC9saT5cbiAqIDxsaT5kYXRlIC0gc3BlY2lmeSBEYXRlIG9iamVjdC48L2xpPlxuICogPC91bD5cbiAqIE5PVEU6ICdwYXJhbXMnIGNhbiBiZSBvbWl0dGVkLlxuICovXG5LSlVSLmFzbjEuREVSR2VuZXJhbGl6ZWRUaW1lID0gZnVuY3Rpb24ocGFyYW1zKSB7XG4gICAgS0pVUi5hc24xLkRFUkdlbmVyYWxpemVkVGltZS5zdXBlcmNsYXNzLmNvbnN0cnVjdG9yLmNhbGwodGhpcywgcGFyYW1zKTtcbiAgICB0aGlzLmhUID0gXCIxOFwiO1xuXG4gICAgLyoqXG4gICAgICogc2V0IHZhbHVlIGJ5IGEgRGF0ZSBvYmplY3RcbiAgICAgKiBAbmFtZSBzZXRCeURhdGVcbiAgICAgKiBAbWVtYmVyT2YgS0pVUi5hc24xLkRFUkdlbmVyYWxpemVkVGltZVxuICAgICAqIEBmdW5jdGlvblxuICAgICAqIEBwYXJhbSB7RGF0ZX0gZGF0ZU9iamVjdCBEYXRlIG9iamVjdCB0byBzZXQgQVNOLjEgdmFsdWUoVilcbiAgICAgKiBAZXhhbXBsZVxuICAgICAqIFdoZW4geW91IHNwZWNpZnkgVVRDIHRpbWUsIHVzZSAnRGF0ZS5VVEMnIG1ldGhvZCBsaWtlIHRoaXM6PGJyLz5cbiAgICAgKiB2YXIgbyA9IG5ldyBERVJVVENUaW1lKCk7XG4gICAgICogdmFyIGRhdGUgPSBuZXcgRGF0ZShEYXRlLlVUQygyMDE1LCAwLCAzMSwgMjMsIDU5LCA1OSwgMCkpOyAjMjAxNUpBTjMxIDIzOjU5OjU5XG4gICAgICogby5zZXRCeURhdGUoZGF0ZSk7XG4gICAgICovXG4gICAgdGhpcy5zZXRCeURhdGUgPSBmdW5jdGlvbihkYXRlT2JqZWN0KSB7XG5cdHRoaXMuaFRMViA9IG51bGw7XG5cdHRoaXMuaXNNb2RpZmllZCA9IHRydWU7XG5cdHRoaXMuZGF0ZSA9IGRhdGVPYmplY3Q7XG5cdHRoaXMucyA9IHRoaXMuZm9ybWF0RGF0ZSh0aGlzLmRhdGUsICdnZW4nKTtcblx0dGhpcy5oViA9IHN0b2hleCh0aGlzLnMpO1xuICAgIH07XG5cbiAgICBpZiAodHlwZW9mIHBhcmFtcyAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdGlmICh0eXBlb2YgcGFyYW1zWydzdHInXSAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdCAgICB0aGlzLnNldFN0cmluZyhwYXJhbXNbJ3N0ciddKTtcblx0fSBlbHNlIGlmICh0eXBlb2YgcGFyYW1zWydoZXgnXSAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdCAgICB0aGlzLnNldFN0cmluZ0hleChwYXJhbXNbJ2hleCddKTtcblx0fSBlbHNlIGlmICh0eXBlb2YgcGFyYW1zWydkYXRlJ10gIT0gXCJ1bmRlZmluZWRcIikge1xuXHQgICAgdGhpcy5zZXRCeURhdGUocGFyYW1zWydkYXRlJ10pO1xuXHR9XG4gICAgfVxufTtcbkpTWC5leHRlbmQoS0pVUi5hc24xLkRFUkdlbmVyYWxpemVkVGltZSwgS0pVUi5hc24xLkRFUkFic3RyYWN0VGltZSk7XG5cbi8vICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXG4vKipcbiAqIGNsYXNzIGZvciBBU04uMSBERVIgU2VxdWVuY2VcbiAqIEBuYW1lIEtKVVIuYXNuMS5ERVJTZXF1ZW5jZVxuICogQGNsYXNzIGNsYXNzIGZvciBBU04uMSBERVIgU2VxdWVuY2VcbiAqIEBleHRlbmRzIEtKVVIuYXNuMS5ERVJBYnN0cmFjdFN0cnVjdHVyZWRcbiAqIEBkZXNjcmlwdGlvblxuICogPGJyLz5cbiAqIEFzIGZvciBhcmd1bWVudCAncGFyYW1zJyBmb3IgY29uc3RydWN0b3IsIHlvdSBjYW4gc3BlY2lmeSBvbmUgb2ZcbiAqIGZvbGxvd2luZyBwcm9wZXJ0aWVzOlxuICogPHVsPlxuICogPGxpPmFycmF5IC0gc3BlY2lmeSBhcnJheSBvZiBBU04xT2JqZWN0IHRvIHNldCBlbGVtZW50cyBvZiBjb250ZW50PC9saT5cbiAqIDwvdWw+XG4gKiBOT1RFOiAncGFyYW1zJyBjYW4gYmUgb21pdHRlZC5cbiAqL1xuS0pVUi5hc24xLkRFUlNlcXVlbmNlID0gZnVuY3Rpb24ocGFyYW1zKSB7XG4gICAgS0pVUi5hc24xLkRFUlNlcXVlbmNlLnN1cGVyY2xhc3MuY29uc3RydWN0b3IuY2FsbCh0aGlzLCBwYXJhbXMpO1xuICAgIHRoaXMuaFQgPSBcIjMwXCI7XG4gICAgdGhpcy5nZXRGcmVzaFZhbHVlSGV4ID0gZnVuY3Rpb24oKSB7XG5cdHZhciBoID0gJyc7XG5cdGZvciAodmFyIGkgPSAwOyBpIDwgdGhpcy5hc24xQXJyYXkubGVuZ3RoOyBpKyspIHtcblx0ICAgIHZhciBhc24xT2JqID0gdGhpcy5hc24xQXJyYXlbaV07XG5cdCAgICBoICs9IGFzbjFPYmouZ2V0RW5jb2RlZEhleCgpO1xuXHR9XG5cdHRoaXMuaFYgPSBoO1xuXHRyZXR1cm4gdGhpcy5oVjtcbiAgICB9O1xufTtcbkpTWC5leHRlbmQoS0pVUi5hc24xLkRFUlNlcXVlbmNlLCBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJ1Y3R1cmVkKTtcblxuLy8gKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcbi8qKlxuICogY2xhc3MgZm9yIEFTTi4xIERFUiBTZXRcbiAqIEBuYW1lIEtKVVIuYXNuMS5ERVJTZXRcbiAqIEBjbGFzcyBjbGFzcyBmb3IgQVNOLjEgREVSIFNldFxuICogQGV4dGVuZHMgS0pVUi5hc24xLkRFUkFic3RyYWN0U3RydWN0dXJlZFxuICogQGRlc2NyaXB0aW9uXG4gKiA8YnIvPlxuICogQXMgZm9yIGFyZ3VtZW50ICdwYXJhbXMnIGZvciBjb25zdHJ1Y3RvciwgeW91IGNhbiBzcGVjaWZ5IG9uZSBvZlxuICogZm9sbG93aW5nIHByb3BlcnRpZXM6XG4gKiA8dWw+XG4gKiA8bGk+YXJyYXkgLSBzcGVjaWZ5IGFycmF5IG9mIEFTTjFPYmplY3QgdG8gc2V0IGVsZW1lbnRzIG9mIGNvbnRlbnQ8L2xpPlxuICogPC91bD5cbiAqIE5PVEU6ICdwYXJhbXMnIGNhbiBiZSBvbWl0dGVkLlxuICovXG5LSlVSLmFzbjEuREVSU2V0ID0gZnVuY3Rpb24ocGFyYW1zKSB7XG4gICAgS0pVUi5hc24xLkRFUlNldC5zdXBlcmNsYXNzLmNvbnN0cnVjdG9yLmNhbGwodGhpcywgcGFyYW1zKTtcbiAgICB0aGlzLmhUID0gXCIzMVwiO1xuICAgIHRoaXMuZ2V0RnJlc2hWYWx1ZUhleCA9IGZ1bmN0aW9uKCkge1xuXHR2YXIgYSA9IG5ldyBBcnJheSgpO1xuXHRmb3IgKHZhciBpID0gMDsgaSA8IHRoaXMuYXNuMUFycmF5Lmxlbmd0aDsgaSsrKSB7XG5cdCAgICB2YXIgYXNuMU9iaiA9IHRoaXMuYXNuMUFycmF5W2ldO1xuXHQgICAgYS5wdXNoKGFzbjFPYmouZ2V0RW5jb2RlZEhleCgpKTtcblx0fVxuXHRhLnNvcnQoKTtcblx0dGhpcy5oViA9IGEuam9pbignJyk7XG5cdHJldHVybiB0aGlzLmhWO1xuICAgIH07XG59O1xuSlNYLmV4dGVuZChLSlVSLmFzbjEuREVSU2V0LCBLSlVSLmFzbjEuREVSQWJzdHJhY3RTdHJ1Y3R1cmVkKTtcblxuLy8gKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcbi8qKlxuICogY2xhc3MgZm9yIEFTTi4xIERFUiBUYWdnZWRPYmplY3RcbiAqIEBuYW1lIEtKVVIuYXNuMS5ERVJUYWdnZWRPYmplY3RcbiAqIEBjbGFzcyBjbGFzcyBmb3IgQVNOLjEgREVSIFRhZ2dlZE9iamVjdFxuICogQGV4dGVuZHMgS0pVUi5hc24xLkFTTjFPYmplY3RcbiAqIEBkZXNjcmlwdGlvblxuICogPGJyLz5cbiAqIFBhcmFtZXRlciAndGFnTm9OZXgnIGlzIEFTTi4xIHRhZyhUKSB2YWx1ZSBmb3IgdGhpcyBvYmplY3QuXG4gKiBGb3IgZXhhbXBsZSwgaWYgeW91IGZpbmQgJ1sxXScgdGFnIGluIGEgQVNOLjEgZHVtcCwgXG4gKiAndGFnTm9IZXgnIHdpbGwgYmUgJ2ExJy5cbiAqIDxici8+XG4gKiBBcyBmb3Igb3B0aW9uYWwgYXJndW1lbnQgJ3BhcmFtcycgZm9yIGNvbnN0cnVjdG9yLCB5b3UgY2FuIHNwZWNpZnkgKkFOWSogb2ZcbiAqIGZvbGxvd2luZyBwcm9wZXJ0aWVzOlxuICogPHVsPlxuICogPGxpPmV4cGxpY2l0IC0gc3BlY2lmeSB0cnVlIGlmIHRoaXMgaXMgZXhwbGljaXQgdGFnIG90aGVyd2lzZSBmYWxzZSBcbiAqICAgICAoZGVmYXVsdCBpcyAndHJ1ZScpLjwvbGk+XG4gKiA8bGk+dGFnIC0gc3BlY2lmeSB0YWcgKGRlZmF1bHQgaXMgJ2EwJyB3aGljaCBtZWFucyBbMF0pPC9saT5cbiAqIDxsaT5vYmogLSBzcGVjaWZ5IEFTTjFPYmplY3Qgd2hpY2ggaXMgdGFnZ2VkPC9saT5cbiAqIDwvdWw+XG4gKiBAZXhhbXBsZVxuICogZDEgPSBuZXcgS0pVUi5hc24xLkRFUlVURjhTdHJpbmcoeydzdHInOidhJ30pO1xuICogZDIgPSBuZXcgS0pVUi5hc24xLkRFUlRhZ2dlZE9iamVjdCh7J29iaic6IGQxfSk7XG4gKiBoZXggPSBkMi5nZXRFbmNvZGVkSGV4KCk7XG4gKi9cbktKVVIuYXNuMS5ERVJUYWdnZWRPYmplY3QgPSBmdW5jdGlvbihwYXJhbXMpIHtcbiAgICBLSlVSLmFzbjEuREVSVGFnZ2VkT2JqZWN0LnN1cGVyY2xhc3MuY29uc3RydWN0b3IuY2FsbCh0aGlzKTtcbiAgICB0aGlzLmhUID0gXCJhMFwiO1xuICAgIHRoaXMuaFYgPSAnJztcbiAgICB0aGlzLmlzRXhwbGljaXQgPSB0cnVlO1xuICAgIHRoaXMuYXNuMU9iamVjdCA9IG51bGw7XG5cbiAgICAvKipcbiAgICAgKiBzZXQgdmFsdWUgYnkgYW4gQVNOMU9iamVjdFxuICAgICAqIEBuYW1lIHNldFN0cmluZ1xuICAgICAqIEBtZW1iZXJPZiBLSlVSLmFzbjEuREVSVGFnZ2VkT2JqZWN0XG4gICAgICogQGZ1bmN0aW9uXG4gICAgICogQHBhcmFtIHtCb29sZWFufSBpc0V4cGxpY2l0RmxhZyBmbGFnIGZvciBleHBsaWNpdC9pbXBsaWNpdCB0YWdcbiAgICAgKiBAcGFyYW0ge0ludGVnZXJ9IHRhZ05vSGV4IGhleGFkZWNpbWFsIHN0cmluZyBvZiBBU04uMSB0YWdcbiAgICAgKiBAcGFyYW0ge0FTTjFPYmplY3R9IGFzbjFPYmplY3QgQVNOLjEgdG8gZW5jYXBzdWxhdGVcbiAgICAgKi9cbiAgICB0aGlzLnNldEFTTjFPYmplY3QgPSBmdW5jdGlvbihpc0V4cGxpY2l0RmxhZywgdGFnTm9IZXgsIGFzbjFPYmplY3QpIHtcblx0dGhpcy5oVCA9IHRhZ05vSGV4O1xuXHR0aGlzLmlzRXhwbGljaXQgPSBpc0V4cGxpY2l0RmxhZztcblx0dGhpcy5hc24xT2JqZWN0ID0gYXNuMU9iamVjdDtcblx0aWYgKHRoaXMuaXNFeHBsaWNpdCkge1xuXHQgICAgdGhpcy5oViA9IHRoaXMuYXNuMU9iamVjdC5nZXRFbmNvZGVkSGV4KCk7XG5cdCAgICB0aGlzLmhUTFYgPSBudWxsO1xuXHQgICAgdGhpcy5pc01vZGlmaWVkID0gdHJ1ZTtcblx0fSBlbHNlIHtcblx0ICAgIHRoaXMuaFYgPSBudWxsO1xuXHQgICAgdGhpcy5oVExWID0gYXNuMU9iamVjdC5nZXRFbmNvZGVkSGV4KCk7XG5cdCAgICB0aGlzLmhUTFYgPSB0aGlzLmhUTFYucmVwbGFjZSgvXi4uLywgdGFnTm9IZXgpO1xuXHQgICAgdGhpcy5pc01vZGlmaWVkID0gZmFsc2U7XG5cdH1cbiAgICB9O1xuXG4gICAgdGhpcy5nZXRGcmVzaFZhbHVlSGV4ID0gZnVuY3Rpb24oKSB7XG5cdHJldHVybiB0aGlzLmhWO1xuICAgIH07XG5cbiAgICBpZiAodHlwZW9mIHBhcmFtcyAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdGlmICh0eXBlb2YgcGFyYW1zWyd0YWcnXSAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdCAgICB0aGlzLmhUID0gcGFyYW1zWyd0YWcnXTtcblx0fVxuXHRpZiAodHlwZW9mIHBhcmFtc1snZXhwbGljaXQnXSAhPSBcInVuZGVmaW5lZFwiKSB7XG5cdCAgICB0aGlzLmlzRXhwbGljaXQgPSBwYXJhbXNbJ2V4cGxpY2l0J107XG5cdH1cblx0aWYgKHR5cGVvZiBwYXJhbXNbJ29iaiddICE9IFwidW5kZWZpbmVkXCIpIHtcblx0ICAgIHRoaXMuYXNuMU9iamVjdCA9IHBhcmFtc1snb2JqJ107XG5cdCAgICB0aGlzLnNldEFTTjFPYmplY3QodGhpcy5pc0V4cGxpY2l0LCB0aGlzLmhULCB0aGlzLmFzbjFPYmplY3QpO1xuXHR9XG4gICAgfVxufTtcbkpTWC5leHRlbmQoS0pVUi5hc24xLkRFUlRhZ2dlZE9iamVjdCwgS0pVUi5hc24xLkFTTjFPYmplY3QpO1xuLy8gSGV4IEphdmFTY3JpcHQgZGVjb2RlclxuLy8gQ29weXJpZ2h0IChjKSAyMDA4LTIwMTMgTGFwbyBMdWNoaW5pIDxsYXBvQGxhcG8uaXQ+XG5cbi8vIFBlcm1pc3Npb24gdG8gdXNlLCBjb3B5LCBtb2RpZnksIGFuZC9vciBkaXN0cmlidXRlIHRoaXMgc29mdHdhcmUgZm9yIGFueVxuLy8gcHVycG9zZSB3aXRoIG9yIHdpdGhvdXQgZmVlIGlzIGhlcmVieSBncmFudGVkLCBwcm92aWRlZCB0aGF0IHRoZSBhYm92ZVxuLy8gY29weXJpZ2h0IG5vdGljZSBhbmQgdGhpcyBwZXJtaXNzaW9uIG5vdGljZSBhcHBlYXIgaW4gYWxsIGNvcGllcy5cbi8vIFxuLy8gVEhFIFNPRlRXQVJFIElTIFBST1ZJREVEIFwiQVMgSVNcIiBBTkQgVEhFIEFVVEhPUiBESVNDTEFJTVMgQUxMIFdBUlJBTlRJRVNcbi8vIFdJVEggUkVHQVJEIFRPIFRISVMgU09GVFdBUkUgSU5DTFVESU5HIEFMTCBJTVBMSUVEIFdBUlJBTlRJRVMgT0Zcbi8vIE1FUkNIQU5UQUJJTElUWSBBTkQgRklUTkVTUy4gSU4gTk8gRVZFTlQgU0hBTEwgVEhFIEFVVEhPUiBCRSBMSUFCTEUgRk9SXG4vLyBBTlkgU1BFQ0lBTCwgRElSRUNULCBJTkRJUkVDVCwgT1IgQ09OU0VRVUVOVElBTCBEQU1BR0VTIE9SIEFOWSBEQU1BR0VTXG4vLyBXSEFUU09FVkVSIFJFU1VMVElORyBGUk9NIExPU1MgT0YgVVNFLCBEQVRBIE9SIFBST0ZJVFMsIFdIRVRIRVIgSU4gQU5cbi8vIEFDVElPTiBPRiBDT05UUkFDVCwgTkVHTElHRU5DRSBPUiBPVEhFUiBUT1JUSU9VUyBBQ1RJT04sIEFSSVNJTkcgT1VUIE9GXG4vLyBPUiBJTiBDT05ORUNUSU9OIFdJVEggVEhFIFVTRSBPUiBQRVJGT1JNQU5DRSBPRiBUSElTIFNPRlRXQVJFLlxuXG4vKmpzaGludCBicm93c2VyOiB0cnVlLCBzdHJpY3Q6IHRydWUsIGltbWVkOiB0cnVlLCBsYXRlZGVmOiB0cnVlLCB1bmRlZjogdHJ1ZSwgcmVnZXhkYXNoOiBmYWxzZSAqL1xuKGZ1bmN0aW9uICh1bmRlZmluZWQpIHtcblwidXNlIHN0cmljdFwiO1xuXG52YXIgSGV4ID0ge30sXG4gICAgZGVjb2RlcjtcblxuSGV4LmRlY29kZSA9IGZ1bmN0aW9uKGEpIHtcbiAgICB2YXIgaTtcbiAgICBpZiAoZGVjb2RlciA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHZhciBoZXggPSBcIjAxMjM0NTY3ODlBQkNERUZcIixcbiAgICAgICAgICAgIGlnbm9yZSA9IFwiIFxcZlxcblxcclxcdFxcdTAwQTBcXHUyMDI4XFx1MjAyOVwiO1xuICAgICAgICBkZWNvZGVyID0gW107XG4gICAgICAgIGZvciAoaSA9IDA7IGkgPCAxNjsgKytpKVxuICAgICAgICAgICAgZGVjb2RlcltoZXguY2hhckF0KGkpXSA9IGk7XG4gICAgICAgIGhleCA9IGhleC50b0xvd2VyQ2FzZSgpO1xuICAgICAgICBmb3IgKGkgPSAxMDsgaSA8IDE2OyArK2kpXG4gICAgICAgICAgICBkZWNvZGVyW2hleC5jaGFyQXQoaSldID0gaTtcbiAgICAgICAgZm9yIChpID0gMDsgaSA8IGlnbm9yZS5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgIGRlY29kZXJbaWdub3JlLmNoYXJBdChpKV0gPSAtMTtcbiAgICB9XG4gICAgdmFyIG91dCA9IFtdLFxuICAgICAgICBiaXRzID0gMCxcbiAgICAgICAgY2hhcl9jb3VudCA9IDA7XG4gICAgZm9yIChpID0gMDsgaSA8IGEubGVuZ3RoOyArK2kpIHtcbiAgICAgICAgdmFyIGMgPSBhLmNoYXJBdChpKTtcbiAgICAgICAgaWYgKGMgPT0gJz0nKVxuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIGMgPSBkZWNvZGVyW2NdO1xuICAgICAgICBpZiAoYyA9PSAtMSlcbiAgICAgICAgICAgIGNvbnRpbnVlO1xuICAgICAgICBpZiAoYyA9PT0gdW5kZWZpbmVkKVxuICAgICAgICAgICAgdGhyb3cgJ0lsbGVnYWwgY2hhcmFjdGVyIGF0IG9mZnNldCAnICsgaTtcbiAgICAgICAgYml0cyB8PSBjO1xuICAgICAgICBpZiAoKytjaGFyX2NvdW50ID49IDIpIHtcbiAgICAgICAgICAgIG91dFtvdXQubGVuZ3RoXSA9IGJpdHM7XG4gICAgICAgICAgICBiaXRzID0gMDtcbiAgICAgICAgICAgIGNoYXJfY291bnQgPSAwO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgYml0cyA8PD0gNDtcbiAgICAgICAgfVxuICAgIH1cbiAgICBpZiAoY2hhcl9jb3VudClcbiAgICAgICAgdGhyb3cgXCJIZXggZW5jb2RpbmcgaW5jb21wbGV0ZTogNCBiaXRzIG1pc3NpbmdcIjtcbiAgICByZXR1cm4gb3V0O1xufTtcblxuLy8gZXhwb3J0IGdsb2JhbHNcbndpbmRvdy5IZXggPSBIZXg7XG59KSgpO1xuLy8gQmFzZTY0IEphdmFTY3JpcHQgZGVjb2RlclxuLy8gQ29weXJpZ2h0IChjKSAyMDA4LTIwMTMgTGFwbyBMdWNoaW5pIDxsYXBvQGxhcG8uaXQ+XG5cbi8vIFBlcm1pc3Npb24gdG8gdXNlLCBjb3B5LCBtb2RpZnksIGFuZC9vciBkaXN0cmlidXRlIHRoaXMgc29mdHdhcmUgZm9yIGFueVxuLy8gcHVycG9zZSB3aXRoIG9yIHdpdGhvdXQgZmVlIGlzIGhlcmVieSBncmFudGVkLCBwcm92aWRlZCB0aGF0IHRoZSBhYm92ZVxuLy8gY29weXJpZ2h0IG5vdGljZSBhbmQgdGhpcyBwZXJtaXNzaW9uIG5vdGljZSBhcHBlYXIgaW4gYWxsIGNvcGllcy5cbi8vIFxuLy8gVEhFIFNPRlRXQVJFIElTIFBST1ZJREVEIFwiQVMgSVNcIiBBTkQgVEhFIEFVVEhPUiBESVNDTEFJTVMgQUxMIFdBUlJBTlRJRVNcbi8vIFdJVEggUkVHQVJEIFRPIFRISVMgU09GVFdBUkUgSU5DTFVESU5HIEFMTCBJTVBMSUVEIFdBUlJBTlRJRVMgT0Zcbi8vIE1FUkNIQU5UQUJJTElUWSBBTkQgRklUTkVTUy4gSU4gTk8gRVZFTlQgU0hBTEwgVEhFIEFVVEhPUiBCRSBMSUFCTEUgRk9SXG4vLyBBTlkgU1BFQ0lBTCwgRElSRUNULCBJTkRJUkVDVCwgT1IgQ09OU0VRVUVOVElBTCBEQU1BR0VTIE9SIEFOWSBEQU1BR0VTXG4vLyBXSEFUU09FVkVSIFJFU1VMVElORyBGUk9NIExPU1MgT0YgVVNFLCBEQVRBIE9SIFBST0ZJVFMsIFdIRVRIRVIgSU4gQU5cbi8vIEFDVElPTiBPRiBDT05UUkFDVCwgTkVHTElHRU5DRSBPUiBPVEhFUiBUT1JUSU9VUyBBQ1RJT04sIEFSSVNJTkcgT1VUIE9GXG4vLyBPUiBJTiBDT05ORUNUSU9OIFdJVEggVEhFIFVTRSBPUiBQRVJGT1JNQU5DRSBPRiBUSElTIFNPRlRXQVJFLlxuXG4vKmpzaGludCBicm93c2VyOiB0cnVlLCBzdHJpY3Q6IHRydWUsIGltbWVkOiB0cnVlLCBsYXRlZGVmOiB0cnVlLCB1bmRlZjogdHJ1ZSwgcmVnZXhkYXNoOiBmYWxzZSAqL1xuKGZ1bmN0aW9uICh1bmRlZmluZWQpIHtcblwidXNlIHN0cmljdFwiO1xuXG52YXIgQmFzZTY0ID0ge30sXG4gICAgZGVjb2RlcjtcblxuQmFzZTY0LmRlY29kZSA9IGZ1bmN0aW9uIChhKSB7XG4gICAgdmFyIGk7XG4gICAgaWYgKGRlY29kZXIgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICB2YXIgYjY0ID0gXCJBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OSsvXCIsXG4gICAgICAgICAgICBpZ25vcmUgPSBcIj0gXFxmXFxuXFxyXFx0XFx1MDBBMFxcdTIwMjhcXHUyMDI5XCI7XG4gICAgICAgIGRlY29kZXIgPSBbXTtcbiAgICAgICAgZm9yIChpID0gMDsgaSA8IDY0OyArK2kpXG4gICAgICAgICAgICBkZWNvZGVyW2I2NC5jaGFyQXQoaSldID0gaTtcbiAgICAgICAgZm9yIChpID0gMDsgaSA8IGlnbm9yZS5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgIGRlY29kZXJbaWdub3JlLmNoYXJBdChpKV0gPSAtMTtcbiAgICB9XG4gICAgdmFyIG91dCA9IFtdO1xuICAgIHZhciBiaXRzID0gMCwgY2hhcl9jb3VudCA9IDA7XG4gICAgZm9yIChpID0gMDsgaSA8IGEubGVuZ3RoOyArK2kpIHtcbiAgICAgICAgdmFyIGMgPSBhLmNoYXJBdChpKTtcbiAgICAgICAgaWYgKGMgPT0gJz0nKVxuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIGMgPSBkZWNvZGVyW2NdO1xuICAgICAgICBpZiAoYyA9PSAtMSlcbiAgICAgICAgICAgIGNvbnRpbnVlO1xuICAgICAgICBpZiAoYyA9PT0gdW5kZWZpbmVkKVxuICAgICAgICAgICAgdGhyb3cgJ0lsbGVnYWwgY2hhcmFjdGVyIGF0IG9mZnNldCAnICsgaTtcbiAgICAgICAgYml0cyB8PSBjO1xuICAgICAgICBpZiAoKytjaGFyX2NvdW50ID49IDQpIHtcbiAgICAgICAgICAgIG91dFtvdXQubGVuZ3RoXSA9IChiaXRzID4+IDE2KTtcbiAgICAgICAgICAgIG91dFtvdXQubGVuZ3RoXSA9IChiaXRzID4+IDgpICYgMHhGRjtcbiAgICAgICAgICAgIG91dFtvdXQubGVuZ3RoXSA9IGJpdHMgJiAweEZGO1xuICAgICAgICAgICAgYml0cyA9IDA7XG4gICAgICAgICAgICBjaGFyX2NvdW50ID0gMDtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGJpdHMgPDw9IDY7XG4gICAgICAgIH1cbiAgICB9XG4gICAgc3dpdGNoIChjaGFyX2NvdW50KSB7XG4gICAgICBjYXNlIDE6XG4gICAgICAgIHRocm93IFwiQmFzZTY0IGVuY29kaW5nIGluY29tcGxldGU6IGF0IGxlYXN0IDIgYml0cyBtaXNzaW5nXCI7XG4gICAgICBjYXNlIDI6XG4gICAgICAgIG91dFtvdXQubGVuZ3RoXSA9IChiaXRzID4+IDEwKTtcbiAgICAgICAgYnJlYWs7XG4gICAgICBjYXNlIDM6XG4gICAgICAgIG91dFtvdXQubGVuZ3RoXSA9IChiaXRzID4+IDE2KTtcbiAgICAgICAgb3V0W291dC5sZW5ndGhdID0gKGJpdHMgPj4gOCkgJiAweEZGO1xuICAgICAgICBicmVhaztcbiAgICB9XG4gICAgcmV0dXJuIG91dDtcbn07XG5cbkJhc2U2NC5yZSA9IC8tLS0tLUJFR0lOIFteLV0rLS0tLS0oW0EtWmEtejAtOStcXC89XFxzXSspLS0tLS1FTkQgW14tXSstLS0tLXxiZWdpbi1iYXNlNjRbXlxcbl0rXFxuKFtBLVphLXowLTkrXFwvPVxcc10rKT09PT0vO1xuQmFzZTY0LnVuYXJtb3IgPSBmdW5jdGlvbiAoYSkge1xuICAgIHZhciBtID0gQmFzZTY0LnJlLmV4ZWMoYSk7XG4gICAgaWYgKG0pIHtcbiAgICAgICAgaWYgKG1bMV0pXG4gICAgICAgICAgICBhID0gbVsxXTtcbiAgICAgICAgZWxzZSBpZiAobVsyXSlcbiAgICAgICAgICAgIGEgPSBtWzJdO1xuICAgICAgICBlbHNlXG4gICAgICAgICAgICB0aHJvdyBcIlJlZ0V4cCBvdXQgb2Ygc3luY1wiO1xuICAgIH1cbiAgICByZXR1cm4gQmFzZTY0LmRlY29kZShhKTtcbn07XG5cbi8vIGV4cG9ydCBnbG9iYWxzXG53aW5kb3cuQmFzZTY0ID0gQmFzZTY0O1xufSkoKTtcbi8vIEFTTi4xIEphdmFTY3JpcHQgZGVjb2RlclxuLy8gQ29weXJpZ2h0IChjKSAyMDA4LTIwMTMgTGFwbyBMdWNoaW5pIDxsYXBvQGxhcG8uaXQ+XG5cbi8vIFBlcm1pc3Npb24gdG8gdXNlLCBjb3B5LCBtb2RpZnksIGFuZC9vciBkaXN0cmlidXRlIHRoaXMgc29mdHdhcmUgZm9yIGFueVxuLy8gcHVycG9zZSB3aXRoIG9yIHdpdGhvdXQgZmVlIGlzIGhlcmVieSBncmFudGVkLCBwcm92aWRlZCB0aGF0IHRoZSBhYm92ZVxuLy8gY29weXJpZ2h0IG5vdGljZSBhbmQgdGhpcyBwZXJtaXNzaW9uIG5vdGljZSBhcHBlYXIgaW4gYWxsIGNvcGllcy5cbi8vIFxuLy8gVEhFIFNPRlRXQVJFIElTIFBST1ZJREVEIFwiQVMgSVNcIiBBTkQgVEhFIEFVVEhPUiBESVNDTEFJTVMgQUxMIFdBUlJBTlRJRVNcbi8vIFdJVEggUkVHQVJEIFRPIFRISVMgU09GVFdBUkUgSU5DTFVESU5HIEFMTCBJTVBMSUVEIFdBUlJBTlRJRVMgT0Zcbi8vIE1FUkNIQU5UQUJJTElUWSBBTkQgRklUTkVTUy4gSU4gTk8gRVZFTlQgU0hBTEwgVEhFIEFVVEhPUiBCRSBMSUFCTEUgRk9SXG4vLyBBTlkgU1BFQ0lBTCwgRElSRUNULCBJTkRJUkVDVCwgT1IgQ09OU0VRVUVOVElBTCBEQU1BR0VTIE9SIEFOWSBEQU1BR0VTXG4vLyBXSEFUU09FVkVSIFJFU1VMVElORyBGUk9NIExPU1MgT0YgVVNFLCBEQVRBIE9SIFBST0ZJVFMsIFdIRVRIRVIgSU4gQU5cbi8vIEFDVElPTiBPRiBDT05UUkFDVCwgTkVHTElHRU5DRSBPUiBPVEhFUiBUT1JUSU9VUyBBQ1RJT04sIEFSSVNJTkcgT1VUIE9GXG4vLyBPUiBJTiBDT05ORUNUSU9OIFdJVEggVEhFIFVTRSBPUiBQRVJGT1JNQU5DRSBPRiBUSElTIFNPRlRXQVJFLlxuXG4vKmpzaGludCBicm93c2VyOiB0cnVlLCBzdHJpY3Q6IHRydWUsIGltbWVkOiB0cnVlLCBsYXRlZGVmOiB0cnVlLCB1bmRlZjogdHJ1ZSwgcmVnZXhkYXNoOiBmYWxzZSAqL1xuLypnbG9iYWwgb2lkcyAqL1xuKGZ1bmN0aW9uICh1bmRlZmluZWQpIHtcblwidXNlIHN0cmljdFwiO1xuXG52YXIgaGFyZExpbWl0ID0gMTAwLFxuICAgIGVsbGlwc2lzID0gXCJcXHUyMDI2XCIsXG4gICAgRE9NID0ge1xuICAgICAgICB0YWc6IGZ1bmN0aW9uICh0YWdOYW1lLCBjbGFzc05hbWUpIHtcbiAgICAgICAgICAgIHZhciB0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCh0YWdOYW1lKTtcbiAgICAgICAgICAgIHQuY2xhc3NOYW1lID0gY2xhc3NOYW1lO1xuICAgICAgICAgICAgcmV0dXJuIHQ7XG4gICAgICAgIH0sXG4gICAgICAgIHRleHQ6IGZ1bmN0aW9uIChzdHIpIHtcbiAgICAgICAgICAgIHJldHVybiBkb2N1bWVudC5jcmVhdGVUZXh0Tm9kZShzdHIpO1xuICAgICAgICB9XG4gICAgfTtcblxuZnVuY3Rpb24gU3RyZWFtKGVuYywgcG9zKSB7XG4gICAgaWYgKGVuYyBpbnN0YW5jZW9mIFN0cmVhbSkge1xuICAgICAgICB0aGlzLmVuYyA9IGVuYy5lbmM7XG4gICAgICAgIHRoaXMucG9zID0gZW5jLnBvcztcbiAgICB9IGVsc2Uge1xuICAgICAgICB0aGlzLmVuYyA9IGVuYztcbiAgICAgICAgdGhpcy5wb3MgPSBwb3M7XG4gICAgfVxufVxuU3RyZWFtLnByb3RvdHlwZS5nZXQgPSBmdW5jdGlvbiAocG9zKSB7XG4gICAgaWYgKHBvcyA9PT0gdW5kZWZpbmVkKVxuICAgICAgICBwb3MgPSB0aGlzLnBvcysrO1xuICAgIGlmIChwb3MgPj0gdGhpcy5lbmMubGVuZ3RoKVxuICAgICAgICB0aHJvdyAnUmVxdWVzdGluZyBieXRlIG9mZnNldCAnICsgcG9zICsgJyBvbiBhIHN0cmVhbSBvZiBsZW5ndGggJyArIHRoaXMuZW5jLmxlbmd0aDtcbiAgICByZXR1cm4gdGhpcy5lbmNbcG9zXTtcbn07XG5TdHJlYW0ucHJvdG90eXBlLmhleERpZ2l0cyA9IFwiMDEyMzQ1Njc4OUFCQ0RFRlwiO1xuU3RyZWFtLnByb3RvdHlwZS5oZXhCeXRlID0gZnVuY3Rpb24gKGIpIHtcbiAgICByZXR1cm4gdGhpcy5oZXhEaWdpdHMuY2hhckF0KChiID4+IDQpICYgMHhGKSArIHRoaXMuaGV4RGlnaXRzLmNoYXJBdChiICYgMHhGKTtcbn07XG5TdHJlYW0ucHJvdG90eXBlLmhleER1bXAgPSBmdW5jdGlvbiAoc3RhcnQsIGVuZCwgcmF3KSB7XG4gICAgdmFyIHMgPSBcIlwiO1xuICAgIGZvciAodmFyIGkgPSBzdGFydDsgaSA8IGVuZDsgKytpKSB7XG4gICAgICAgIHMgKz0gdGhpcy5oZXhCeXRlKHRoaXMuZ2V0KGkpKTtcbiAgICAgICAgaWYgKHJhdyAhPT0gdHJ1ZSlcbiAgICAgICAgICAgIHN3aXRjaCAoaSAmIDB4Rikge1xuICAgICAgICAgICAgY2FzZSAweDc6IHMgKz0gXCIgIFwiOyBicmVhaztcbiAgICAgICAgICAgIGNhc2UgMHhGOiBzICs9IFwiXFxuXCI7IGJyZWFrO1xuICAgICAgICAgICAgZGVmYXVsdDogIHMgKz0gXCIgXCI7XG4gICAgICAgICAgICB9XG4gICAgfVxuICAgIHJldHVybiBzO1xufTtcblN0cmVhbS5wcm90b3R5cGUucGFyc2VTdHJpbmdJU08gPSBmdW5jdGlvbiAoc3RhcnQsIGVuZCkge1xuICAgIHZhciBzID0gXCJcIjtcbiAgICBmb3IgKHZhciBpID0gc3RhcnQ7IGkgPCBlbmQ7ICsraSlcbiAgICAgICAgcyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKHRoaXMuZ2V0KGkpKTtcbiAgICByZXR1cm4gcztcbn07XG5TdHJlYW0ucHJvdG90eXBlLnBhcnNlU3RyaW5nVVRGID0gZnVuY3Rpb24gKHN0YXJ0LCBlbmQpIHtcbiAgICB2YXIgcyA9IFwiXCI7XG4gICAgZm9yICh2YXIgaSA9IHN0YXJ0OyBpIDwgZW5kOyApIHtcbiAgICAgICAgdmFyIGMgPSB0aGlzLmdldChpKyspO1xuICAgICAgICBpZiAoYyA8IDEyOClcbiAgICAgICAgICAgIHMgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShjKTtcbiAgICAgICAgZWxzZSBpZiAoKGMgPiAxOTEpICYmIChjIDwgMjI0KSlcbiAgICAgICAgICAgIHMgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSgoKGMgJiAweDFGKSA8PCA2KSB8ICh0aGlzLmdldChpKyspICYgMHgzRikpO1xuICAgICAgICBlbHNlXG4gICAgICAgICAgICBzICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoKChjICYgMHgwRikgPDwgMTIpIHwgKCh0aGlzLmdldChpKyspICYgMHgzRikgPDwgNikgfCAodGhpcy5nZXQoaSsrKSAmIDB4M0YpKTtcbiAgICB9XG4gICAgcmV0dXJuIHM7XG59O1xuU3RyZWFtLnByb3RvdHlwZS5wYXJzZVN0cmluZ0JNUCA9IGZ1bmN0aW9uIChzdGFydCwgZW5kKSB7XG4gICAgdmFyIHN0ciA9IFwiXCJcbiAgICBmb3IgKHZhciBpID0gc3RhcnQ7IGkgPCBlbmQ7IGkgKz0gMikge1xuICAgICAgICB2YXIgaGlnaF9ieXRlID0gdGhpcy5nZXQoaSk7XG4gICAgICAgIHZhciBsb3dfYnl0ZSA9IHRoaXMuZ2V0KGkgKyAxKTtcbiAgICAgICAgc3RyICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoIChoaWdoX2J5dGUgPDwgOCkgKyBsb3dfYnl0ZSApO1xuICAgIH1cblxuICAgIHJldHVybiBzdHI7XG59O1xuU3RyZWFtLnByb3RvdHlwZS5yZVRpbWUgPSAvXigoPzoxWzg5XXwyXFxkKT9cXGRcXGQpKDBbMS05XXwxWzAtMl0pKDBbMS05XXxbMTJdXFxkfDNbMDFdKShbMDFdXFxkfDJbMC0zXSkoPzooWzAtNV1cXGQpKD86KFswLTVdXFxkKSg/OlsuLF0oXFxkezEsM30pKT8pPyk/KFp8Wy0rXSg/OlswXVxcZHwxWzAtMl0pKFswLTVdXFxkKT8pPyQvO1xuU3RyZWFtLnByb3RvdHlwZS5wYXJzZVRpbWUgPSBmdW5jdGlvbiAoc3RhcnQsIGVuZCkge1xuICAgIHZhciBzID0gdGhpcy5wYXJzZVN0cmluZ0lTTyhzdGFydCwgZW5kKSxcbiAgICAgICAgbSA9IHRoaXMucmVUaW1lLmV4ZWMocyk7XG4gICAgaWYgKCFtKVxuICAgICAgICByZXR1cm4gXCJVbnJlY29nbml6ZWQgdGltZTogXCIgKyBzO1xuICAgIHMgPSBtWzFdICsgXCItXCIgKyBtWzJdICsgXCItXCIgKyBtWzNdICsgXCIgXCIgKyBtWzRdO1xuICAgIGlmIChtWzVdKSB7XG4gICAgICAgIHMgKz0gXCI6XCIgKyBtWzVdO1xuICAgICAgICBpZiAobVs2XSkge1xuICAgICAgICAgICAgcyArPSBcIjpcIiArIG1bNl07XG4gICAgICAgICAgICBpZiAobVs3XSlcbiAgICAgICAgICAgICAgICBzICs9IFwiLlwiICsgbVs3XTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBpZiAobVs4XSkge1xuICAgICAgICBzICs9IFwiIFVUQ1wiO1xuICAgICAgICBpZiAobVs4XSAhPSAnWicpIHtcbiAgICAgICAgICAgIHMgKz0gbVs4XTtcbiAgICAgICAgICAgIGlmIChtWzldKVxuICAgICAgICAgICAgICAgIHMgKz0gXCI6XCIgKyBtWzldO1xuICAgICAgICB9XG4gICAgfVxuICAgIHJldHVybiBzO1xufTtcblN0cmVhbS5wcm90b3R5cGUucGFyc2VJbnRlZ2VyID0gZnVuY3Rpb24gKHN0YXJ0LCBlbmQpIHtcbiAgICAvL1RPRE8gc3VwcG9ydCBuZWdhdGl2ZSBudW1iZXJzXG4gICAgdmFyIGxlbiA9IGVuZCAtIHN0YXJ0O1xuICAgIGlmIChsZW4gPiA0KSB7XG4gICAgICAgIGxlbiA8PD0gMztcbiAgICAgICAgdmFyIHMgPSB0aGlzLmdldChzdGFydCk7XG4gICAgICAgIGlmIChzID09PSAwKVxuICAgICAgICAgICAgbGVuIC09IDg7XG4gICAgICAgIGVsc2VcbiAgICAgICAgICAgIHdoaWxlIChzIDwgMTI4KSB7XG4gICAgICAgICAgICAgICAgcyA8PD0gMTtcbiAgICAgICAgICAgICAgICAtLWxlbjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgcmV0dXJuIFwiKFwiICsgbGVuICsgXCIgYml0KVwiO1xuICAgIH1cbiAgICB2YXIgbiA9IDA7XG4gICAgZm9yICh2YXIgaSA9IHN0YXJ0OyBpIDwgZW5kOyArK2kpXG4gICAgICAgIG4gPSAobiA8PCA4KSB8IHRoaXMuZ2V0KGkpO1xuICAgIHJldHVybiBuO1xufTtcblN0cmVhbS5wcm90b3R5cGUucGFyc2VCaXRTdHJpbmcgPSBmdW5jdGlvbiAoc3RhcnQsIGVuZCkge1xuICAgIHZhciB1bnVzZWRCaXQgPSB0aGlzLmdldChzdGFydCksXG4gICAgICAgIGxlbkJpdCA9ICgoZW5kIC0gc3RhcnQgLSAxKSA8PCAzKSAtIHVudXNlZEJpdCxcbiAgICAgICAgcyA9IFwiKFwiICsgbGVuQml0ICsgXCIgYml0KVwiO1xuICAgIGlmIChsZW5CaXQgPD0gMjApIHtcbiAgICAgICAgdmFyIHNraXAgPSB1bnVzZWRCaXQ7XG4gICAgICAgIHMgKz0gXCIgXCI7XG4gICAgICAgIGZvciAodmFyIGkgPSBlbmQgLSAxOyBpID4gc3RhcnQ7IC0taSkge1xuICAgICAgICAgICAgdmFyIGIgPSB0aGlzLmdldChpKTtcbiAgICAgICAgICAgIGZvciAodmFyIGogPSBza2lwOyBqIDwgODsgKytqKVxuICAgICAgICAgICAgICAgIHMgKz0gKGIgPj4gaikgJiAxID8gXCIxXCIgOiBcIjBcIjtcbiAgICAgICAgICAgIHNraXAgPSAwO1xuICAgICAgICB9XG4gICAgfVxuICAgIHJldHVybiBzO1xufTtcblN0cmVhbS5wcm90b3R5cGUucGFyc2VPY3RldFN0cmluZyA9IGZ1bmN0aW9uIChzdGFydCwgZW5kKSB7XG4gICAgdmFyIGxlbiA9IGVuZCAtIHN0YXJ0LFxuICAgICAgICBzID0gXCIoXCIgKyBsZW4gKyBcIiBieXRlKSBcIjtcbiAgICBpZiAobGVuID4gaGFyZExpbWl0KVxuICAgICAgICBlbmQgPSBzdGFydCArIGhhcmRMaW1pdDtcbiAgICBmb3IgKHZhciBpID0gc3RhcnQ7IGkgPCBlbmQ7ICsraSlcbiAgICAgICAgcyArPSB0aGlzLmhleEJ5dGUodGhpcy5nZXQoaSkpOyAvL1RPRE86IGFsc28gdHJ5IExhdGluMT9cbiAgICBpZiAobGVuID4gaGFyZExpbWl0KVxuICAgICAgICBzICs9IGVsbGlwc2lzO1xuICAgIHJldHVybiBzO1xufTtcblN0cmVhbS5wcm90b3R5cGUucGFyc2VPSUQgPSBmdW5jdGlvbiAoc3RhcnQsIGVuZCkge1xuICAgIHZhciBzID0gJycsXG4gICAgICAgIG4gPSAwLFxuICAgICAgICBiaXRzID0gMDtcbiAgICBmb3IgKHZhciBpID0gc3RhcnQ7IGkgPCBlbmQ7ICsraSkge1xuICAgICAgICB2YXIgdiA9IHRoaXMuZ2V0KGkpO1xuICAgICAgICBuID0gKG4gPDwgNykgfCAodiAmIDB4N0YpO1xuICAgICAgICBiaXRzICs9IDc7XG4gICAgICAgIGlmICghKHYgJiAweDgwKSkgeyAvLyBmaW5pc2hlZFxuICAgICAgICAgICAgaWYgKHMgPT09ICcnKSB7XG4gICAgICAgICAgICAgICAgdmFyIG0gPSBuIDwgODAgPyBuIDwgNDAgPyAwIDogMSA6IDI7XG4gICAgICAgICAgICAgICAgcyA9IG0gKyBcIi5cIiArIChuIC0gbSAqIDQwKTtcbiAgICAgICAgICAgIH0gZWxzZVxuICAgICAgICAgICAgICAgIHMgKz0gXCIuXCIgKyAoKGJpdHMgPj0gMzEpID8gXCJiaWdpbnRcIiA6IG4pO1xuICAgICAgICAgICAgbiA9IGJpdHMgPSAwO1xuICAgICAgICB9XG4gICAgfVxuICAgIHJldHVybiBzO1xufTtcblxuZnVuY3Rpb24gQVNOMShzdHJlYW0sIGhlYWRlciwgbGVuZ3RoLCB0YWcsIHN1Yikge1xuICAgIHRoaXMuc3RyZWFtID0gc3RyZWFtO1xuICAgIHRoaXMuaGVhZGVyID0gaGVhZGVyO1xuICAgIHRoaXMubGVuZ3RoID0gbGVuZ3RoO1xuICAgIHRoaXMudGFnID0gdGFnO1xuICAgIHRoaXMuc3ViID0gc3ViO1xufVxuQVNOMS5wcm90b3R5cGUudHlwZU5hbWUgPSBmdW5jdGlvbiAoKSB7XG4gICAgaWYgKHRoaXMudGFnID09PSB1bmRlZmluZWQpXG4gICAgICAgIHJldHVybiBcInVua25vd25cIjtcbiAgICB2YXIgdGFnQ2xhc3MgPSB0aGlzLnRhZyA+PiA2LFxuICAgICAgICB0YWdDb25zdHJ1Y3RlZCA9ICh0aGlzLnRhZyA+PiA1KSAmIDEsXG4gICAgICAgIHRhZ051bWJlciA9IHRoaXMudGFnICYgMHgxRjtcbiAgICBzd2l0Y2ggKHRhZ0NsYXNzKSB7XG4gICAgY2FzZSAwOiAvLyB1bml2ZXJzYWxcbiAgICAgICAgc3dpdGNoICh0YWdOdW1iZXIpIHtcbiAgICAgICAgY2FzZSAweDAwOiByZXR1cm4gXCJFT0NcIjtcbiAgICAgICAgY2FzZSAweDAxOiByZXR1cm4gXCJCT09MRUFOXCI7XG4gICAgICAgIGNhc2UgMHgwMjogcmV0dXJuIFwiSU5URUdFUlwiO1xuICAgICAgICBjYXNlIDB4MDM6IHJldHVybiBcIkJJVF9TVFJJTkdcIjtcbiAgICAgICAgY2FzZSAweDA0OiByZXR1cm4gXCJPQ1RFVF9TVFJJTkdcIjtcbiAgICAgICAgY2FzZSAweDA1OiByZXR1cm4gXCJOVUxMXCI7XG4gICAgICAgIGNhc2UgMHgwNjogcmV0dXJuIFwiT0JKRUNUX0lERU5USUZJRVJcIjtcbiAgICAgICAgY2FzZSAweDA3OiByZXR1cm4gXCJPYmplY3REZXNjcmlwdG9yXCI7XG4gICAgICAgIGNhc2UgMHgwODogcmV0dXJuIFwiRVhURVJOQUxcIjtcbiAgICAgICAgY2FzZSAweDA5OiByZXR1cm4gXCJSRUFMXCI7XG4gICAgICAgIGNhc2UgMHgwQTogcmV0dXJuIFwiRU5VTUVSQVRFRFwiO1xuICAgICAgICBjYXNlIDB4MEI6IHJldHVybiBcIkVNQkVEREVEX1BEVlwiO1xuICAgICAgICBjYXNlIDB4MEM6IHJldHVybiBcIlVURjhTdHJpbmdcIjtcbiAgICAgICAgY2FzZSAweDEwOiByZXR1cm4gXCJTRVFVRU5DRVwiO1xuICAgICAgICBjYXNlIDB4MTE6IHJldHVybiBcIlNFVFwiO1xuICAgICAgICBjYXNlIDB4MTI6IHJldHVybiBcIk51bWVyaWNTdHJpbmdcIjtcbiAgICAgICAgY2FzZSAweDEzOiByZXR1cm4gXCJQcmludGFibGVTdHJpbmdcIjsgLy8gQVNDSUkgc3Vic2V0XG4gICAgICAgIGNhc2UgMHgxNDogcmV0dXJuIFwiVGVsZXRleFN0cmluZ1wiOyAvLyBha2EgVDYxU3RyaW5nXG4gICAgICAgIGNhc2UgMHgxNTogcmV0dXJuIFwiVmlkZW90ZXhTdHJpbmdcIjtcbiAgICAgICAgY2FzZSAweDE2OiByZXR1cm4gXCJJQTVTdHJpbmdcIjsgLy8gQVNDSUlcbiAgICAgICAgY2FzZSAweDE3OiByZXR1cm4gXCJVVENUaW1lXCI7XG4gICAgICAgIGNhc2UgMHgxODogcmV0dXJuIFwiR2VuZXJhbGl6ZWRUaW1lXCI7XG4gICAgICAgIGNhc2UgMHgxOTogcmV0dXJuIFwiR3JhcGhpY1N0cmluZ1wiO1xuICAgICAgICBjYXNlIDB4MUE6IHJldHVybiBcIlZpc2libGVTdHJpbmdcIjsgLy8gQVNDSUkgc3Vic2V0XG4gICAgICAgIGNhc2UgMHgxQjogcmV0dXJuIFwiR2VuZXJhbFN0cmluZ1wiO1xuICAgICAgICBjYXNlIDB4MUM6IHJldHVybiBcIlVuaXZlcnNhbFN0cmluZ1wiO1xuICAgICAgICBjYXNlIDB4MUU6IHJldHVybiBcIkJNUFN0cmluZ1wiO1xuICAgICAgICBkZWZhdWx0OiAgIHJldHVybiBcIlVuaXZlcnNhbF9cIiArIHRhZ051bWJlci50b1N0cmluZygxNik7XG4gICAgICAgIH1cbiAgICBjYXNlIDE6IHJldHVybiBcIkFwcGxpY2F0aW9uX1wiICsgdGFnTnVtYmVyLnRvU3RyaW5nKDE2KTtcbiAgICBjYXNlIDI6IHJldHVybiBcIltcIiArIHRhZ051bWJlciArIFwiXVwiOyAvLyBDb250ZXh0XG4gICAgY2FzZSAzOiByZXR1cm4gXCJQcml2YXRlX1wiICsgdGFnTnVtYmVyLnRvU3RyaW5nKDE2KTtcbiAgICB9XG59O1xuQVNOMS5wcm90b3R5cGUucmVTZWVtc0FTQ0lJID0gL15bIC1+XSskLztcbkFTTjEucHJvdG90eXBlLmNvbnRlbnQgPSBmdW5jdGlvbiAoKSB7XG4gICAgaWYgKHRoaXMudGFnID09PSB1bmRlZmluZWQpXG4gICAgICAgIHJldHVybiBudWxsO1xuICAgIHZhciB0YWdDbGFzcyA9IHRoaXMudGFnID4+IDYsXG4gICAgICAgIHRhZ051bWJlciA9IHRoaXMudGFnICYgMHgxRixcbiAgICAgICAgY29udGVudCA9IHRoaXMucG9zQ29udGVudCgpLFxuICAgICAgICBsZW4gPSBNYXRoLmFicyh0aGlzLmxlbmd0aCk7XG4gICAgaWYgKHRhZ0NsYXNzICE9PSAwKSB7IC8vIHVuaXZlcnNhbFxuICAgICAgICBpZiAodGhpcy5zdWIgIT09IG51bGwpXG4gICAgICAgICAgICByZXR1cm4gXCIoXCIgKyB0aGlzLnN1Yi5sZW5ndGggKyBcIiBlbGVtKVwiO1xuICAgICAgICAvL1RPRE86IFRSWSBUTyBQQVJTRSBBU0NJSSBTVFJJTkdcbiAgICAgICAgdmFyIHMgPSB0aGlzLnN0cmVhbS5wYXJzZVN0cmluZ0lTTyhjb250ZW50LCBjb250ZW50ICsgTWF0aC5taW4obGVuLCBoYXJkTGltaXQpKTtcbiAgICAgICAgaWYgKHRoaXMucmVTZWVtc0FTQ0lJLnRlc3QocykpXG4gICAgICAgICAgICByZXR1cm4gcy5zdWJzdHJpbmcoMCwgMiAqIGhhcmRMaW1pdCkgKyAoKHMubGVuZ3RoID4gMiAqIGhhcmRMaW1pdCkgPyBlbGxpcHNpcyA6IFwiXCIpO1xuICAgICAgICBlbHNlXG4gICAgICAgICAgICByZXR1cm4gdGhpcy5zdHJlYW0ucGFyc2VPY3RldFN0cmluZyhjb250ZW50LCBjb250ZW50ICsgbGVuKTtcbiAgICB9XG4gICAgc3dpdGNoICh0YWdOdW1iZXIpIHtcbiAgICBjYXNlIDB4MDE6IC8vIEJPT0xFQU5cbiAgICAgICAgcmV0dXJuICh0aGlzLnN0cmVhbS5nZXQoY29udGVudCkgPT09IDApID8gXCJmYWxzZVwiIDogXCJ0cnVlXCI7XG4gICAgY2FzZSAweDAyOiAvLyBJTlRFR0VSXG4gICAgICAgIHJldHVybiB0aGlzLnN0cmVhbS5wYXJzZUludGVnZXIoY29udGVudCwgY29udGVudCArIGxlbik7XG4gICAgY2FzZSAweDAzOiAvLyBCSVRfU1RSSU5HXG4gICAgICAgIHJldHVybiB0aGlzLnN1YiA/IFwiKFwiICsgdGhpcy5zdWIubGVuZ3RoICsgXCIgZWxlbSlcIiA6XG4gICAgICAgICAgICB0aGlzLnN0cmVhbS5wYXJzZUJpdFN0cmluZyhjb250ZW50LCBjb250ZW50ICsgbGVuKTtcbiAgICBjYXNlIDB4MDQ6IC8vIE9DVEVUX1NUUklOR1xuICAgICAgICByZXR1cm4gdGhpcy5zdWIgPyBcIihcIiArIHRoaXMuc3ViLmxlbmd0aCArIFwiIGVsZW0pXCIgOlxuICAgICAgICAgICAgdGhpcy5zdHJlYW0ucGFyc2VPY3RldFN0cmluZyhjb250ZW50LCBjb250ZW50ICsgbGVuKTtcbiAgICAvL2Nhc2UgMHgwNTogLy8gTlVMTFxuICAgIGNhc2UgMHgwNjogLy8gT0JKRUNUX0lERU5USUZJRVJcbiAgICAgICAgcmV0dXJuIHRoaXMuc3RyZWFtLnBhcnNlT0lEKGNvbnRlbnQsIGNvbnRlbnQgKyBsZW4pO1xuICAgIC8vY2FzZSAweDA3OiAvLyBPYmplY3REZXNjcmlwdG9yXG4gICAgLy9jYXNlIDB4MDg6IC8vIEVYVEVSTkFMXG4gICAgLy9jYXNlIDB4MDk6IC8vIFJFQUxcbiAgICAvL2Nhc2UgMHgwQTogLy8gRU5VTUVSQVRFRFxuICAgIC8vY2FzZSAweDBCOiAvLyBFTUJFRERFRF9QRFZcbiAgICBjYXNlIDB4MTA6IC8vIFNFUVVFTkNFXG4gICAgY2FzZSAweDExOiAvLyBTRVRcbiAgICAgICAgcmV0dXJuIFwiKFwiICsgdGhpcy5zdWIubGVuZ3RoICsgXCIgZWxlbSlcIjtcbiAgICBjYXNlIDB4MEM6IC8vIFVURjhTdHJpbmdcbiAgICAgICAgcmV0dXJuIHRoaXMuc3RyZWFtLnBhcnNlU3RyaW5nVVRGKGNvbnRlbnQsIGNvbnRlbnQgKyBsZW4pO1xuICAgIGNhc2UgMHgxMjogLy8gTnVtZXJpY1N0cmluZ1xuICAgIGNhc2UgMHgxMzogLy8gUHJpbnRhYmxlU3RyaW5nXG4gICAgY2FzZSAweDE0OiAvLyBUZWxldGV4U3RyaW5nXG4gICAgY2FzZSAweDE1OiAvLyBWaWRlb3RleFN0cmluZ1xuICAgIGNhc2UgMHgxNjogLy8gSUE1U3RyaW5nXG4gICAgLy9jYXNlIDB4MTk6IC8vIEdyYXBoaWNTdHJpbmdcbiAgICBjYXNlIDB4MUE6IC8vIFZpc2libGVTdHJpbmdcbiAgICAvL2Nhc2UgMHgxQjogLy8gR2VuZXJhbFN0cmluZ1xuICAgIC8vY2FzZSAweDFDOiAvLyBVbml2ZXJzYWxTdHJpbmdcbiAgICAgICAgcmV0dXJuIHRoaXMuc3RyZWFtLnBhcnNlU3RyaW5nSVNPKGNvbnRlbnQsIGNvbnRlbnQgKyBsZW4pO1xuICAgIGNhc2UgMHgxRTogLy8gQk1QU3RyaW5nXG4gICAgICAgIHJldHVybiB0aGlzLnN0cmVhbS5wYXJzZVN0cmluZ0JNUChjb250ZW50LCBjb250ZW50ICsgbGVuKTtcbiAgICBjYXNlIDB4MTc6IC8vIFVUQ1RpbWVcbiAgICBjYXNlIDB4MTg6IC8vIEdlbmVyYWxpemVkVGltZVxuICAgICAgICByZXR1cm4gdGhpcy5zdHJlYW0ucGFyc2VUaW1lKGNvbnRlbnQsIGNvbnRlbnQgKyBsZW4pO1xuICAgIH1cbiAgICByZXR1cm4gbnVsbDtcbn07XG5BU04xLnByb3RvdHlwZS50b1N0cmluZyA9IGZ1bmN0aW9uICgpIHtcbiAgICByZXR1cm4gdGhpcy50eXBlTmFtZSgpICsgXCJAXCIgKyB0aGlzLnN0cmVhbS5wb3MgKyBcIltoZWFkZXI6XCIgKyB0aGlzLmhlYWRlciArIFwiLGxlbmd0aDpcIiArIHRoaXMubGVuZ3RoICsgXCIsc3ViOlwiICsgKCh0aGlzLnN1YiA9PT0gbnVsbCkgPyAnbnVsbCcgOiB0aGlzLnN1Yi5sZW5ndGgpICsgXCJdXCI7XG59O1xuQVNOMS5wcm90b3R5cGUucHJpbnQgPSBmdW5jdGlvbiAoaW5kZW50KSB7XG4gICAgaWYgKGluZGVudCA9PT0gdW5kZWZpbmVkKSBpbmRlbnQgPSAnJztcbiAgICBkb2N1bWVudC53cml0ZWxuKGluZGVudCArIHRoaXMpO1xuICAgIGlmICh0aGlzLnN1YiAhPT0gbnVsbCkge1xuICAgICAgICBpbmRlbnQgKz0gJyAgJztcbiAgICAgICAgZm9yICh2YXIgaSA9IDAsIG1heCA9IHRoaXMuc3ViLmxlbmd0aDsgaSA8IG1heDsgKytpKVxuICAgICAgICAgICAgdGhpcy5zdWJbaV0ucHJpbnQoaW5kZW50KTtcbiAgICB9XG59O1xuQVNOMS5wcm90b3R5cGUudG9QcmV0dHlTdHJpbmcgPSBmdW5jdGlvbiAoaW5kZW50KSB7XG4gICAgaWYgKGluZGVudCA9PT0gdW5kZWZpbmVkKSBpbmRlbnQgPSAnJztcbiAgICB2YXIgcyA9IGluZGVudCArIHRoaXMudHlwZU5hbWUoKSArIFwiIEBcIiArIHRoaXMuc3RyZWFtLnBvcztcbiAgICBpZiAodGhpcy5sZW5ndGggPj0gMClcbiAgICAgICAgcyArPSBcIitcIjtcbiAgICBzICs9IHRoaXMubGVuZ3RoO1xuICAgIGlmICh0aGlzLnRhZyAmIDB4MjApXG4gICAgICAgIHMgKz0gXCIgKGNvbnN0cnVjdGVkKVwiO1xuICAgIGVsc2UgaWYgKCgodGhpcy50YWcgPT0gMHgwMykgfHwgKHRoaXMudGFnID09IDB4MDQpKSAmJiAodGhpcy5zdWIgIT09IG51bGwpKVxuICAgICAgICBzICs9IFwiIChlbmNhcHN1bGF0ZXMpXCI7XG4gICAgcyArPSBcIlxcblwiO1xuICAgIGlmICh0aGlzLnN1YiAhPT0gbnVsbCkge1xuICAgICAgICBpbmRlbnQgKz0gJyAgJztcbiAgICAgICAgZm9yICh2YXIgaSA9IDAsIG1heCA9IHRoaXMuc3ViLmxlbmd0aDsgaSA8IG1heDsgKytpKVxuICAgICAgICAgICAgcyArPSB0aGlzLnN1YltpXS50b1ByZXR0eVN0cmluZyhpbmRlbnQpO1xuICAgIH1cbiAgICByZXR1cm4gcztcbn07XG5BU04xLnByb3RvdHlwZS50b0RPTSA9IGZ1bmN0aW9uICgpIHtcbiAgICB2YXIgbm9kZSA9IERPTS50YWcoXCJkaXZcIiwgXCJub2RlXCIpO1xuICAgIG5vZGUuYXNuMSA9IHRoaXM7XG4gICAgdmFyIGhlYWQgPSBET00udGFnKFwiZGl2XCIsIFwiaGVhZFwiKTtcbiAgICB2YXIgcyA9IHRoaXMudHlwZU5hbWUoKS5yZXBsYWNlKC9fL2csIFwiIFwiKTtcbiAgICBoZWFkLmlubmVySFRNTCA9IHM7XG4gICAgdmFyIGNvbnRlbnQgPSB0aGlzLmNvbnRlbnQoKTtcbiAgICBpZiAoY29udGVudCAhPT0gbnVsbCkge1xuICAgICAgICBjb250ZW50ID0gU3RyaW5nKGNvbnRlbnQpLnJlcGxhY2UoLzwvZywgXCImbHQ7XCIpO1xuICAgICAgICB2YXIgcHJldmlldyA9IERPTS50YWcoXCJzcGFuXCIsIFwicHJldmlld1wiKTtcbiAgICAgICAgcHJldmlldy5hcHBlbmRDaGlsZChET00udGV4dChjb250ZW50KSk7XG4gICAgICAgIGhlYWQuYXBwZW5kQ2hpbGQocHJldmlldyk7XG4gICAgfVxuICAgIG5vZGUuYXBwZW5kQ2hpbGQoaGVhZCk7XG4gICAgdGhpcy5ub2RlID0gbm9kZTtcbiAgICB0aGlzLmhlYWQgPSBoZWFkO1xuICAgIHZhciB2YWx1ZSA9IERPTS50YWcoXCJkaXZcIiwgXCJ2YWx1ZVwiKTtcbiAgICBzID0gXCJPZmZzZXQ6IFwiICsgdGhpcy5zdHJlYW0ucG9zICsgXCI8YnIvPlwiO1xuICAgIHMgKz0gXCJMZW5ndGg6IFwiICsgdGhpcy5oZWFkZXIgKyBcIitcIjtcbiAgICBpZiAodGhpcy5sZW5ndGggPj0gMClcbiAgICAgICAgcyArPSB0aGlzLmxlbmd0aDtcbiAgICBlbHNlXG4gICAgICAgIHMgKz0gKC10aGlzLmxlbmd0aCkgKyBcIiAodW5kZWZpbmVkKVwiO1xuICAgIGlmICh0aGlzLnRhZyAmIDB4MjApXG4gICAgICAgIHMgKz0gXCI8YnIvPihjb25zdHJ1Y3RlZClcIjtcbiAgICBlbHNlIGlmICgoKHRoaXMudGFnID09IDB4MDMpIHx8ICh0aGlzLnRhZyA9PSAweDA0KSkgJiYgKHRoaXMuc3ViICE9PSBudWxsKSlcbiAgICAgICAgcyArPSBcIjxici8+KGVuY2Fwc3VsYXRlcylcIjtcbiAgICAvL1RPRE8gaWYgKHRoaXMudGFnID09IDB4MDMpIHMgKz0gXCJVbnVzZWQgYml0czogXCJcbiAgICBpZiAoY29udGVudCAhPT0gbnVsbCkge1xuICAgICAgICBzICs9IFwiPGJyLz5WYWx1ZTo8YnIvPjxiPlwiICsgY29udGVudCArIFwiPC9iPlwiO1xuICAgICAgICBpZiAoKHR5cGVvZiBvaWRzID09PSAnb2JqZWN0JykgJiYgKHRoaXMudGFnID09IDB4MDYpKSB7XG4gICAgICAgICAgICB2YXIgb2lkID0gb2lkc1tjb250ZW50XTtcbiAgICAgICAgICAgIGlmIChvaWQpIHtcbiAgICAgICAgICAgICAgICBpZiAob2lkLmQpIHMgKz0gXCI8YnIvPlwiICsgb2lkLmQ7XG4gICAgICAgICAgICAgICAgaWYgKG9pZC5jKSBzICs9IFwiPGJyLz5cIiArIG9pZC5jO1xuICAgICAgICAgICAgICAgIGlmIChvaWQudykgcyArPSBcIjxici8+KHdhcm5pbmchKVwiO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxuICAgIHZhbHVlLmlubmVySFRNTCA9IHM7XG4gICAgbm9kZS5hcHBlbmRDaGlsZCh2YWx1ZSk7XG4gICAgdmFyIHN1YiA9IERPTS50YWcoXCJkaXZcIiwgXCJzdWJcIik7XG4gICAgaWYgKHRoaXMuc3ViICE9PSBudWxsKSB7XG4gICAgICAgIGZvciAodmFyIGkgPSAwLCBtYXggPSB0aGlzLnN1Yi5sZW5ndGg7IGkgPCBtYXg7ICsraSlcbiAgICAgICAgICAgIHN1Yi5hcHBlbmRDaGlsZCh0aGlzLnN1YltpXS50b0RPTSgpKTtcbiAgICB9XG4gICAgbm9kZS5hcHBlbmRDaGlsZChzdWIpO1xuICAgIGhlYWQub25jbGljayA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgbm9kZS5jbGFzc05hbWUgPSAobm9kZS5jbGFzc05hbWUgPT0gXCJub2RlIGNvbGxhcHNlZFwiKSA/IFwibm9kZVwiIDogXCJub2RlIGNvbGxhcHNlZFwiO1xuICAgIH07XG4gICAgcmV0dXJuIG5vZGU7XG59O1xuQVNOMS5wcm90b3R5cGUucG9zU3RhcnQgPSBmdW5jdGlvbiAoKSB7XG4gICAgcmV0dXJuIHRoaXMuc3RyZWFtLnBvcztcbn07XG5BU04xLnByb3RvdHlwZS5wb3NDb250ZW50ID0gZnVuY3Rpb24gKCkge1xuICAgIHJldHVybiB0aGlzLnN0cmVhbS5wb3MgKyB0aGlzLmhlYWRlcjtcbn07XG5BU04xLnByb3RvdHlwZS5wb3NFbmQgPSBmdW5jdGlvbiAoKSB7XG4gICAgcmV0dXJuIHRoaXMuc3RyZWFtLnBvcyArIHRoaXMuaGVhZGVyICsgTWF0aC5hYnModGhpcy5sZW5ndGgpO1xufTtcbkFTTjEucHJvdG90eXBlLmZha2VIb3ZlciA9IGZ1bmN0aW9uIChjdXJyZW50KSB7XG4gICAgdGhpcy5ub2RlLmNsYXNzTmFtZSArPSBcIiBob3ZlclwiO1xuICAgIGlmIChjdXJyZW50KVxuICAgICAgICB0aGlzLmhlYWQuY2xhc3NOYW1lICs9IFwiIGhvdmVyXCI7XG59O1xuQVNOMS5wcm90b3R5cGUuZmFrZU91dCA9IGZ1bmN0aW9uIChjdXJyZW50KSB7XG4gICAgdmFyIHJlID0gLyA/aG92ZXIvO1xuICAgIHRoaXMubm9kZS5jbGFzc05hbWUgPSB0aGlzLm5vZGUuY2xhc3NOYW1lLnJlcGxhY2UocmUsIFwiXCIpO1xuICAgIGlmIChjdXJyZW50KVxuICAgICAgICB0aGlzLmhlYWQuY2xhc3NOYW1lID0gdGhpcy5oZWFkLmNsYXNzTmFtZS5yZXBsYWNlKHJlLCBcIlwiKTtcbn07XG5BU04xLnByb3RvdHlwZS50b0hleERPTV9zdWIgPSBmdW5jdGlvbiAobm9kZSwgY2xhc3NOYW1lLCBzdHJlYW0sIHN0YXJ0LCBlbmQpIHtcbiAgICBpZiAoc3RhcnQgPj0gZW5kKVxuICAgICAgICByZXR1cm47XG4gICAgdmFyIHN1YiA9IERPTS50YWcoXCJzcGFuXCIsIGNsYXNzTmFtZSk7XG4gICAgc3ViLmFwcGVuZENoaWxkKERPTS50ZXh0KFxuICAgICAgICBzdHJlYW0uaGV4RHVtcChzdGFydCwgZW5kKSkpO1xuICAgIG5vZGUuYXBwZW5kQ2hpbGQoc3ViKTtcbn07XG5BU04xLnByb3RvdHlwZS50b0hleERPTSA9IGZ1bmN0aW9uIChyb290KSB7XG4gICAgdmFyIG5vZGUgPSBET00udGFnKFwic3BhblwiLCBcImhleFwiKTtcbiAgICBpZiAocm9vdCA9PT0gdW5kZWZpbmVkKSByb290ID0gbm9kZTtcbiAgICB0aGlzLmhlYWQuaGV4Tm9kZSA9IG5vZGU7XG4gICAgdGhpcy5oZWFkLm9ubW91c2VvdmVyID0gZnVuY3Rpb24gKCkgeyB0aGlzLmhleE5vZGUuY2xhc3NOYW1lID0gXCJoZXhDdXJyZW50XCI7IH07XG4gICAgdGhpcy5oZWFkLm9ubW91c2VvdXQgID0gZnVuY3Rpb24gKCkgeyB0aGlzLmhleE5vZGUuY2xhc3NOYW1lID0gXCJoZXhcIjsgfTtcbiAgICBub2RlLmFzbjEgPSB0aGlzO1xuICAgIG5vZGUub25tb3VzZW92ZXIgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHZhciBjdXJyZW50ID0gIXJvb3Quc2VsZWN0ZWQ7XG4gICAgICAgIGlmIChjdXJyZW50KSB7XG4gICAgICAgICAgICByb290LnNlbGVjdGVkID0gdGhpcy5hc24xO1xuICAgICAgICAgICAgdGhpcy5jbGFzc05hbWUgPSBcImhleEN1cnJlbnRcIjtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLmFzbjEuZmFrZUhvdmVyKGN1cnJlbnQpO1xuICAgIH07XG4gICAgbm9kZS5vbm1vdXNlb3V0ICA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdmFyIGN1cnJlbnQgPSAocm9vdC5zZWxlY3RlZCA9PSB0aGlzLmFzbjEpO1xuICAgICAgICB0aGlzLmFzbjEuZmFrZU91dChjdXJyZW50KTtcbiAgICAgICAgaWYgKGN1cnJlbnQpIHtcbiAgICAgICAgICAgIHJvb3Quc2VsZWN0ZWQgPSBudWxsO1xuICAgICAgICAgICAgdGhpcy5jbGFzc05hbWUgPSBcImhleFwiO1xuICAgICAgICB9XG4gICAgfTtcbiAgICB0aGlzLnRvSGV4RE9NX3N1Yihub2RlLCBcInRhZ1wiLCB0aGlzLnN0cmVhbSwgdGhpcy5wb3NTdGFydCgpLCB0aGlzLnBvc1N0YXJ0KCkgKyAxKTtcbiAgICB0aGlzLnRvSGV4RE9NX3N1Yihub2RlLCAodGhpcy5sZW5ndGggPj0gMCkgPyBcImRsZW5cIiA6IFwidWxlblwiLCB0aGlzLnN0cmVhbSwgdGhpcy5wb3NTdGFydCgpICsgMSwgdGhpcy5wb3NDb250ZW50KCkpO1xuICAgIGlmICh0aGlzLnN1YiA9PT0gbnVsbClcbiAgICAgICAgbm9kZS5hcHBlbmRDaGlsZChET00udGV4dChcbiAgICAgICAgICAgIHRoaXMuc3RyZWFtLmhleER1bXAodGhpcy5wb3NDb250ZW50KCksIHRoaXMucG9zRW5kKCkpKSk7XG4gICAgZWxzZSBpZiAodGhpcy5zdWIubGVuZ3RoID4gMCkge1xuICAgICAgICB2YXIgZmlyc3QgPSB0aGlzLnN1YlswXTtcbiAgICAgICAgdmFyIGxhc3QgPSB0aGlzLnN1Ylt0aGlzLnN1Yi5sZW5ndGggLSAxXTtcbiAgICAgICAgdGhpcy50b0hleERPTV9zdWIobm9kZSwgXCJpbnRyb1wiLCB0aGlzLnN0cmVhbSwgdGhpcy5wb3NDb250ZW50KCksIGZpcnN0LnBvc1N0YXJ0KCkpO1xuICAgICAgICBmb3IgKHZhciBpID0gMCwgbWF4ID0gdGhpcy5zdWIubGVuZ3RoOyBpIDwgbWF4OyArK2kpXG4gICAgICAgICAgICBub2RlLmFwcGVuZENoaWxkKHRoaXMuc3ViW2ldLnRvSGV4RE9NKHJvb3QpKTtcbiAgICAgICAgdGhpcy50b0hleERPTV9zdWIobm9kZSwgXCJvdXRyb1wiLCB0aGlzLnN0cmVhbSwgbGFzdC5wb3NFbmQoKSwgdGhpcy5wb3NFbmQoKSk7XG4gICAgfVxuICAgIHJldHVybiBub2RlO1xufTtcbkFTTjEucHJvdG90eXBlLnRvSGV4U3RyaW5nID0gZnVuY3Rpb24gKHJvb3QpIHtcbiAgICByZXR1cm4gdGhpcy5zdHJlYW0uaGV4RHVtcCh0aGlzLnBvc1N0YXJ0KCksIHRoaXMucG9zRW5kKCksIHRydWUpO1xufTtcbkFTTjEuZGVjb2RlTGVuZ3RoID0gZnVuY3Rpb24gKHN0cmVhbSkge1xuICAgIHZhciBidWYgPSBzdHJlYW0uZ2V0KCksXG4gICAgICAgIGxlbiA9IGJ1ZiAmIDB4N0Y7XG4gICAgaWYgKGxlbiA9PSBidWYpXG4gICAgICAgIHJldHVybiBsZW47XG4gICAgaWYgKGxlbiA+IDMpXG4gICAgICAgIHRocm93IFwiTGVuZ3RoIG92ZXIgMjQgYml0cyBub3Qgc3VwcG9ydGVkIGF0IHBvc2l0aW9uIFwiICsgKHN0cmVhbS5wb3MgLSAxKTtcbiAgICBpZiAobGVuID09PSAwKVxuICAgICAgICByZXR1cm4gLTE7IC8vIHVuZGVmaW5lZFxuICAgIGJ1ZiA9IDA7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBsZW47ICsraSlcbiAgICAgICAgYnVmID0gKGJ1ZiA8PCA4KSB8IHN0cmVhbS5nZXQoKTtcbiAgICByZXR1cm4gYnVmO1xufTtcbkFTTjEuaGFzQ29udGVudCA9IGZ1bmN0aW9uICh0YWcsIGxlbiwgc3RyZWFtKSB7XG4gICAgaWYgKHRhZyAmIDB4MjApIC8vIGNvbnN0cnVjdGVkXG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgIGlmICgodGFnIDwgMHgwMykgfHwgKHRhZyA+IDB4MDQpKVxuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgdmFyIHAgPSBuZXcgU3RyZWFtKHN0cmVhbSk7XG4gICAgaWYgKHRhZyA9PSAweDAzKSBwLmdldCgpOyAvLyBCaXRTdHJpbmcgdW51c2VkIGJpdHMsIG11c3QgYmUgaW4gWzAsIDddXG4gICAgdmFyIHN1YlRhZyA9IHAuZ2V0KCk7XG4gICAgaWYgKChzdWJUYWcgPj4gNikgJiAweDAxKSAvLyBub3QgKHVuaXZlcnNhbCBvciBjb250ZXh0KVxuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgdHJ5IHtcbiAgICAgICAgdmFyIHN1Ykxlbmd0aCA9IEFTTjEuZGVjb2RlTGVuZ3RoKHApO1xuICAgICAgICByZXR1cm4gKChwLnBvcyAtIHN0cmVhbS5wb3MpICsgc3ViTGVuZ3RoID09IGxlbik7XG4gICAgfSBjYXRjaCAoZXhjZXB0aW9uKSB7XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG59O1xuQVNOMS5kZWNvZGUgPSBmdW5jdGlvbiAoc3RyZWFtKSB7XG4gICAgaWYgKCEoc3RyZWFtIGluc3RhbmNlb2YgU3RyZWFtKSlcbiAgICAgICAgc3RyZWFtID0gbmV3IFN0cmVhbShzdHJlYW0sIDApO1xuICAgIHZhciBzdHJlYW1TdGFydCA9IG5ldyBTdHJlYW0oc3RyZWFtKSxcbiAgICAgICAgdGFnID0gc3RyZWFtLmdldCgpLFxuICAgICAgICBsZW4gPSBBU04xLmRlY29kZUxlbmd0aChzdHJlYW0pLFxuICAgICAgICBoZWFkZXIgPSBzdHJlYW0ucG9zIC0gc3RyZWFtU3RhcnQucG9zLFxuICAgICAgICBzdWIgPSBudWxsO1xuICAgIGlmIChBU04xLmhhc0NvbnRlbnQodGFnLCBsZW4sIHN0cmVhbSkpIHtcbiAgICAgICAgLy8gaXQgaGFzIGNvbnRlbnQsIHNvIHdlIGRlY29kZSBpdFxuICAgICAgICB2YXIgc3RhcnQgPSBzdHJlYW0ucG9zO1xuICAgICAgICBpZiAodGFnID09IDB4MDMpIHN0cmVhbS5nZXQoKTsgLy8gc2tpcCBCaXRTdHJpbmcgdW51c2VkIGJpdHMsIG11c3QgYmUgaW4gWzAsIDddXG4gICAgICAgIHN1YiA9IFtdO1xuICAgICAgICBpZiAobGVuID49IDApIHtcbiAgICAgICAgICAgIC8vIGRlZmluaXRlIGxlbmd0aFxuICAgICAgICAgICAgdmFyIGVuZCA9IHN0YXJ0ICsgbGVuO1xuICAgICAgICAgICAgd2hpbGUgKHN0cmVhbS5wb3MgPCBlbmQpXG4gICAgICAgICAgICAgICAgc3ViW3N1Yi5sZW5ndGhdID0gQVNOMS5kZWNvZGUoc3RyZWFtKTtcbiAgICAgICAgICAgIGlmIChzdHJlYW0ucG9zICE9IGVuZClcbiAgICAgICAgICAgICAgICB0aHJvdyBcIkNvbnRlbnQgc2l6ZSBpcyBub3QgY29ycmVjdCBmb3IgY29udGFpbmVyIHN0YXJ0aW5nIGF0IG9mZnNldCBcIiArIHN0YXJ0O1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgLy8gdW5kZWZpbmVkIGxlbmd0aFxuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBmb3IgKDs7KSB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBzID0gQVNOMS5kZWNvZGUoc3RyZWFtKTtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHMudGFnID09PSAwKVxuICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgIHN1YltzdWIubGVuZ3RoXSA9IHM7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGxlbiA9IHN0YXJ0IC0gc3RyZWFtLnBvcztcbiAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBcIkV4Y2VwdGlvbiB3aGlsZSBkZWNvZGluZyB1bmRlZmluZWQgbGVuZ3RoIGNvbnRlbnQ6IFwiICsgZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0gZWxzZVxuICAgICAgICBzdHJlYW0ucG9zICs9IGxlbjsgLy8gc2tpcCBjb250ZW50XG4gICAgcmV0dXJuIG5ldyBBU04xKHN0cmVhbVN0YXJ0LCBoZWFkZXIsIGxlbiwgdGFnLCBzdWIpO1xufTtcbkFTTjEudGVzdCA9IGZ1bmN0aW9uICgpIHtcbiAgICB2YXIgdGVzdCA9IFtcbiAgICAgICAgeyB2YWx1ZTogWzB4MjddLCAgICAgICAgICAgICAgICAgICBleHBlY3RlZDogMHgyNyAgICAgfSxcbiAgICAgICAgeyB2YWx1ZTogWzB4ODEsIDB4QzldLCAgICAgICAgICAgICBleHBlY3RlZDogMHhDOSAgICAgfSxcbiAgICAgICAgeyB2YWx1ZTogWzB4ODMsIDB4RkUsIDB4REMsIDB4QkFdLCBleHBlY3RlZDogMHhGRURDQkEgfVxuICAgIF07XG4gICAgZm9yICh2YXIgaSA9IDAsIG1heCA9IHRlc3QubGVuZ3RoOyBpIDwgbWF4OyArK2kpIHtcbiAgICAgICAgdmFyIHBvcyA9IDAsXG4gICAgICAgICAgICBzdHJlYW0gPSBuZXcgU3RyZWFtKHRlc3RbaV0udmFsdWUsIDApLFxuICAgICAgICAgICAgcmVzID0gQVNOMS5kZWNvZGVMZW5ndGgoc3RyZWFtKTtcbiAgICAgICAgaWYgKHJlcyAhPSB0ZXN0W2ldLmV4cGVjdGVkKVxuICAgICAgICAgICAgZG9jdW1lbnQud3JpdGUoXCJJbiB0ZXN0W1wiICsgaSArIFwiXSBleHBlY3RlZCBcIiArIHRlc3RbaV0uZXhwZWN0ZWQgKyBcIiBnb3QgXCIgKyByZXMgKyBcIlxcblwiKTtcbiAgICB9XG59O1xuXG4vLyBleHBvcnQgZ2xvYmFsc1xud2luZG93LkFTTjEgPSBBU04xO1xufSkoKTtcbi8qKlxuICogUmV0cmlldmUgdGhlIGhleGFkZWNpbWFsIHZhbHVlIChhcyBhIHN0cmluZykgb2YgdGhlIGN1cnJlbnQgQVNOLjEgZWxlbWVudFxuICogQHJldHVybnMge3N0cmluZ31cbiAqIEBwdWJsaWNcbiAqL1xuQVNOMS5wcm90b3R5cGUuZ2V0SGV4U3RyaW5nVmFsdWUgPSBmdW5jdGlvbiAoKSB7XG4gIHZhciBoZXhTdHJpbmcgPSB0aGlzLnRvSGV4U3RyaW5nKCk7XG4gIHZhciBvZmZzZXQgPSB0aGlzLmhlYWRlciAqIDI7XG4gIHZhciBsZW5ndGggPSB0aGlzLmxlbmd0aCAqIDI7XG4gIHJldHVybiBoZXhTdHJpbmcuc3Vic3RyKG9mZnNldCwgbGVuZ3RoKTtcbn07XG5cbi8qKlxuICogTWV0aG9kIHRvIHBhcnNlIGEgcGVtIGVuY29kZWQgc3RyaW5nIGNvbnRhaW5pbmcgYm90aCBhIHB1YmxpYyBvciBwcml2YXRlIGtleS5cbiAqIFRoZSBtZXRob2Qgd2lsbCB0cmFuc2xhdGUgdGhlIHBlbSBlbmNvZGVkIHN0cmluZyBpbiBhIGRlciBlbmNvZGVkIHN0cmluZyBhbmRcbiAqIHdpbGwgcGFyc2UgcHJpdmF0ZSBrZXkgYW5kIHB1YmxpYyBrZXkgcGFyYW1ldGVycy4gVGhpcyBtZXRob2QgYWNjZXB0cyBwdWJsaWMga2V5XG4gKiBpbiB0aGUgcnNhZW5jcnlwdGlvbiBwa2NzICMxIGZvcm1hdCAob2lkOiAxLjIuODQwLjExMzU0OS4xLjEuMSkuXG4gKlxuICogQHRvZG8gQ2hlY2sgaG93IG1hbnkgcnNhIGZvcm1hdHMgdXNlIHRoZSBzYW1lIGZvcm1hdCBvZiBwa2NzICMxLlxuICpcbiAqIFRoZSBmb3JtYXQgaXMgZGVmaW5lZCBhczpcbiAqIFB1YmxpY0tleUluZm8gOjo9IFNFUVVFTkNFIHtcbiAqICAgYWxnb3JpdGhtICAgICAgIEFsZ29yaXRobUlkZW50aWZpZXIsXG4gKiAgIFB1YmxpY0tleSAgICAgICBCSVQgU1RSSU5HXG4gKiB9XG4gKiBXaGVyZSBBbGdvcml0aG1JZGVudGlmaWVyIGlzOlxuICogQWxnb3JpdGhtSWRlbnRpZmllciA6Oj0gU0VRVUVOQ0Uge1xuICogICBhbGdvcml0aG0gICAgICAgT0JKRUNUIElERU5USUZJRVIsICAgICB0aGUgT0lEIG9mIHRoZSBlbmMgYWxnb3JpdGhtXG4gKiAgIHBhcmFtZXRlcnMgICAgICBBTlkgREVGSU5FRCBCWSBhbGdvcml0aG0gT1BUSU9OQUwgKE5VTEwgZm9yIFBLQ1MgIzEpXG4gKiB9XG4gKiBhbmQgUHVibGljS2V5IGlzIGEgU0VRVUVOQ0UgZW5jYXBzdWxhdGVkIGluIGEgQklUIFNUUklOR1xuICogUlNBUHVibGljS2V5IDo6PSBTRVFVRU5DRSB7XG4gKiAgIG1vZHVsdXMgICAgICAgICAgIElOVEVHRVIsICAtLSBuXG4gKiAgIHB1YmxpY0V4cG9uZW50ICAgIElOVEVHRVIgICAtLSBlXG4gKiB9XG4gKiBpdCdzIHBvc3NpYmxlIHRvIGV4YW1pbmUgdGhlIHN0cnVjdHVyZSBvZiB0aGUga2V5cyBvYnRhaW5lZCBmcm9tIG9wZW5zc2wgdXNpbmdcbiAqIGFuIGFzbi4xIGR1bXBlciBhcyB0aGUgb25lIHVzZWQgaGVyZSB0byBwYXJzZSB0aGUgY29tcG9uZW50czogaHR0cDovL2xhcG8uaXQvYXNuMWpzL1xuICogQGFyZ3VtZW50IHtzdHJpbmd9IHBlbSB0aGUgcGVtIGVuY29kZWQgc3RyaW5nLCBjYW4gaW5jbHVkZSB0aGUgQkVHSU4vRU5EIGhlYWRlci9mb290ZXJcbiAqIEBwcml2YXRlXG4gKi9cblJTQUtleS5wcm90b3R5cGUucGFyc2VLZXkgPSBmdW5jdGlvbiAocGVtKSB7XG4gIHRyeSB7XG4gICAgdmFyIG1vZHVsdXMgPSAwO1xuICAgIHZhciBwdWJsaWNfZXhwb25lbnQgPSAwO1xuICAgIHZhciByZUhleCA9IC9eXFxzKig/OlswLTlBLUZhLWZdWzAtOUEtRmEtZl1cXHMqKSskLztcbiAgICB2YXIgZGVyID0gcmVIZXgudGVzdChwZW0pID8gSGV4LmRlY29kZShwZW0pIDogQmFzZTY0LnVuYXJtb3IocGVtKTtcbiAgICB2YXIgYXNuMSA9IEFTTjEuZGVjb2RlKGRlcik7XG5cbiAgICAvL0ZpeGVzIGEgYnVnIHdpdGggT3BlblNTTCAxLjArIHByaXZhdGUga2V5c1xuICAgIGlmKGFzbjEuc3ViLmxlbmd0aCA9PT0gMyl7XG4gICAgICAgIGFzbjEgPSBhc24xLnN1YlsyXS5zdWJbMF07XG4gICAgfVxuICAgIGlmIChhc24xLnN1Yi5sZW5ndGggPT09IDkpIHtcblxuICAgICAgLy8gUGFyc2UgdGhlIHByaXZhdGUga2V5LlxuICAgICAgbW9kdWx1cyA9IGFzbjEuc3ViWzFdLmdldEhleFN0cmluZ1ZhbHVlKCk7IC8vYmlnaW50XG4gICAgICB0aGlzLm4gPSBwYXJzZUJpZ0ludChtb2R1bHVzLCAxNik7XG5cbiAgICAgIHB1YmxpY19leHBvbmVudCA9IGFzbjEuc3ViWzJdLmdldEhleFN0cmluZ1ZhbHVlKCk7IC8vaW50XG4gICAgICB0aGlzLmUgPSBwYXJzZUludChwdWJsaWNfZXhwb25lbnQsIDE2KTtcblxuICAgICAgdmFyIHByaXZhdGVfZXhwb25lbnQgPSBhc24xLnN1YlszXS5nZXRIZXhTdHJpbmdWYWx1ZSgpOyAvL2JpZ2ludFxuICAgICAgdGhpcy5kID0gcGFyc2VCaWdJbnQocHJpdmF0ZV9leHBvbmVudCwgMTYpO1xuXG4gICAgICB2YXIgcHJpbWUxID0gYXNuMS5zdWJbNF0uZ2V0SGV4U3RyaW5nVmFsdWUoKTsgLy9iaWdpbnRcbiAgICAgIHRoaXMucCA9IHBhcnNlQmlnSW50KHByaW1lMSwgMTYpO1xuXG4gICAgICB2YXIgcHJpbWUyID0gYXNuMS5zdWJbNV0uZ2V0SGV4U3RyaW5nVmFsdWUoKTsgLy9iaWdpbnRcbiAgICAgIHRoaXMucSA9IHBhcnNlQmlnSW50KHByaW1lMiwgMTYpO1xuXG4gICAgICB2YXIgZXhwb25lbnQxID0gYXNuMS5zdWJbNl0uZ2V0SGV4U3RyaW5nVmFsdWUoKTsgLy9iaWdpbnRcbiAgICAgIHRoaXMuZG1wMSA9IHBhcnNlQmlnSW50KGV4cG9uZW50MSwgMTYpO1xuXG4gICAgICB2YXIgZXhwb25lbnQyID0gYXNuMS5zdWJbN10uZ2V0SGV4U3RyaW5nVmFsdWUoKTsgLy9iaWdpbnRcbiAgICAgIHRoaXMuZG1xMSA9IHBhcnNlQmlnSW50KGV4cG9uZW50MiwgMTYpO1xuXG4gICAgICB2YXIgY29lZmZpY2llbnQgPSBhc24xLnN1Yls4XS5nZXRIZXhTdHJpbmdWYWx1ZSgpOyAvL2JpZ2ludFxuICAgICAgdGhpcy5jb2VmZiA9IHBhcnNlQmlnSW50KGNvZWZmaWNpZW50LCAxNik7XG5cbiAgICB9XG4gICAgZWxzZSBpZiAoYXNuMS5zdWIubGVuZ3RoID09PSAyKSB7XG5cbiAgICAgIC8vIFBhcnNlIHRoZSBwdWJsaWMga2V5LlxuICAgICAgdmFyIGJpdF9zdHJpbmcgPSBhc24xLnN1YlsxXTtcbiAgICAgIHZhciBzZXF1ZW5jZSA9IGJpdF9zdHJpbmcuc3ViWzBdO1xuXG4gICAgICBtb2R1bHVzID0gc2VxdWVuY2Uuc3ViWzBdLmdldEhleFN0cmluZ1ZhbHVlKCk7XG4gICAgICB0aGlzLm4gPSBwYXJzZUJpZ0ludChtb2R1bHVzLCAxNik7XG4gICAgICBwdWJsaWNfZXhwb25lbnQgPSBzZXF1ZW5jZS5zdWJbMV0uZ2V0SGV4U3RyaW5nVmFsdWUoKTtcbiAgICAgIHRoaXMuZSA9IHBhcnNlSW50KHB1YmxpY19leHBvbmVudCwgMTYpO1xuXG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbiAgICByZXR1cm4gdHJ1ZTtcbiAgfVxuICBjYXRjaCAoZXgpIHtcbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cbn07XG5cbi8qKlxuICogVHJhbnNsYXRlIHJzYSBwYXJhbWV0ZXJzIGluIGEgaGV4IGVuY29kZWQgc3RyaW5nIHJlcHJlc2VudGluZyB0aGUgcnNhIGtleS5cbiAqXG4gKiBUaGUgdHJhbnNsYXRpb24gZm9sbG93IHRoZSBBU04uMSBub3RhdGlvbiA6XG4gKiBSU0FQcml2YXRlS2V5IDo6PSBTRVFVRU5DRSB7XG4gKiAgIHZlcnNpb24gICAgICAgICAgIFZlcnNpb24sXG4gKiAgIG1vZHVsdXMgICAgICAgICAgIElOVEVHRVIsICAtLSBuXG4gKiAgIHB1YmxpY0V4cG9uZW50ICAgIElOVEVHRVIsICAtLSBlXG4gKiAgIHByaXZhdGVFeHBvbmVudCAgIElOVEVHRVIsICAtLSBkXG4gKiAgIHByaW1lMSAgICAgICAgICAgIElOVEVHRVIsICAtLSBwXG4gKiAgIHByaW1lMiAgICAgICAgICAgIElOVEVHRVIsICAtLSBxXG4gKiAgIGV4cG9uZW50MSAgICAgICAgIElOVEVHRVIsICAtLSBkIG1vZCAocDEpXG4gKiAgIGV4cG9uZW50MiAgICAgICAgIElOVEVHRVIsICAtLSBkIG1vZCAocS0xKVxuICogICBjb2VmZmljaWVudCAgICAgICBJTlRFR0VSLCAgLS0gKGludmVyc2Ugb2YgcSkgbW9kIHBcbiAqIH1cbiAqIEByZXR1cm5zIHtzdHJpbmd9ICBERVIgRW5jb2RlZCBTdHJpbmcgcmVwcmVzZW50aW5nIHRoZSByc2EgcHJpdmF0ZSBrZXlcbiAqIEBwcml2YXRlXG4gKi9cblJTQUtleS5wcm90b3R5cGUuZ2V0UHJpdmF0ZUJhc2VLZXkgPSBmdW5jdGlvbiAoKSB7XG4gIHZhciBvcHRpb25zID0ge1xuICAgICdhcnJheSc6IFtcbiAgICAgIG5ldyBLSlVSLmFzbjEuREVSSW50ZWdlcih7J2ludCc6IDB9KSxcbiAgICAgIG5ldyBLSlVSLmFzbjEuREVSSW50ZWdlcih7J2JpZ2ludCc6IHRoaXMubn0pLFxuICAgICAgbmV3IEtKVVIuYXNuMS5ERVJJbnRlZ2VyKHsnaW50JzogdGhpcy5lfSksXG4gICAgICBuZXcgS0pVUi5hc24xLkRFUkludGVnZXIoeydiaWdpbnQnOiB0aGlzLmR9KSxcbiAgICAgIG5ldyBLSlVSLmFzbjEuREVSSW50ZWdlcih7J2JpZ2ludCc6IHRoaXMucH0pLFxuICAgICAgbmV3IEtKVVIuYXNuMS5ERVJJbnRlZ2VyKHsnYmlnaW50JzogdGhpcy5xfSksXG4gICAgICBuZXcgS0pVUi5hc24xLkRFUkludGVnZXIoeydiaWdpbnQnOiB0aGlzLmRtcDF9KSxcbiAgICAgIG5ldyBLSlVSLmFzbjEuREVSSW50ZWdlcih7J2JpZ2ludCc6IHRoaXMuZG1xMX0pLFxuICAgICAgbmV3IEtKVVIuYXNuMS5ERVJJbnRlZ2VyKHsnYmlnaW50JzogdGhpcy5jb2VmZn0pXG4gICAgXVxuICB9O1xuICB2YXIgc2VxID0gbmV3IEtKVVIuYXNuMS5ERVJTZXF1ZW5jZShvcHRpb25zKTtcbiAgcmV0dXJuIHNlcS5nZXRFbmNvZGVkSGV4KCk7XG59O1xuXG4vKipcbiAqIGJhc2U2NCAocGVtKSBlbmNvZGVkIHZlcnNpb24gb2YgdGhlIERFUiBlbmNvZGVkIHJlcHJlc2VudGF0aW9uXG4gKiBAcmV0dXJucyB7c3RyaW5nfSBwZW0gZW5jb2RlZCByZXByZXNlbnRhdGlvbiB3aXRob3V0IGhlYWRlciBhbmQgZm9vdGVyXG4gKiBAcHVibGljXG4gKi9cblJTQUtleS5wcm90b3R5cGUuZ2V0UHJpdmF0ZUJhc2VLZXlCNjQgPSBmdW5jdGlvbiAoKSB7XG4gIHJldHVybiBoZXgyYjY0KHRoaXMuZ2V0UHJpdmF0ZUJhc2VLZXkoKSk7XG59O1xuXG4vKipcbiAqIFRyYW5zbGF0ZSByc2EgcGFyYW1ldGVycyBpbiBhIGhleCBlbmNvZGVkIHN0cmluZyByZXByZXNlbnRpbmcgdGhlIHJzYSBwdWJsaWMga2V5LlxuICogVGhlIHJlcHJlc2VudGF0aW9uIGZvbGxvdyB0aGUgQVNOLjEgbm90YXRpb24gOlxuICogUHVibGljS2V5SW5mbyA6Oj0gU0VRVUVOQ0Uge1xuICogICBhbGdvcml0aG0gICAgICAgQWxnb3JpdGhtSWRlbnRpZmllcixcbiAqICAgUHVibGljS2V5ICAgICAgIEJJVCBTVFJJTkdcbiAqIH1cbiAqIFdoZXJlIEFsZ29yaXRobUlkZW50aWZpZXIgaXM6XG4gKiBBbGdvcml0aG1JZGVudGlmaWVyIDo6PSBTRVFVRU5DRSB7XG4gKiAgIGFsZ29yaXRobSAgICAgICBPQkpFQ1QgSURFTlRJRklFUiwgICAgIHRoZSBPSUQgb2YgdGhlIGVuYyBhbGdvcml0aG1cbiAqICAgcGFyYW1ldGVycyAgICAgIEFOWSBERUZJTkVEIEJZIGFsZ29yaXRobSBPUFRJT05BTCAoTlVMTCBmb3IgUEtDUyAjMSlcbiAqIH1cbiAqIGFuZCBQdWJsaWNLZXkgaXMgYSBTRVFVRU5DRSBlbmNhcHN1bGF0ZWQgaW4gYSBCSVQgU1RSSU5HXG4gKiBSU0FQdWJsaWNLZXkgOjo9IFNFUVVFTkNFIHtcbiAqICAgbW9kdWx1cyAgICAgICAgICAgSU5URUdFUiwgIC0tIG5cbiAqICAgcHVibGljRXhwb25lbnQgICAgSU5URUdFUiAgIC0tIGVcbiAqIH1cbiAqIEByZXR1cm5zIHtzdHJpbmd9IERFUiBFbmNvZGVkIFN0cmluZyByZXByZXNlbnRpbmcgdGhlIHJzYSBwdWJsaWMga2V5XG4gKiBAcHJpdmF0ZVxuICovXG5SU0FLZXkucHJvdG90eXBlLmdldFB1YmxpY0Jhc2VLZXkgPSBmdW5jdGlvbiAoKSB7XG4gIHZhciBvcHRpb25zID0ge1xuICAgICdhcnJheSc6IFtcbiAgICAgIG5ldyBLSlVSLmFzbjEuREVST2JqZWN0SWRlbnRpZmllcih7J29pZCc6ICcxLjIuODQwLjExMzU0OS4xLjEuMSd9KSwgLy9SU0EgRW5jcnlwdGlvbiBwa2NzICMxIG9pZFxuICAgICAgbmV3IEtKVVIuYXNuMS5ERVJOdWxsKClcbiAgICBdXG4gIH07XG4gIHZhciBmaXJzdF9zZXF1ZW5jZSA9IG5ldyBLSlVSLmFzbjEuREVSU2VxdWVuY2Uob3B0aW9ucyk7XG5cbiAgb3B0aW9ucyA9IHtcbiAgICAnYXJyYXknOiBbXG4gICAgICBuZXcgS0pVUi5hc24xLkRFUkludGVnZXIoeydiaWdpbnQnOiB0aGlzLm59KSxcbiAgICAgIG5ldyBLSlVSLmFzbjEuREVSSW50ZWdlcih7J2ludCc6IHRoaXMuZX0pXG4gICAgXVxuICB9O1xuICB2YXIgc2Vjb25kX3NlcXVlbmNlID0gbmV3IEtKVVIuYXNuMS5ERVJTZXF1ZW5jZShvcHRpb25zKTtcblxuICBvcHRpb25zID0ge1xuICAgICdoZXgnOiAnMDAnICsgc2Vjb25kX3NlcXVlbmNlLmdldEVuY29kZWRIZXgoKVxuICB9O1xuICB2YXIgYml0X3N0cmluZyA9IG5ldyBLSlVSLmFzbjEuREVSQml0U3RyaW5nKG9wdGlvbnMpO1xuXG4gIG9wdGlvbnMgPSB7XG4gICAgJ2FycmF5JzogW1xuICAgICAgZmlyc3Rfc2VxdWVuY2UsXG4gICAgICBiaXRfc3RyaW5nXG4gICAgXVxuICB9O1xuICB2YXIgc2VxID0gbmV3IEtKVVIuYXNuMS5ERVJTZXF1ZW5jZShvcHRpb25zKTtcbiAgcmV0dXJuIHNlcS5nZXRFbmNvZGVkSGV4KCk7XG59O1xuXG4vKipcbiAqIGJhc2U2NCAocGVtKSBlbmNvZGVkIHZlcnNpb24gb2YgdGhlIERFUiBlbmNvZGVkIHJlcHJlc2VudGF0aW9uXG4gKiBAcmV0dXJucyB7c3RyaW5nfSBwZW0gZW5jb2RlZCByZXByZXNlbnRhdGlvbiB3aXRob3V0IGhlYWRlciBhbmQgZm9vdGVyXG4gKiBAcHVibGljXG4gKi9cblJTQUtleS5wcm90b3R5cGUuZ2V0UHVibGljQmFzZUtleUI2NCA9IGZ1bmN0aW9uICgpIHtcbiAgcmV0dXJuIGhleDJiNjQodGhpcy5nZXRQdWJsaWNCYXNlS2V5KCkpO1xufTtcblxuLyoqXG4gKiB3cmFwIHRoZSBzdHJpbmcgaW4gYmxvY2sgb2Ygd2lkdGggY2hhcnMuIFRoZSBkZWZhdWx0IHZhbHVlIGZvciByc2Ega2V5cyBpcyA2NFxuICogY2hhcmFjdGVycy5cbiAqIEBwYXJhbSB7c3RyaW5nfSBzdHIgdGhlIHBlbSBlbmNvZGVkIHN0cmluZyB3aXRob3V0IGhlYWRlciBhbmQgZm9vdGVyXG4gKiBAcGFyYW0ge051bWJlcn0gW3dpZHRoPTY0XSAtIHRoZSBsZW5ndGggdGhlIHN0cmluZyBoYXMgdG8gYmUgd3JhcHBlZCBhdFxuICogQHJldHVybnMge3N0cmluZ31cbiAqIEBwcml2YXRlXG4gKi9cblJTQUtleS5wcm90b3R5cGUud29yZHdyYXAgPSBmdW5jdGlvbiAoc3RyLCB3aWR0aCkge1xuICB3aWR0aCA9IHdpZHRoIHx8IDY0O1xuICBpZiAoIXN0cikge1xuICAgIHJldHVybiBzdHI7XG4gIH1cbiAgdmFyIHJlZ2V4ID0gJyguezEsJyArIHdpZHRoICsgJ30pKCArfCRcXG4/KXwoLnsxLCcgKyB3aWR0aCArICd9KSc7XG4gIHJldHVybiBzdHIubWF0Y2goUmVnRXhwKHJlZ2V4LCAnZycpKS5qb2luKCdcXG4nKTtcbn07XG5cbi8qKlxuICogUmV0cmlldmUgdGhlIHBlbSBlbmNvZGVkIHByaXZhdGUga2V5XG4gKiBAcmV0dXJucyB7c3RyaW5nfSB0aGUgcGVtIGVuY29kZWQgcHJpdmF0ZSBrZXkgd2l0aCBoZWFkZXIvZm9vdGVyXG4gKiBAcHVibGljXG4gKi9cblJTQUtleS5wcm90b3R5cGUuZ2V0UHJpdmF0ZUtleSA9IGZ1bmN0aW9uICgpIHtcbiAgdmFyIGtleSA9IFwiLS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLVxcblwiO1xuICBrZXkgKz0gdGhpcy53b3Jkd3JhcCh0aGlzLmdldFByaXZhdGVCYXNlS2V5QjY0KCkpICsgXCJcXG5cIjtcbiAga2V5ICs9IFwiLS0tLS1FTkQgUlNBIFBSSVZBVEUgS0VZLS0tLS1cIjtcbiAgcmV0dXJuIGtleTtcbn07XG5cbi8qKlxuICogUmV0cmlldmUgdGhlIHBlbSBlbmNvZGVkIHB1YmxpYyBrZXlcbiAqIEByZXR1cm5zIHtzdHJpbmd9IHRoZSBwZW0gZW5jb2RlZCBwdWJsaWMga2V5IHdpdGggaGVhZGVyL2Zvb3RlclxuICogQHB1YmxpY1xuICovXG5SU0FLZXkucHJvdG90eXBlLmdldFB1YmxpY0tleSA9IGZ1bmN0aW9uICgpIHtcbiAgdmFyIGtleSA9IFwiLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS1cXG5cIjtcbiAga2V5ICs9IHRoaXMud29yZHdyYXAodGhpcy5nZXRQdWJsaWNCYXNlS2V5QjY0KCkpICsgXCJcXG5cIjtcbiAga2V5ICs9IFwiLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tXCI7XG4gIHJldHVybiBrZXk7XG59O1xuXG4vKipcbiAqIENoZWNrIGlmIHRoZSBvYmplY3QgY29udGFpbnMgdGhlIG5lY2Vzc2FyeSBwYXJhbWV0ZXJzIHRvIHBvcHVsYXRlIHRoZSByc2EgbW9kdWx1c1xuICogYW5kIHB1YmxpYyBleHBvbmVudCBwYXJhbWV0ZXJzLlxuICogQHBhcmFtIHtPYmplY3R9IFtvYmo9e31dIC0gQW4gb2JqZWN0IHRoYXQgbWF5IGNvbnRhaW4gdGhlIHR3byBwdWJsaWMga2V5XG4gKiBwYXJhbWV0ZXJzXG4gKiBAcmV0dXJucyB7Ym9vbGVhbn0gdHJ1ZSBpZiB0aGUgb2JqZWN0IGNvbnRhaW5zIGJvdGggdGhlIG1vZHVsdXMgYW5kIHRoZSBwdWJsaWMgZXhwb25lbnRcbiAqIHByb3BlcnRpZXMgKG4gYW5kIGUpXG4gKiBAdG9kbyBjaGVjayBmb3IgdHlwZXMgb2YgbiBhbmQgZS4gTiBzaG91bGQgYmUgYSBwYXJzZWFibGUgYmlnSW50IG9iamVjdCwgRSBzaG91bGRcbiAqIGJlIGEgcGFyc2VhYmxlIGludGVnZXIgbnVtYmVyXG4gKiBAcHJpdmF0ZVxuICovXG5SU0FLZXkucHJvdG90eXBlLmhhc1B1YmxpY0tleVByb3BlcnR5ID0gZnVuY3Rpb24gKG9iaikge1xuICBvYmogPSBvYmogfHwge307XG4gIHJldHVybiAoXG4gICAgb2JqLmhhc093blByb3BlcnR5KCduJykgJiZcbiAgICBvYmouaGFzT3duUHJvcGVydHkoJ2UnKVxuICApO1xufTtcblxuLyoqXG4gKiBDaGVjayBpZiB0aGUgb2JqZWN0IGNvbnRhaW5zIEFMTCB0aGUgcGFyYW1ldGVycyBvZiBhbiBSU0Ega2V5LlxuICogQHBhcmFtIHtPYmplY3R9IFtvYmo9e31dIC0gQW4gb2JqZWN0IHRoYXQgbWF5IGNvbnRhaW4gbmluZSByc2Ega2V5XG4gKiBwYXJhbWV0ZXJzXG4gKiBAcmV0dXJucyB7Ym9vbGVhbn0gdHJ1ZSBpZiB0aGUgb2JqZWN0IGNvbnRhaW5zIGFsbCB0aGUgcGFyYW1ldGVycyBuZWVkZWRcbiAqIEB0b2RvIGNoZWNrIGZvciB0eXBlcyBvZiB0aGUgcGFyYW1ldGVycyBhbGwgdGhlIHBhcmFtZXRlcnMgYnV0IHRoZSBwdWJsaWMgZXhwb25lbnRcbiAqIHNob3VsZCBiZSBwYXJzZWFibGUgYmlnaW50IG9iamVjdHMsIHRoZSBwdWJsaWMgZXhwb25lbnQgc2hvdWxkIGJlIGEgcGFyc2VhYmxlIGludGVnZXIgbnVtYmVyXG4gKiBAcHJpdmF0ZVxuICovXG5SU0FLZXkucHJvdG90eXBlLmhhc1ByaXZhdGVLZXlQcm9wZXJ0eSA9IGZ1bmN0aW9uIChvYmopIHtcbiAgb2JqID0gb2JqIHx8IHt9O1xuICByZXR1cm4gKFxuICAgIG9iai5oYXNPd25Qcm9wZXJ0eSgnbicpICYmXG4gICAgb2JqLmhhc093blByb3BlcnR5KCdlJykgJiZcbiAgICBvYmouaGFzT3duUHJvcGVydHkoJ2QnKSAmJlxuICAgIG9iai5oYXNPd25Qcm9wZXJ0eSgncCcpICYmXG4gICAgb2JqLmhhc093blByb3BlcnR5KCdxJykgJiZcbiAgICBvYmouaGFzT3duUHJvcGVydHkoJ2RtcDEnKSAmJlxuICAgIG9iai5oYXNPd25Qcm9wZXJ0eSgnZG1xMScpICYmXG4gICAgb2JqLmhhc093blByb3BlcnR5KCdjb2VmZicpXG4gICk7XG59O1xuXG4vKipcbiAqIFBhcnNlIHRoZSBwcm9wZXJ0aWVzIG9mIG9iaiBpbiB0aGUgY3VycmVudCByc2Egb2JqZWN0LiBPYmogc2hvdWxkIEFUIExFQVNUXG4gKiBpbmNsdWRlIHRoZSBtb2R1bHVzIGFuZCBwdWJsaWMgZXhwb25lbnQgKG4sIGUpIHBhcmFtZXRlcnMuXG4gKiBAcGFyYW0ge09iamVjdH0gb2JqIC0gdGhlIG9iamVjdCBjb250YWluaW5nIHJzYSBwYXJhbWV0ZXJzXG4gKiBAcHJpdmF0ZVxuICovXG5SU0FLZXkucHJvdG90eXBlLnBhcnNlUHJvcGVydGllc0Zyb20gPSBmdW5jdGlvbiAob2JqKSB7XG4gIHRoaXMubiA9IG9iai5uO1xuICB0aGlzLmUgPSBvYmouZTtcblxuICBpZiAob2JqLmhhc093blByb3BlcnR5KCdkJykpIHtcbiAgICB0aGlzLmQgPSBvYmouZDtcbiAgICB0aGlzLnAgPSBvYmoucDtcbiAgICB0aGlzLnEgPSBvYmoucTtcbiAgICB0aGlzLmRtcDEgPSBvYmouZG1wMTtcbiAgICB0aGlzLmRtcTEgPSBvYmouZG1xMTtcbiAgICB0aGlzLmNvZWZmID0gb2JqLmNvZWZmO1xuICB9XG59O1xuXG4vKipcbiAqIENyZWF0ZSBhIG5ldyBKU0VuY3J5cHRSU0FLZXkgdGhhdCBleHRlbmRzIFRvbSBXdSdzIFJTQSBrZXkgb2JqZWN0LlxuICogVGhpcyBvYmplY3QgaXMganVzdCBhIGRlY29yYXRvciBmb3IgcGFyc2luZyB0aGUga2V5IHBhcmFtZXRlclxuICogQHBhcmFtIHtzdHJpbmd8T2JqZWN0fSBrZXkgLSBUaGUga2V5IGluIHN0cmluZyBmb3JtYXQsIG9yIGFuIG9iamVjdCBjb250YWluaW5nXG4gKiB0aGUgcGFyYW1ldGVycyBuZWVkZWQgdG8gYnVpbGQgYSBSU0FLZXkgb2JqZWN0LlxuICogQGNvbnN0cnVjdG9yXG4gKi9cbnZhciBKU0VuY3J5cHRSU0FLZXkgPSBmdW5jdGlvbiAoa2V5KSB7XG4gIC8vIENhbGwgdGhlIHN1cGVyIGNvbnN0cnVjdG9yLlxuICBSU0FLZXkuY2FsbCh0aGlzKTtcbiAgLy8gSWYgYSBrZXkga2V5IHdhcyBwcm92aWRlZC5cbiAgaWYgKGtleSkge1xuICAgIC8vIElmIHRoaXMgaXMgYSBzdHJpbmcuLi5cbiAgICBpZiAodHlwZW9mIGtleSA9PT0gJ3N0cmluZycpIHtcbiAgICAgIHRoaXMucGFyc2VLZXkoa2V5KTtcbiAgICB9XG4gICAgZWxzZSBpZiAoXG4gICAgICB0aGlzLmhhc1ByaXZhdGVLZXlQcm9wZXJ0eShrZXkpIHx8XG4gICAgICB0aGlzLmhhc1B1YmxpY0tleVByb3BlcnR5KGtleSlcbiAgICApIHtcbiAgICAgIC8vIFNldCB0aGUgdmFsdWVzIGZvciB0aGUga2V5LlxuICAgICAgdGhpcy5wYXJzZVByb3BlcnRpZXNGcm9tKGtleSk7XG4gICAgfVxuICB9XG59O1xuXG4vLyBEZXJpdmUgZnJvbSBSU0FLZXkuXG5KU0VuY3J5cHRSU0FLZXkucHJvdG90eXBlID0gbmV3IFJTQUtleSgpO1xuXG4vLyBSZXNldCB0aGUgY29udHJ1Y3Rvci5cbkpTRW5jcnlwdFJTQUtleS5wcm90b3R5cGUuY29uc3RydWN0b3IgPSBKU0VuY3J5cHRSU0FLZXk7XG5cblxuLyoqXG4gKlxuICogQHBhcmFtIHtPYmplY3R9IFtvcHRpb25zID0ge31dIC0gQW4gb2JqZWN0IHRvIGN1c3RvbWl6ZSBKU0VuY3J5cHQgYmVoYXZpb3VyXG4gKiBwb3NzaWJsZSBwYXJhbWV0ZXJzIGFyZTpcbiAqIC0gZGVmYXVsdF9rZXlfc2l6ZSAgICAgICAge251bWJlcn0gIGRlZmF1bHQ6IDEwMjQgdGhlIGtleSBzaXplIGluIGJpdFxuICogLSBkZWZhdWx0X3B1YmxpY19leHBvbmVudCB7c3RyaW5nfSAgZGVmYXVsdDogJzAxMDAwMScgdGhlIGhleGFkZWNpbWFsIHJlcHJlc2VudGF0aW9uIG9mIHRoZSBwdWJsaWMgZXhwb25lbnRcbiAqIC0gbG9nICAgICAgICAgICAgICAgICAgICAge2Jvb2xlYW59IGRlZmF1bHQ6IGZhbHNlIHdoZXRoZXIgbG9nIHdhcm4vZXJyb3Igb3Igbm90XG4gKiBAY29uc3RydWN0b3JcbiAqL1xudmFyIEpTRW5jcnlwdCA9IGZ1bmN0aW9uIChvcHRpb25zKSB7XG4gIG9wdGlvbnMgPSBvcHRpb25zIHx8IHt9O1xuICB0aGlzLmRlZmF1bHRfa2V5X3NpemUgPSBwYXJzZUludChvcHRpb25zLmRlZmF1bHRfa2V5X3NpemUpIHx8IDEwMjQ7XG4gIHRoaXMuZGVmYXVsdF9wdWJsaWNfZXhwb25lbnQgPSBvcHRpb25zLmRlZmF1bHRfcHVibGljX2V4cG9uZW50IHx8ICcwMTAwMDEnOyAvLzY1NTM3IGRlZmF1bHQgb3BlbnNzbCBwdWJsaWMgZXhwb25lbnQgZm9yIHJzYSBrZXkgdHlwZVxuICB0aGlzLmxvZyA9IG9wdGlvbnMubG9nIHx8IGZhbHNlO1xuICAvLyBUaGUgcHJpdmF0ZSBhbmQgcHVibGljIGtleS5cbiAgdGhpcy5rZXkgPSBudWxsO1xufTtcblxuLyoqXG4gKiBNZXRob2QgdG8gc2V0IHRoZSByc2Ega2V5IHBhcmFtZXRlciAob25lIG1ldGhvZCBpcyBlbm91Z2ggdG8gc2V0IGJvdGggdGhlIHB1YmxpY1xuICogYW5kIHRoZSBwcml2YXRlIGtleSwgc2luY2UgdGhlIHByaXZhdGUga2V5IGNvbnRhaW5zIHRoZSBwdWJsaWMga2V5IHBhcmFtZW50ZXJzKVxuICogTG9nIGEgd2FybmluZyBpZiBsb2dzIGFyZSBlbmFibGVkXG4gKiBAcGFyYW0ge09iamVjdHxzdHJpbmd9IGtleSB0aGUgcGVtIGVuY29kZWQgc3RyaW5nIG9yIGFuIG9iamVjdCAod2l0aCBvciB3aXRob3V0IGhlYWRlci9mb290ZXIpXG4gKiBAcHVibGljXG4gKi9cbkpTRW5jcnlwdC5wcm90b3R5cGUuc2V0S2V5ID0gZnVuY3Rpb24gKGtleSkge1xuICBpZiAodGhpcy5sb2cgJiYgdGhpcy5rZXkpIHtcbiAgICBjb25zb2xlLndhcm4oJ0Ega2V5IHdhcyBhbHJlYWR5IHNldCwgb3ZlcnJpZGluZyBleGlzdGluZy4nKTtcbiAgfVxuICB0aGlzLmtleSA9IG5ldyBKU0VuY3J5cHRSU0FLZXkoa2V5KTtcbn07XG5cbi8qKlxuICogUHJveHkgbWV0aG9kIGZvciBzZXRLZXksIGZvciBhcGkgY29tcGF0aWJpbGl0eVxuICogQHNlZSBzZXRLZXlcbiAqIEBwdWJsaWNcbiAqL1xuSlNFbmNyeXB0LnByb3RvdHlwZS5zZXRQcml2YXRlS2V5ID0gZnVuY3Rpb24gKHByaXZrZXkpIHtcbiAgLy8gQ3JlYXRlIHRoZSBrZXkuXG4gIHRoaXMuc2V0S2V5KHByaXZrZXkpO1xufTtcblxuLyoqXG4gKiBQcm94eSBtZXRob2QgZm9yIHNldEtleSwgZm9yIGFwaSBjb21wYXRpYmlsaXR5XG4gKiBAc2VlIHNldEtleVxuICogQHB1YmxpY1xuICovXG5KU0VuY3J5cHQucHJvdG90eXBlLnNldFB1YmxpY0tleSA9IGZ1bmN0aW9uIChwdWJrZXkpIHtcbiAgLy8gU2V0cyB0aGUgcHVibGljIGtleS5cbiAgdGhpcy5zZXRLZXkocHVia2V5KTtcbn07XG5cbi8qKlxuICogUHJveHkgbWV0aG9kIGZvciBSU0FLZXkgb2JqZWN0J3MgZGVjcnlwdCwgZGVjcnlwdCB0aGUgc3RyaW5nIHVzaW5nIHRoZSBwcml2YXRlXG4gKiBjb21wb25lbnRzIG9mIHRoZSByc2Ega2V5IG9iamVjdC4gTm90ZSB0aGF0IGlmIHRoZSBvYmplY3Qgd2FzIG5vdCBzZXQgd2lsbCBiZSBjcmVhdGVkXG4gKiBvbiB0aGUgZmx5IChieSB0aGUgZ2V0S2V5IG1ldGhvZCkgdXNpbmcgdGhlIHBhcmFtZXRlcnMgcGFzc2VkIGluIHRoZSBKU0VuY3J5cHQgY29uc3RydWN0b3JcbiAqIEBwYXJhbSB7c3RyaW5nfSBzdHJpbmcgYmFzZTY0IGVuY29kZWQgY3J5cHRlZCBzdHJpbmcgdG8gZGVjcnlwdFxuICogQHJldHVybiB7c3RyaW5nfSB0aGUgZGVjcnlwdGVkIHN0cmluZ1xuICogQHB1YmxpY1xuICovXG5KU0VuY3J5cHQucHJvdG90eXBlLmRlY3J5cHQgPSBmdW5jdGlvbiAoc3RyaW5nKSB7XG4gIC8vIFJldHVybiB0aGUgZGVjcnlwdGVkIHN0cmluZy5cbiAgdHJ5IHtcbiAgICByZXR1cm4gdGhpcy5nZXRLZXkoKS5kZWNyeXB0KGI2NHRvaGV4KHN0cmluZykpO1xuICB9XG4gIGNhdGNoIChleCkge1xuICAgIHJldHVybiBmYWxzZTtcbiAgfVxufTtcblxuLyoqXG4gKiBQcm94eSBtZXRob2QgZm9yIFJTQUtleSBvYmplY3QncyBlbmNyeXB0LCBlbmNyeXB0IHRoZSBzdHJpbmcgdXNpbmcgdGhlIHB1YmxpY1xuICogY29tcG9uZW50cyBvZiB0aGUgcnNhIGtleSBvYmplY3QuIE5vdGUgdGhhdCBpZiB0aGUgb2JqZWN0IHdhcyBub3Qgc2V0IHdpbGwgYmUgY3JlYXRlZFxuICogb24gdGhlIGZseSAoYnkgdGhlIGdldEtleSBtZXRob2QpIHVzaW5nIHRoZSBwYXJhbWV0ZXJzIHBhc3NlZCBpbiB0aGUgSlNFbmNyeXB0IGNvbnN0cnVjdG9yXG4gKiBAcGFyYW0ge3N0cmluZ30gc3RyaW5nIHRoZSBzdHJpbmcgdG8gZW5jcnlwdFxuICogQHJldHVybiB7c3RyaW5nfSB0aGUgZW5jcnlwdGVkIHN0cmluZyBlbmNvZGVkIGluIGJhc2U2NFxuICogQHB1YmxpY1xuICovXG5KU0VuY3J5cHQucHJvdG90eXBlLmVuY3J5cHQgPSBmdW5jdGlvbiAoc3RyaW5nKSB7XG4gIC8vIFJldHVybiB0aGUgZW5jcnlwdGVkIHN0cmluZy5cbiAgdHJ5IHtcbiAgICByZXR1cm4gaGV4MmI2NCh0aGlzLmdldEtleSgpLmVuY3J5cHQoc3RyaW5nKSk7XG4gIH1cbiAgY2F0Y2ggKGV4KSB7XG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG59O1xuXG4vKipcbiAqIEdldHRlciBmb3IgdGhlIGN1cnJlbnQgSlNFbmNyeXB0UlNBS2V5IG9iamVjdC4gSWYgaXQgZG9lc24ndCBleGlzdHMgYSBuZXcgb2JqZWN0XG4gKiB3aWxsIGJlIGNyZWF0ZWQgYW5kIHJldHVybmVkXG4gKiBAcGFyYW0ge2NhbGxiYWNrfSBbY2JdIHRoZSBjYWxsYmFjayB0byBiZSBjYWxsZWQgaWYgd2Ugd2FudCB0aGUga2V5IHRvIGJlIGdlbmVyYXRlZFxuICogaW4gYW4gYXN5bmMgZmFzaGlvblxuICogQHJldHVybnMge0pTRW5jcnlwdFJTQUtleX0gdGhlIEpTRW5jcnlwdFJTQUtleSBvYmplY3RcbiAqIEBwdWJsaWNcbiAqL1xuSlNFbmNyeXB0LnByb3RvdHlwZS5nZXRLZXkgPSBmdW5jdGlvbiAoY2IpIHtcbiAgLy8gT25seSBjcmVhdGUgbmV3IGlmIGl0IGRvZXMgbm90IGV4aXN0LlxuICBpZiAoIXRoaXMua2V5KSB7XG4gICAgLy8gR2V0IGEgbmV3IHByaXZhdGUga2V5LlxuICAgIHRoaXMua2V5ID0gbmV3IEpTRW5jcnlwdFJTQUtleSgpO1xuICAgIGlmIChjYiAmJiB7fS50b1N0cmluZy5jYWxsKGNiKSA9PT0gJ1tvYmplY3QgRnVuY3Rpb25dJykge1xuICAgICAgdGhpcy5rZXkuZ2VuZXJhdGVBc3luYyh0aGlzLmRlZmF1bHRfa2V5X3NpemUsIHRoaXMuZGVmYXVsdF9wdWJsaWNfZXhwb25lbnQsIGNiKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG4gICAgLy8gR2VuZXJhdGUgdGhlIGtleS5cbiAgICB0aGlzLmtleS5nZW5lcmF0ZSh0aGlzLmRlZmF1bHRfa2V5X3NpemUsIHRoaXMuZGVmYXVsdF9wdWJsaWNfZXhwb25lbnQpO1xuICB9XG4gIHJldHVybiB0aGlzLmtleTtcbn07XG5cbi8qKlxuICogUmV0dXJucyB0aGUgcGVtIGVuY29kZWQgcmVwcmVzZW50YXRpb24gb2YgdGhlIHByaXZhdGUga2V5XG4gKiBJZiB0aGUga2V5IGRvZXNuJ3QgZXhpc3RzIGEgbmV3IGtleSB3aWxsIGJlIGNyZWF0ZWRcbiAqIEByZXR1cm5zIHtzdHJpbmd9IHBlbSBlbmNvZGVkIHJlcHJlc2VudGF0aW9uIG9mIHRoZSBwcml2YXRlIGtleSBXSVRIIGhlYWRlciBhbmQgZm9vdGVyXG4gKiBAcHVibGljXG4gKi9cbkpTRW5jcnlwdC5wcm90b3R5cGUuZ2V0UHJpdmF0ZUtleSA9IGZ1bmN0aW9uICgpIHtcbiAgLy8gUmV0dXJuIHRoZSBwcml2YXRlIHJlcHJlc2VudGF0aW9uIG9mIHRoaXMga2V5LlxuICByZXR1cm4gdGhpcy5nZXRLZXkoKS5nZXRQcml2YXRlS2V5KCk7XG59O1xuXG4vKipcbiAqIFJldHVybnMgdGhlIHBlbSBlbmNvZGVkIHJlcHJlc2VudGF0aW9uIG9mIHRoZSBwcml2YXRlIGtleVxuICogSWYgdGhlIGtleSBkb2Vzbid0IGV4aXN0cyBhIG5ldyBrZXkgd2lsbCBiZSBjcmVhdGVkXG4gKiBAcmV0dXJucyB7c3RyaW5nfSBwZW0gZW5jb2RlZCByZXByZXNlbnRhdGlvbiBvZiB0aGUgcHJpdmF0ZSBrZXkgV0lUSE9VVCBoZWFkZXIgYW5kIGZvb3RlclxuICogQHB1YmxpY1xuICovXG5KU0VuY3J5cHQucHJvdG90eXBlLmdldFByaXZhdGVLZXlCNjQgPSBmdW5jdGlvbiAoKSB7XG4gIC8vIFJldHVybiB0aGUgcHJpdmF0ZSByZXByZXNlbnRhdGlvbiBvZiB0aGlzIGtleS5cbiAgcmV0dXJuIHRoaXMuZ2V0S2V5KCkuZ2V0UHJpdmF0ZUJhc2VLZXlCNjQoKTtcbn07XG5cblxuLyoqXG4gKiBSZXR1cm5zIHRoZSBwZW0gZW5jb2RlZCByZXByZXNlbnRhdGlvbiBvZiB0aGUgcHVibGljIGtleVxuICogSWYgdGhlIGtleSBkb2Vzbid0IGV4aXN0cyBhIG5ldyBrZXkgd2lsbCBiZSBjcmVhdGVkXG4gKiBAcmV0dXJucyB7c3RyaW5nfSBwZW0gZW5jb2RlZCByZXByZXNlbnRhdGlvbiBvZiB0aGUgcHVibGljIGtleSBXSVRIIGhlYWRlciBhbmQgZm9vdGVyXG4gKiBAcHVibGljXG4gKi9cbkpTRW5jcnlwdC5wcm90b3R5cGUuZ2V0UHVibGljS2V5ID0gZnVuY3Rpb24gKCkge1xuICAvLyBSZXR1cm4gdGhlIHByaXZhdGUgcmVwcmVzZW50YXRpb24gb2YgdGhpcyBrZXkuXG4gIHJldHVybiB0aGlzLmdldEtleSgpLmdldFB1YmxpY0tleSgpO1xufTtcblxuLyoqXG4gKiBSZXR1cm5zIHRoZSBwZW0gZW5jb2RlZCByZXByZXNlbnRhdGlvbiBvZiB0aGUgcHVibGljIGtleVxuICogSWYgdGhlIGtleSBkb2Vzbid0IGV4aXN0cyBhIG5ldyBrZXkgd2lsbCBiZSBjcmVhdGVkXG4gKiBAcmV0dXJucyB7c3RyaW5nfSBwZW0gZW5jb2RlZCByZXByZXNlbnRhdGlvbiBvZiB0aGUgcHVibGljIGtleSBXSVRIT1VUIGhlYWRlciBhbmQgZm9vdGVyXG4gKiBAcHVibGljXG4gKi9cbkpTRW5jcnlwdC5wcm90b3R5cGUuZ2V0UHVibGljS2V5QjY0ID0gZnVuY3Rpb24gKCkge1xuICAvLyBSZXR1cm4gdGhlIHByaXZhdGUgcmVwcmVzZW50YXRpb24gb2YgdGhpcyBrZXkuXG4gIHJldHVybiB0aGlzLmdldEtleSgpLmdldFB1YmxpY0Jhc2VLZXlCNjQoKTtcbn07XG5cblxuICBKU0VuY3J5cHQudmVyc2lvbiA9ICcyLjMuMSc7XG4gIGV4cG9ydHMuSlNFbmNyeXB0ID0gSlNFbmNyeXB0O1xufSk7IiwiLypqc2hpbnQgbXVsdGlzdHI6IHRydWUgKi9cblxubW9kdWxlLmV4cG9ydHMgPSB7XG4gIHB1YmxpY19rZXk6IFwiLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS1cXFxuICAgICAgICAgICAgICBNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXVqOVNaUzMrK1FlUVdkdWVpVTJKXFxcbiAgICAgICAgICAgICAgdzRxZjlCTVRZSE55S1kwcGJOQlFZbDdTY3BVYzZRR1dEcHlBUFBmd0hhUStueHRlZkZmaFpmZ0pXbHpaN0UwR1xcXG4gICAgICAgICAgICAgIEp2WWVPUkNIdjBQODhPY1hJMUIvNy9Xc1U2eTZqL3piMnptL0I2cWl5SmxzNnpsYTZXZmRmQlMwZXhJRG1jeGpcXFxuICAgICAgICAgICAgICB4Y0ZZZjluOUp5Zkw1b0Rha2Y1Q0Q0NDJMQkVOcDd3Qkh4WVliYmk5UzN0TmlRTGNxcld2YkNkNjRuMDJrZ25NXFxcbiAgICAgICAgICAgICAgSFRpRnY1d3c1bVRQRTE1R0JQUlA0bTFDZjRGMFBidUxTTzZwSHJvMnJnYUlsV2llRER3NmZEQWpKNkZzQVBJUlxcXG4gICAgICAgICAgICAgIFpoS2N3VURPL0k4RDNnazBEVEkzQm80aUc3L2hBSSswbE1ET1BqcGFIeXVVNGdrZjd0ZFczb1J1a1FGKzM0MnFcXFxuICAgICAgICAgICAgICA5UUlEQVFBQlxcXG4gICAgICAgICAgICAgIC0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLVwiXG59XG4iLCIvKmpzaGludCBtdWx0aXN0cjogdHJ1ZSAqL1xuSlNFbmNyeXB0ID0gcmVxdWlyZSgnanNlbmNyeXB0JykuSlNFbmNyeXB0O1xuQ29uc3RhbnRzID0gcmVxdWlyZSgnLi4vY29uc3RhbnRzJyk7XG5cbmZ1bmN0aW9uIGVuY3J5cHRLZXlWYWx1ZVBhaXIocGFpcil7XG4gIHZhciBjcnlwdCA9IG5ldyBKU0VuY3J5cHQoKTtcbiAgY3J5cHQuc2V0UHVibGljS2V5KENvbnN0YW50cy5wdWJsaWNfa2V5KTtcbiAgZW5jcnlwdGVkX3BhaXIgPSB7XG4gICAga2V5OiBjcnlwdC5lbmNyeXB0KHBhaXIua2V5KSxcbiAgICB2YWx1ZTogY3J5cHQuZW5jcnlwdChwYWlyLnZhbHVlKVxuICB9O1xuICByZXR1cm4gZW5jcnlwdGVkX3BhaXI7XG59XG5cbmZ1bmN0aW9uIHN1Ym1pdEtleVZhbHVlUGFpcihldmVudCkge1xuICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICBrZXlfZWxlbWVudCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwia2V5XCIpO1xuICB2YWx1ZV9lbGVtZW50ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJ2YWx1ZVwiKTtcblxuICB2YXIgcGFpciA9IHtcbiAgICBrZXkgOiBrZXlfZWxlbWVudC52YWx1ZSxcbiAgICB2YWx1ZSA6IHZhbHVlX2VsZW1lbnQudmFsdWVcbiAgfTtcblxuICB2YXIgZW5jcnlwdGVkX3BhaXIgPSBlbmNyeXB0S2V5VmFsdWVQYWlyKHBhaXIpO1xuXG4gIHNlbmQoZW5jcnlwdGVkX3BhaXIpO1xufVxuXG5mdW5jdGlvbiBzZW5kKGVuY3J5cHRlZF9wYWlyKSB7XG4gIHZhciB4aHR0cCA9IG5ldyBYTUxIdHRwUmVxdWVzdCgpO1xuICB4aHR0cC5vbnJlYWR5c3RhdGVjaGFuZ2UgPSBmdW5jdGlvbigpIHtcbiAgICBpZiAoeGh0dHAucmVhZHlTdGF0ZSA9PSA0ICYmIHhodHRwLnN0YXR1cyA9PSAyMDApIHtcbiAgICAgYWxlcnQoJ1NlbnQgc3VjY2Vzc2Z1bGx5Jyk7XG4gICAgfVxuICB9O1xuICB4aHR0cC5vcGVuKFwiUE9TVFwiLCBcIndyaXRlXCIsIHRydWUpO1xuICB4aHR0cC5zZXRSZXF1ZXN0SGVhZGVyKFwiQ29udGVudC1UeXBlXCIsIFwiYXBwbGljYXRpb24vanNvbjtjaGFyc2V0PVVURi04XCIpO1xuICB4aHR0cC5zZW5kKEpTT04uc3RyaW5naWZ5KGVuY3J5cHRlZF9wYWlyKSk7XG59XG5cbndpbmRvdy5vbmxvYWQgPSBmdW5jdGlvbigpe1xuICB2YXIgZm9ybSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwiZm9ybVwiKTtcbiAgZm9ybS5hZGRFdmVudExpc3RlbmVyKCdzdWJtaXQnLCBzdWJtaXRLZXlWYWx1ZVBhaXIpO1xufTtcbiJdfQ==
