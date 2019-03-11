const crypto = require('crypto');
const assert = require('assert');
const util = require('util');

/**
 * Assert a value to be true, or throw error with optional message
 * @param {Boolean} val
 * @param {String} msg
 */
function assert_(val, msg) {
  if (!val) throw new Error(msg || 'assertion');
}

/**
 * Convert a Buffer to a BigInt
 * @param {Buffer} buf
 * @return {BigInt}
 */
function bufferToBigInt(buf) {
  assertIsBuffer(buf);
  return BigInt('0x' + buf.toString('hex'));
}

/**
 * Calculates a % b, the sane way
 * Modulo in JavaScript: -27 % 7 => -6
 * Modulo in everything else: -27 % 7 => 1
 * @param {BigInt} a
 * @param {BigInt} b
 * @return {BigInt}
 */
function mod(a, b) {
  let result = a % b;
  if (result < 0n) result += b;
  return result;
}

/**
 * Calculates b^e % m efficiently
 * https://en.wikipedia.org/wiki/Modular_exponentiation#Right-to-left_binary_method
 * @param {BigInt} b Base
 * @param {BigInt} e Exponent
 * @param {BigInt} m Modulo
 * @return {BigInt}
 */
function powm(b, e, m) {
  if (m === 1n) return 0;
  let result = 1n;
  b = mod(b, m);
  while (e > 0) {
    if (e % 2n === 1n) result = result * b % m;
    e = e >> 1n;
    b = b ** 2n % m;
  }
  return result;
}

/**
 * Convert a BigInt to a Buffer
 * @param {BigInt} n
 * @return {Buffer}
 */
function bigIntToBuffer(n) {
  assertIsBigInt(n);
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  return Buffer.from(hex, 'hex');
}

/**
 * Pad a buffer to a length
 * Original comment:
 * If a conversion is explicitly specified with the operator PAD(),
 * the integer will first be implicitly converted, then the resultant
 * byte-string will be left-padded with zeros (if necessary) until its
 * length equals the implicitly-converted length of N.
 * @param {Buffer} n Buffer to pad
 * @param {Number} len Desired length of result
 * @return {Buffer}
 */
function padTo(n, len) {
  assertIsBuffer(n, 'n');
  let padding = len - n.length;
  assert_(padding > -1, 'Negative padding.  Very uncomfortable.');
  let result = Buffer.alloc(len);
  result.fill(0, 0, padding);
  n.copy(result, padding);
  assert.equal(result.length, len);
  return result;
}

/**
 * Pad the SRP N value
 * @param {BigInt} number Number to pad
 * @param {Object} params SRP parameters
 * @return {Buffer}
 */
function padToN(number, params) {
  assertIsBigInt(number);
  return padTo(bigIntToBuffer(number), params.N_length_bits / 8);
}

/* never used?
function padToH(number, params) {
  assertIsBigInt(number);
  let hashlen_bits;
  if (params.hash === 'sha1')
    {hashlen_bits = 160;}
  else if (params.hash === 'sha256')
    {hashlen_bits = 256;}
  else if (params.hash === 'sha512')
    {hashlen_bits = 512;}
  else
    {throw Error('cannot determine length of hash \''+params.hash+'\'');}

  return padTo(number.toBuffer(), hashlen_bits / 8);
}
*/

/**
 * Assert the argument to be a Buffer
 * @param {*} arg
 * @param {String} argName Original name of argument
 */
function assertIsBuffer(arg, argName) {
  argName = argName || 'arg';
  assert_(Buffer.isBuffer(arg), argName + ' must be a buffer');
}

/**
 * Assert the argument to be a Buffer with a valid SRP N value
 * @param {*} arg
 * @param {Object} params SRP params
 * @param {String} argName Original name of argument
 */
function assertIsNBuffer(arg, params, argName) {
  argName = argName || 'arg';
  assert_(Buffer.isBuffer(arg), 'Type error: ' + argName + ' must be a buffer');
  if (arg.length != params.N_length_bits / 8) {
    assert_(false, `${argName} was ${arg.length}, expected ${params.N_length_bits / 8}`);
  }
}

/**
 * Assert the argument to be a BigInt
 * @param {*} arg
 */
function assertIsBigInt(arg) {
  assert(typeof arg === 'bigint');
}

/**
 * compute the intermediate value x as a hash of three buffers:
 * salt, identity, and password.  And a colon.  FOUR buffers.
 *      x = H(s | H(I | ":" | P))
 * @param {Object} params SRP parameters
 * @param {Buffer} salt Salt
 * @param {Buffer} I User identity
 * @param {Buffer} P User password
 * @return {BigInt} User secret
 */
function getx(params, salt, I, P) {
  assertIsBuffer(salt, 'salt (salt)');
  assertIsBuffer(I, 'identity (I)');
  assertIsBuffer(P, 'password (P)');
  let hashIP = crypto.createHash(params.hash)
    .update(Buffer.concat([I, Buffer.from(':'), P]))
    .digest();
  let hashX = crypto.createHash(params.hash)
    .update(salt)
    .update(hashIP)
    .digest();
  return bufferToBigInt(hashX);
}

/**
 * The verifier is calculated as described in Section 3 of [SRP-RFC].
 * We give the algorithm here for convenience.
 *
 * The verifier (v) is computed based on the salt (s), user name (I),
 * password (P), and group parameters (N, g).
 *
 *         x = H(s | H(I | ":" | P))
 *         v = g^x % N
 *
 * @param {Object} params SRP parameters
 * @param {Buffer} salt Salt
 * @param {Buffer} I User identity
 * @param {Buffer} P User password
 * @return {Buffer}
 */
function computeVerifier(params, salt, I, P) {
  assertIsBuffer(salt, 'salt (salt)');
  assertIsBuffer(I, 'identity (I)');
  assertIsBuffer(P, 'password (P)');
  let vNum = powm(params.g, getx(params, salt, I, P), params.N);
  return padToN(vNum, params);
}

/**
 * calculate the SRP-6 multiplier
 * @param {Object} params SRP parameters
 * @return {BigInt}
 */
function getk(params) {
  let kBuf = crypto
    .createHash(params.hash)
    .update(padToN(params.N, params))
    .update(padToN(params.g, params))
    .digest();
  return bufferToBigInt(kBuf);
}

let randomBytesAsync = util.promisify(crypto.randomBytes);
/**
 * Generate a random key
 * @param {Number} bytes Length of key
 * @return {Buffer}
 */
async function genKey(bytes = 32) {
  return await randomBytesAsync(bytes);
}

/**
 * The server key exchange message also contains the server's public
 * value (B).  The server calculates this value as B = k*v + g^b % N,
 * where b is a random number that SHOULD be at least 256 bits in length
 * and k = H(N | PAD(g)).
 *
 * Note: as the tests imply, the entire expression is mod N.
 *
 * @param {Object} params SRP parameters
 * @param {BigInt} k SRP multiplier (k)
 * @param {BigInt} v SRP verifier
 * @param {BigInt} b Server secret exponent (b)
 * @return {Buffer} Server public message (B)
 */
function getB(params, k, v, b) {
  assertIsBigInt(v);
  assertIsBigInt(k);
  assertIsBigInt(b);
  let N = params.N;
  let r = (k * v + powm(params.g, b, N)) % N;
  return padToN(r, params);
}

/**
 * The client key exchange message carries the client's public value
 * (A).  The client calculates this value as A = g^a % N, where a is a
 * random number that SHOULD be at least 256 bits in length.
 *
 * Note: for this implementation, we take that to mean 256/8 bytes.
 *
 * @param {Object} params SRP parameters
 * @param {BigInt} aNum Client secret component (a)
 * @return {BigInt} Client public component (A)
 */
function getA(params, aNum) {
  assertIsBigInt(aNum);
  /* we haven't implemented bitLengtha
  if (Math.ceil(aNum.bitLength() / 8) < 256 / 8) {
    console.warn('getA: client key length', aNum.bitLength(), 'is less than the recommended 256');
  }
  */
  return padToN(powm(params.g, aNum, params.N), params);
}

/**
 * getu() hashes the two public messages together, to obtain a scrambling
 * parameter "u" which cannot be predicted by either party ahead of time.
 * This makes it safe to use the message ordering defined in the SRP-6a
 * paper, in which the server reveals their "B" value before the client
 * commits to their "A" value.
 *
 * @param {Object} params SRP parameters
 * @param {Buffer} A Client ephemeral public key (A)
 * @param {Buffer} B Server ephemeral public key (B)
 * @return {BigInt} Shared scrambling parameter (u)
 */
function getu(params, A, B) {
  assertIsNBuffer(A, params, 'A');
  assertIsNBuffer(B, params, 'B');
  let uBuf = crypto.createHash(params.hash)
    .update(A).update(B)
    .digest();
  return bufferToBigInt(uBuf);
}

/**
 * The TLS premaster secret as calculated by the client
 * @param {Object} params SRP parameters
 * @param {Buffer} kNum SRP multiplier (k)
 * @param {Buffer} xNum User secret (calculated from I, P, and salt) (x)
 * @param {Buffer} aNum Client ephemeral private key (a)
 * @param {BigInt} BNum Server ephemeral public key, obtained from server (B)
 * @param {BigInt} uNum SRP scrambling parameter (u)
 * @return {Buffer}
 */
function clientGetS(params, kNum, xNum, aNum, BNum, uNum) {
  assertIsBigInt(kNum);
  assertIsBigInt(xNum);
  assertIsBigInt(aNum);
  assertIsBigInt(BNum);
  assertIsBigInt(uNum);
  let g = params.g;
  let N = params.N;
  if (BNum <= 0 || N <= BNum) {
    throw new Error('invalid server-supplied \'B\', must be 1..N-1');
  }
  let SNum = powm(BNum - kNum * powm(g, xNum, N), aNum + uNum * xNum, N) % N;
  return padToN(SNum, params);
}

/**
 * The TLS premastersecret as calculated by the server
 * @param {Object} params SRP parameters
 * @param {BigInt} vNum Verifier (v)
 * @param {BigInt} ANum Client ephemeral public key (A)
 * @param {BigInt} bNum Server ephemeral private key (b)
 * @param {BigInt} uNum SRP scrambling parameter (u)
 * @return {Buffer}
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         v (bignum)       verifier (stored on server)
 *         A (bignum)       ephemeral client public key (read from client)
 *         b (bignum)       server ephemeral private key (generated for session)
 *
 * returns: bignum
 */
function serverGetS(params, vNum, ANum, bNum, uNum) {
  assertIsBigInt(vNum);
  assertIsBigInt(ANum);
  assertIsBigInt(bNum);
  assertIsBigInt(uNum);
  let N = params.N;
  if (ANum <= 0n || N <= ANum) {
    throw new Error('invalid client-supplied \'A\', must be 1..N-1');
  }
  let SNum = powm(ANum * powm(vNum, uNum, N), bNum, N) % N;
  return padToN(SNum, params);
}

/**
 * Compute the shared session key K from S
 *
 * @param {Object} params SRP parameters
 * @param {Buffer} SBuf SRP session key (S)
 * @return {Buffer} SRP strong session key (K)
 */
function getK(params, SBuf) {
  assertIsNBuffer(SBuf, params, 'S');
  return crypto.createHash(params.hash)
    .update(SBuf)
    .digest();
}

/**
 * Compute the M1 verification parameter (sent to server)
 * @param {Object} params SRP parameters
 * @param {Buffer} ABuf Client ephemeral public key (A)
 * @param {Buffer} BBuf Server ephemeral public key (B)
 * @param {Buffer} SBuf Shared session key (S)
 * @return {Buffer}
 */
function getM1(params, ABuf, BBuf, SBuf) {
  assertIsNBuffer(ABuf, params, 'A');
  assertIsNBuffer(BBuf, params, 'B');
  assertIsNBuffer(SBuf, params, 'S');
  return crypto.createHash(params.hash)
    .update(ABuf).update(BBuf).update(SBuf)
    .digest();
}

/**
 * Compute the M2 verification parameter (sent to client)
 * @param {Object} params SRP parameters
 * @param {Buffer} ABuf Client ephemeral public key (A)
 * @param {Buffer} MBuf M1 verification parameter (M1)
 * @param {Buffer} KBuf Strong shared session key (K)
 * @return {Buffer}
 */
function getM2(params, ABuf, MBuf, KBuf) {
  assertIsNBuffer(ABuf, params, 'A');
  assertIsBuffer(MBuf, 'M');
  assertIsBuffer(KBuf, 'K');
  return crypto.createHash(params.hash)
    .update(ABuf).update(MBuf).update(KBuf)
    .digest();
}

/**
 * Constant-time buffer equality checking
 * @param {Buffer} buf1
 * @param {Buffer} buf2
 * @return {Boolean}
 */
function equal(buf1, buf2) {
  let mismatch = buf1.length - buf2.length;
  if (mismatch) return false;
  for (let i = 0; i < buf1.length; i++) {
    mismatch |= buf1[i] ^ buf2[i];
  }
  return mismatch === 0;
}

/** Represents an SRP client */
class Client {
  /**
   * The constructor
   * @param {Object} params SRP parameters
   * @param {Buffer} saltBuf Salt (s)
   * @param {Buffer} identityBuf User identity (I)
   * @param {Buffer} passwordBuf User password (P)
   * @param {Buffer} secret1Buf Client ephemeral secret key (a)
   */
  constructor(params, saltBuf, identityBuf, passwordBuf, secret1Buf) {
    assertIsBuffer(saltBuf, 'salt (salt)');
    assertIsBuffer(identityBuf, 'identity (I)');
    assertIsBuffer(passwordBuf, 'password (P)');
    assertIsBuffer(secret1Buf, 'secret1');
    this._private = {
      params: params,
      k_num: getk(params),
      x_num: getx(params, saltBuf, identityBuf, passwordBuf),
      a_num: bufferToBigInt(secret1Buf)
    };
    this._private.A_buf = getA(params, this._private.a_num);
  }
  /**
   * Compute the client ephemeral public key (A)
   * @return {Buffer}
   */
  computeA() {
    return this._private.A_buf;
  }
  /**
   * Set the B value obtained from the server
   * @param {Buffer} BBuf Server ephemeral public key (B)
   */
  setB(BBuf) {
    let p = this._private;
    let BNum = bufferToBigInt(BBuf);
    let uNum = getu(p.params, p.A_buf, BBuf);
    let SBuf = clientGetS(p.params, p.k_num, p.x_num, p.a_num, BNum, uNum);
    p.K_buf = getK(p.params, SBuf);
    p.M1_buf = getM1(p.params, p.A_buf, BBuf, SBuf);
    p.M2_buf = getM2(p.params, p.A_buf, p.M1_buf, p.K_buf);
    p.u_num = uNum; // only for tests
    p.S_buf = SBuf; // only for tests
  }
  /**
   * Compute the M1 verification value
   * @return {Buffer}
   */
  computeM1() {
    if (this._private.M1_buf === undefined) {
      throw new Error('incomplete protocol');
    }
    return this._private.M1_buf;
  }
  /**
   * Verify server M2 verification value. Throws if incorrect
   * @param {Buffer} serverM2Buf
   */
  checkM2(serverM2Buf) {
    if (!equal(this._private.M2_buf, serverM2Buf)) {
      throw new Error('server is not authentic');
    }
  }
  /**
   * Compute the shared session key (K)
   * @return {Buffer}
   */
  computeK() {
    if (this._private.K_buf === undefined) {
      throw new Error('incomplete protocol');
    }
    return this._private.K_buf;
  }
}

/** Represents a server */
class Server {
  /**
   * The constructor
   * @param {Object} params SRP parameters
   * @param {Buffer} verifierBuf Verifier from client (v)
   * @param {Buffer} secret2Buf Server ephemeral secret key (b)
   */
  constructor(params, verifierBuf, secret2Buf) {
    assertIsBuffer(verifierBuf, 'verifier');
    assertIsBuffer(secret2Buf, 'secret2');
    this._private = { params: params,
                      k_num: getk(params),
                      b_num: bufferToBigInt(secret2Buf),
                      v_num: bufferToBigInt(verifierBuf) };
    this._private.B_buf = getB(params, this._private.k_num,
                               this._private.v_num, this._private.b_num);
  }
  /**
   * Compute the server ephemeral public key (B)
   * @return {Buffer}
   */
  computeB() {
    return this._private.B_buf;
  }
  /**
   * Set the A value received from the client
   * @param {Buffer} ABuf Client ephemeral public key (A)
   */
  setA(ABuf) {
    let p = this._private;
    let ANum = bufferToBigInt(ABuf);
    let uNum = getu(p.params, ABuf, p.B_buf);
    let SBuf = serverGetS(p.params, p.v_num, ANum, p.b_num, uNum);
    p.K_buf = getK(p.params, SBuf);
    p.M1_buf = getM1(p.params, ABuf, p.B_buf, SBuf);
    p.M2_buf = getM2(p.params, ABuf, p.M1_buf, p.K_buf);
    p.u_num = uNum; // only for tests
    p.S_buf = SBuf; // only for tests
  }
  /**
   * Verify M1 verification value. Throws if incorrect
   * @param {Buffer} clientM1Buf
   * @return {Buffer} Server M2 verification value
   */
  checkM1(clientM1Buf) {
    if (this._private.M1_buf === undefined) {
      throw new Error('incomplete protocol');
    }
    if (!equal(this._private.M1_buf, clientM1Buf)) {
      throw new Error('client did not use the same password');
    }
    return this._private.M2_buf;
  }
  /**
   * Compute the shared session key (K)
   * @return {Buffer}
   */
  computeK() {
    if (this._private.K_buf === undefined) {
      throw new Error('incomplete protocol');
    }
    return this._private.K_buf;
  }
}

module.exports = {
  params: require('./params'),
  genKey,
  computeVerifier,
  Client,
  Server,
  bigIntToBuffer,
  bufferToBigInt
};
