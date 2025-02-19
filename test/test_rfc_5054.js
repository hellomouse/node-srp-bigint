const vows = require('vows');
const assert = require('assert');
const srp = require('../lib/srp');
const params = srp.params['1024'];

/*
 * http://tools.ietf.org/html/rfc5054#appendix-B
 */

/**
 * Strip out spaces
 * @param {String} s
 * @return {String}
 */
function h(s) {
  return s.replace(/\s/g, '');
}

const I = Buffer.from('alice');
const P = Buffer.from('password123');
const s = Buffer.from('beb25379d1a8581eb5a727673a2441ee', 'hex');
const expectedK = '7556aa045aef2cdd07abaf0f665c3e818913186f';
const expectedX = '94b7555aabe9127cc58ccf4993db6cf84d16c124';
const expectedV = h('7e273de8 696ffc4f 4e337d05 b4b375be b0dde156 9e8fa00a 9886d812' +
                    '9bada1f1 822223ca 1a605b53 0e379ba4 729fdc59 f105b478 7e5186f5' +
                    'c671085a 1447b52a 48cf1970 b4fb6f84 00bbf4ce bfbb1681 52e08ab5' +
                    'ea53d15c 1aff87b2 b9da6e04 e058ad51 cc72bfc9 033b564e 26480d78' +
                    'e955a5e2 9e7ab245 db2be315 e2099afb');

const a = Buffer.from('60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393', 'hex');
const b = Buffer.from('e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20', 'hex');
const expectedA = h('61d5e490 f6f1b795 47b0704c 436f523d d0e560f0 c64115bb 72557ec4' +
                    '4352e890 3211c046 92272d8b 2d1a5358 a2cf1b6e 0bfcf99f 921530ec' +
                    '8e393561 79eae45e 42ba92ae aced8251 71e1e8b9 af6d9c03 e1327f44' +
                    'be087ef0 6530e69f 66615261 eef54073 ca11cf58 58f0edfd fe15efea' +
                    'b349ef5d 76988a36 72fac47b 0769447b');
const expectedB = h('bd0c6151 2c692c0c b6d041fa 01bb152d 4916a1e7 7af46ae1 05393011' +
                    'baf38964 dc46a067 0dd125b9 5a981652 236f99d9 b681cbf8 7837ec99' +
                    '6c6da044 53728610 d0c6ddb5 8b318885 d7d82c7f 8deb75ce 7bd4fbaa' +
                    '37089e6f 9c6059f3 88838e7a 00030b33 1eb76840 910440b1 b27aaeae' +
                    'eb4012b7 d7665238 a8e3fb00 4b117b58');

const expectedU = 'ce38b9593487da98554ed47d70a7ae5f462ef019';
const expectedS = h('b0dc82ba bcf30674 ae450c02 87745e79 90a3381f 63b387aa f271a10d' +
                    '233861e3 59b48220 f7c4693c 9ae12b0a 6f67809f 0876e2d0 13800d6c' +
                    '41bb59b6 d5979b5c 00a172b4 a2a5903a 0bdcaf8a 709585eb 2afafa8f' +
                    '3499b200 210dcc1f 10eb3394 3cd67fc8 8a2f39a4 be5bec4e c0a3212d' +
                    'c346d7e4 74b29ede 8a469ffe ca686e5a');

/**
 * Return hex representation of the given BigInt
 * @param {BigInt} num
 * @return {String}
 */
function asHex(num) {
  return num.toString(16);
}

vows.describe('RFC 5054')

.addBatch({
  'Test vectors': {
    'topic': function() {
      return srp.computeVerifier(params, s, I, P);
    },

    'x': function() {
      let client = new srp.Client(params, s, I, P, a);
      assert.equal(asHex(client._private.x_num), expectedX);
    },

    'V': function(v) {
      assert.equal(v.toString('hex'), expectedV);
    },

    'k': function() {
      let client = new srp.Client(params, s, I, P, a);
      assert.equal(asHex(client._private.k_num), expectedK);
    },

    'A': function() {
      let client = new srp.Client(params, s, I, P, a);
      assert.equal(client.computeA().toString('hex'), expectedA);
    },

    'B': function(v) {
      let server = new srp.Server(params, v, b);
      assert.equal(server.computeB().toString('hex'), expectedB);
    },

    'u': function() {
      let client = new srp.Client(params, s, I, P, a);
      client.setB(Buffer.from(expectedB, 'hex'));
      assert.equal(asHex(client._private.u_num), expectedU);
    },

    'S client': function() {
      let client = new srp.Client(params, s, I, P, a);
      client.setB(Buffer.from(expectedB, 'hex'));
      assert.equal(client._private.S_buf.toString('hex'), expectedS);
    },

    'S server': function(v) {
      let server = new srp.Server(params, v, b);
      server.setA(Buffer.from(expectedA, 'hex'));
      assert.equal(server._private.S_buf.toString('hex'), expectedS);
    }
  }
})

.export(module);
