const vows = require('vows');
const assert = require('assert');
const srp = require('../lib/srp');

/*
 * Vectors from https://wiki.mozilla.org/Identity/AttachedServices/KeyServerProtocol
 *
 * Verify that we are inter-compatible with the SRP implementation used by
 * Mozilla's Identity-Attached Services, aka PiCl (Profile in the Cloud).
 *
 * Note that P is the HKDF-stretched key, computed elsewhere.
 */

 /**
 * Convert hex string with spaces to a Buffer
 * @param {String} s
 * @return {Buffer}
 */
function h(s) {
  return Buffer.from(s.replace(/\s/g, ''), 'hex');
}

const params = srp.params['2048'];

/* inputs_1/expected_1 are the main PiCl test vectors. They were mechanically
 * generated to force certain derived values (stretched-password "P", v, A,
 * B, and S) to begin with a 0x00 byte (to exercise padding bugs).
 */

const inputs1 = {
  I: Buffer.from('andré@example.org', 'utf8'),
  P: h('00f9b71800ab5337 d51177d8fbc682a3 653fa6dae5b87628 eeec43a18af59a9d'),
  salt: h('00f1000000000000000000000000000000000000000000000000000000000179'),
  // a and b are usually random. For testing, we force them to specific values.
  a: h('00f2000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 000000000000d3d7'
      ),
  b: h('00f3000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 000000000000000f'
      )
};

const expected1 = {
  // 'k' encodes the group (N and g), used in SRP-6a
  k: h('05b9e8ef059c6b32 ea59fc1d322d37f0 4aa30bae5aa9003b 8321e21ddb04e300'),
  // 'x' is derived from the salt and password
  // 'v' is the SRP verifier
  x: h('b5200337cc3f3f92 6cdddae0b2d31029 c069936a844aff58 779a545be89d0abe'),
  v: h('00173ffa0263e63c cfd6791b8ee2a40f 048ec94cd95aa8a3 125726f9805e0c82' +
       '83c658dc0b607fbb 25db68e68e93f265 8483049c68af7e82 14c49fde2712a775' +
       'b63e545160d64b00 189a86708c69657d a7a1678eda0cd79f 86b8560ebdb1ffc2' +
       '21db360eab901d64 3a75bf1205070a57 91230ae56466b8c3 c1eb656e19b794f1' +
       'ea0d2a077b3a7553 50208ea0118fec8c 4b2ec344a05c66ae 1449b32609ca7189' +
       '451c259d65bd15b3 4d8729afdb5faff8 af1f3437bbdc0c3d 0b069a8ab2a959c9' +
       '0c5a43d42082c774 90f3afcc10ef5648 625c0605cdaace6c 6fdc9e9a7e6635d6' +
       '19f50af773452247 0502cab26a52a198 f5b00a2798589165 07b0b4e9ef9524d6'),
  // 'B' is the server's public message
  B: h('0022ce5a7b9d8127 7172caa20b0f1efb 4643b3becc535664 73959b07b790d3c3' +
       'f08650d5531c19ad 30ebb67bdb481d1d 9cf61bf272f84398 48fdda58a4e6abc5' +
       'abb2ac496da5098d 5cbf90e29b4b110e 4e2c033c70af7392 5fa37457ee13ea3e' +
       '8fde4ab516dff1c2 ae8e57a6b264fb9d b637eeeae9b5e43d faba9b329d3b8770' +
       'ce89888709e02627 0e474eef822436e6 397562f284778673 a1a7bc12b6883d1c' +
       '21fbc27ffb3dbeb8 5efda279a69a1941 4969113f10451603 065f0a0126666456' +
       '51dde44a52f4d8de 113e2131321df1bf 4369d2585364f9e5 36c39a4dce33221b' +
       'e57d50ddccb4384e 3612bbfd03a268a3 6e4f7e01de651401 e108cc247db50392'),
  // 'A' is the client's public message
  A: h('007da76cb7e77af5 ab61f334dbd5a958 513afcdf0f47ab99 271fc5f7860fe213' +
       '2e5802ca79d2e5c0 64bb80a38ee08771 c98a937696698d87 8d78571568c98a1c' +
       '40cc6e7cb101988a 2f9ba3d65679027d 4d9068cb8aad6ebf f0101bab6d52b5fd' +
       'fa81d2ed48bba119 d4ecdb7f3f478bd2 36d5749f2275e948 4f2d0a9259d05e49' +
       'd78a23dd26c60bfb a04fd346e5146469 a8c3f010a627be81 c58ded1caaef2363' +
       '635a45f97ca0d895 cc92ace1d09a99d6 beb6b0dc0829535c 857a419e834db128' +
       '64cd6ee8a843563b 0240520ff0195735 cd9d316842d5d3f8 ef7209a0bb4b54ad' +
       '7374d73e79be2c39 75632de562c59647 0bb27bad79c3e2fc ddf194e1666cb9fc'),
  // 'u' combines the two public messages
  u: h('b284aa1064e87751 50da6b5e2147b47c a7df505bed94a6f4 bb2ad873332ad732'),
  // 'S' is the shared secret
  S: h('0092aaf0f527906a a5e8601f5d707907 a03137e1b601e04b 5a1deb02a981f4be' +
       '037b39829a27dba5 0f1b27545ff2e287 29c2b79dcbdd32c9 d6b20d340affab91' +
       'a626a8075806c26f e39df91d0ad979f9 b2ee8aad1bc783e7 097407b63bfe58d9' +
       '118b9b0b2a7c5c4c debaf8e9a460f4bf 6247b0da34b760a5 9fac891757ddedca' +
       'f08eed823b090586 c63009b2d740cc9f 5397be89a2c32cdc fe6d6251ce11e44e' +
       '6ecbdd9b6d93f30e 90896d2527564c7e b9ff70aa91acc0ba c1740a11cd184ffb' +
       '989554ab58117c21 96b353d70c356160 100ef5f4c28d19f6 e59ea2508e8e8aac' +
       '6001497c27f362ed bafb25e0f045bfdf 9fb02db9c908f103 40a639fe84c31b27'),
  // 'K' is the shared derived key
  K: h('e68fd0112bfa31dc ffc8e9c96a1cbadb 4c3145978ff35c73 e5bf8d30bbc7499a'),
  // 'M1' is the client's proof that it knows the shared key
  M1: h('27949ec1e0f16256 33436865edb037e2 3eb6bf5cb91873f2 a2729373c2039008')
};

/* inputs_2/expected_2 have leading 0x00 bytes in 'x' and 'u' */
const inputs2 = {
  I: inputs1.I, P: inputs1.P,
  salt: h('00f1000000000000000000000000000000000000000000000000000000000021'),
  a: h('00f2000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 000000000000000d'
      ),
  b: h('00f3000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000001'
      )
};
const expected2 = {
  k: expected1.k,
  x: h('009b2740fb49284d 69cab7c916d449ee d7dcabf41332b8b8 d6928f529bd1a94e'),
  v: h('1cd8b856685672ee 7a5895d897121234 6c17c3472f2696e4 8cdeec5533c06693' +
       '179bc24802b762bc c1e1f8fc8abe607a f2f44aac9172e7dd 0c0110e45cf3b700' +
       'f8db153b67fb0e76 3c6710b8c1c26baf c3b67a50652ee0d7 c6045a5c4b51ff33' +
       'd0135065dca5d6bb 7e150e07414bd572 a954471059c1b466 d0530b0a80bd2d0c' +
       'f1bedf5abfc05c3c f2736ac40b083dcf 62271e834042ecb0 d4882ddd35403c1e' +
       'd24bc4ffe274c5f6 be50ec9b85aa0cfa 26d97e086ec45e06 3c29174d3dbe5490' +
       '1d2a557b7eb46b18 9e17cc721fc098a0 baee2f364a2b409d 49d9372a9625db11' +
       'acfd74ba7f41285f 9c1916d3caaf5238 852694bbde2a13f7 8fcc92d16658dd04'),
  // 'B' is the server's public message
  B: h('485d56912c60d9c1 7af15494d4d50006 45eefa2d41f6bcb5 785e08efad0833a1' +
       '3cb43ee3869e78d4 c2006f42b9741782 a85c90a110cc9a74 4fc2a361d5535966' +
       '2dc5fa4a8d0c7c0e 63e0cf32a28af655 863dd5d66f550557 eacd3e3e64d90f9f' +
       '0d757403c9bbfb08 fcc9a35e1cb421d7 3bb93fa72d5b54ed bfa219d3867255ba' +
       'f96223eef038f085 722b2d14457a5a13 1857a56e66d3011b b5aa7504c4b9a346' +
       '8d0ebdd817d20105 be06ba261ea16740 723faa097f27ddc2 efe34cf8fe59451a' +
       '5bb3987d7161085f b8fc28d5cc28c466 6a3ca486ad0ca83d 1984248ac838574e' +
       '348fb9745ffd1163 f53b5566768a8971 237065d8f6e786be e15107125fb10df1'),
  // 'A' is the client's public message
  A: h('a4b17836b1e7d6f1 5b9901f644bcdf5e 119e7a861c6ee88d 006d8420a5066f22' +
       'd9bf5ccf3d380437 0d29d778ec40afcf c88de7bf22ec03fc 6ab12e0dd95d15e3' +
       'a6249c94393435b0 0d23b1b0439dabed cce1726b2b3cdea2 647c8790d604d87d' +
       '2ac890cfceec0dbe 434f09a9bc11d984 a1e1990f69956ae0 db6068992ad1715f' +
       'b4381516da83637a 73de4211908c8f2f f8b3a09e8535acf3 c2b8de4e9a632f89' +
       '9bfa08cee543b4ea 50d0aca0b3e4fbfa e49ffa2a1ab89a42 8bea928868828501' +
       '2e8af13fcdd444ad da9ad1d0ab4c2069 91919e5391bd2b1a ab8c2d006baceaf8' +
       'cdcb555a6b16e844 5b03e09776eba841 7576dac458afbbd5 2902dfb0282bed79'),
  // 'u' combines the two public messages
  u: h('000e4039be3989ad 088dc17d8ade899a 6409e7e57b3e8518 cee1cbc77e1de243'),
  // 'S' is the shared secret
  S: h('5c7f591d134d19f9 fcedc2b4e3eecd3d 5deadfe7dd42bd59 b1c960516c65ab61' +
       'd007f8134e0a7ca3 0dd409128ef2c780 6784afd95985c8f3 c2d42cd73d26d315' +
       '541645d28aefabc9 980c9a6e5714b178 aa69e5321828ca00 f3d10d742776cfe4' +
       '4b7f5f5c0247addc 0ab0640b49b540ff 9bccea8702e1f996 49448680c00fb484' +
       '51919224d44236ba 1b1e5cf62a5946bd 637f189ff7b8eba9 7b719f18ad9251f0' +
       'a81c157604065388 d7bf4abbf774bfb2 d7b95ed8359b0d70 6ff5df0223992c81' +
       '4aac506e1bace002 d134ed5e41d74f93 a8f410dfe7dc5954 f70b6bafcd0ddfde' +
       'e75f0058f718ec14 f9bbeb29ff966e00 ddfdd2d38a1c7a68 ac455a57b972d528'),
  // 'K' is the shared derived key
  K: h('b637ede0b7a31c46 b2567e855eb8a7f7 a994937deee76479 62afbe35d6929709'),
  // 'M1' is the client's proof that it knows the shared key
  M1: h('67c83797eb1a3987 e2d48d287e3bd772 d25db2b3cd86ea22 c8cf3ae932a1e45b')
};

/* inputs_3/expected_3 have leading 0x00 bytes in 'x' and 'K' */
const inputs3 = {
  I: inputs2.I, P: inputs2.P,
  salt: h('00f1000000000000000000000000000000000000000000000000000000000021'),
  a: h('00f2000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 00000000000001a0'
      ),
  b: inputs2.b
};
const expected3 = {
  k: expected2.k,
  x: expected2.x,
  v: expected2.v,
  B: expected2.B,
  A: h('87b6da9e4162843b 4d5ee60c403ae3e1 e9fdab64883f13ab 4a44b0718a9ea1b6' +
       '1ad17c675e0f0395 b37d58a046a2d5ab 1fb665a9777abe80 8077ccf6fd8ec583' +
       '854eab98deb257d9 10e5bf5cafed4955 2a5cd9927c0979f7 5a21654644000173' +
       'aef6f2244296439c 10b3c61a03e7146e f6c9c9564b1d2bf5 1ece84d115965f9c' +
       'c82006bdb7a124da 3304bcc24c8f3724 522b748fb19a0cb6 b60e355acbf649b5' +
       '40b4972e24077c29 32004a3ad9e59464 2e90a3bfc8de7085 f4a4efc195bd06c9' +
       '6c7011f3c979eaab 469f06465a5b7239 afaee535aedc5bd2 1a220546e0e6b70b' +
       '5b6f54db3fea46d5 7ebc7fe46156d793 c59e6290d3cf9bc2 4316528da34f4640'),
  u: h('865d0efca6cf17d6 f489e129231f1a48 b20c83ec6581d11f 3a2fa48ea93cd305'),
  S: h('0ae26456e1a0dec1 ce162fb2e5bc7300 3c285e17c0b44f03 7ebbc57f8020ceae' +
       '5d10a9e6e44eab2a 6915b582ab5f6e7d 16002ce05e524015 e9bc7c56d5131da4' +
       'd4c4d7c3debaffcd b60e58468bd2c0da 5de95855480190a3 5258c79032001882' +
       '3d836ca91848c5b6 3ca4265c3329eb44 161af9ce64cf4468 ef0eb88a788a0d07' +
       '52a69821278c94ae 7193161b5c638b55 bf732e2a5996ccc5 16335f9f3d00dfa9' +
       '8ac1b1e4971c5417 d34eba1e2a90ed60 a07d1d8be5b9d773 d8f2cb03bfb75994' +
       '249f7734081aa42d 58dd54f8f725b245 175cf7d102e1086c eba4cfe7e49a2d27' +
       'ffd6aef7549d402f bfcea78b4f3398ac 9ab1ee199f70acb6 4d2a17e159ff500d'),
  K: h('00217598a4008956 4b17196bd43422d6 03a0a88a545b61b3 98c42c9cbcc1d1b3'),
  M1: h('96d815ecece1dff4 254cd77517b37b97 65e741c1a57169ab af538e867444ec7f')
};

/* inputs_4/expected_4 have leading 0x00 bytes in 'x' and 'M1' */
const inputs4 = {
  I: inputs2.I, P: inputs2.P,
  salt: h('00f1000000000000000000000000000000000000000000000000000000000021'),
  a: h('00f2000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000000' +
       '0000000000000000 0000000000000000 0000000000000000 0000000000000190'
      ),
  b: inputs2.b
};
const expected4 = {
  k: expected2.k,
  x: expected2.x,
  v: expected2.v,
  B: expected2.B,
  A: h('4aee66beefb92d12 c8e341814809afcd 9ce083c11abcda70 0c03d5379c429cb9' +
       'acbde6bb42a628f3 7a2536c864c40f74 f48a9d9356029a8b fe0e10cb9cf5a8a4' +
       '2e591841f426d281 edf7c9b04112d8ef bf73f9768a4faace ddd351d3e9380bf1' +
       'dcd0590c7ab50a95 bd23e9617e303bea 6f8fbe8a657b6417 4b60cdf5c059ba67' +
       '1b6735324ae0c30a e7f3e361de8f273c af7b2513fa048ed1 0106c66ce460c5cc' +
       '78544c790f5ffcce 378b79d5f02ec361 3a457b03fa0cc39c 80d6fdd645e24f65' +
       'c690f9478d5b331d c00eef68670edbf3 629fd1a6c85267d2 cbb90f1670e7ba09' +
       'cf2b5a9b00be8e11 f33e47a1c1f04eca f35bccb61af1116e 4d0f9d475017bad2'),
  u: h('d0913eb75b61e15a 87756ffa04d4f967 e492bd0b330a2b11 fe8976aada2bb1ee'),
  S: h('7ba3ce4a3d236b95 3c2d0fee42195c85 081664a44f55b82d a3abf66ac68bdbd7' +
       'ad82d5ad95090782 5241fb706de8fc58 0a29e4579fbbedf3 0bec0138b3f76e06' +
       'f9c86b16ad673890 3003ce8c86cb14ea 552db904a20970a9 7d9258a768087d30' +
       '47a6e77520d32968 de3f64e94cd8c463 92c13e194194745c 8e53a9bb15a79473' +
       '2a645068970fcdd9 a7c98b4aec19773a 5196802c2e932e71 d3a4a340e6f4fe16' +
       '9e7ccc687f7246fe 20edeaf88d1125da c812751317f7213c d84f9efe2313d701' +
       'd4a9bf0242bfe703 26fc19b68c90e83b 59b5cc21886ab602 f8bfa16fb50c3147' +
       '9aad5e31698abf67 863b7ca6b6ac25a7 09a24d8f94c80bbf 691e38c81beb3c72'),
  K: h('bd2a167a93b8496e 68c7e24b37956924 672eb8249d25c281 13984912d5cf27a6'),
  M1: h('00cef66a047d506c bf941c236218e583 5343534ae08cf0cd 0fb7980bed242e05')
};

/**
 * Assert equality of two buffers
 * @param {Buffer} a
 * @param {Buffer} b
 * @param {String} msg Message for thrown error
 */
function hexequal(a, b, msg) {
  assert(a.equals(b), msg);
}

/**
 * Assert equality of two BigInts
 * @param {BigInt} a
 * @param {BigInt} b
 * @param {String} msg Message for thrown error
 */
function numequal(a, b, msg) {
  assert(a === b, msg);
}

/**
 * Check library output against expected output
 * @param {Object} params SRP parameters
 * @param {Object} inputs
 * @param {Object} expected
 */
function checkVectors(params, inputs, expected) {
  hexequal(inputs.I, Buffer.from('616e6472c3a9406578616d706c652e6f7267', 'hex'), 'I');
  hexequal(srp.computeVerifier(params, inputs.salt, inputs.I, inputs.P), expected.v, 'v');

  let client = new srp.Client(params, inputs.salt, inputs.I, inputs.P, inputs.a);
  let server = new srp.Server(params, expected.v, inputs.b);

  numequal(client._private.k_num, srp.bufferToBigInt(expected.k), 'k');
  numequal(client._private.x_num, srp.bufferToBigInt(expected.x), 'x');
  hexequal(client.computeA(), expected.A);
  hexequal(server.computeB(), expected.B);

  assert.throws(() => client.computeM1(), /incomplete protocol/);
  assert.throws(() => client.computeK(), /incomplete protocol/);
  assert.throws(() => server.checkM1(expected.M1), /incomplete protocol/);
  assert.throws(() => server.computeK(), /incomplete protocol/);

  client.setB(expected.B);
  numequal(client._private.u_num, srp.bufferToBigInt(expected.u));
  hexequal(client._private.S_buf, expected.S);
  hexequal(client.computeM1(), expected.M1);
  hexequal(client.computeK(), expected.K);

  server.setA(expected.A);
  numequal(server._private.u_num, srp.bufferToBigInt(expected.u));
  hexequal(server._private.S_buf, expected.S);
  assert.throws(() => server.checkM1(Buffer.from('notM1')),
    /client did not use the same password/);
  server.checkM1(expected.M1); // happy, not throwy
  hexequal(server.computeK(), expected.K);
}

vows.describe('picl vectors')
.addBatch({
    'vectors 1': () => checkVectors(params, inputs1, expected1),
    'vectors 2': () => checkVectors(params, inputs2, expected2),
    'vectors 3': () => checkVectors(params, inputs3, expected3),
    'vectors 4': () => checkVectors(params, inputs4, expected4)
})
.export(module);
