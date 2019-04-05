var wally = require('./wally');

wally.wally_sha256(Buffer.from('test', 'ascii')).then(function (uint8Array) {
  console.log(Buffer.from(uint8Array).toString('hex'))
});
wally.wally_base58_from_bytes(Buffer.from('xyz', 'ascii'), 0).then(function (s) {
  console.log(s);
  wally.wally_base58_to_bytes(s, 0).then(function (bytes_) {
    console.log(Buffer.from(bytes_).toString('ascii'));
  });
});
var zeroes = [];
for (var i = 0; i < 16; ++i) {
  zeroes.push(0);
}
wally.bip32_key_from_seed(Buffer.from(zeroes), 0x0488ADE4, 0).then(function (s) {
  console.log('====> ', Buffer.from(s));
  wally.wally_base58_from_bytes(s, 1).then(function (s) {
    console.log('privkey:', s);
  });
  wally.bip32_privkey_from_parent(s, 1, 0).then(function (pub) {
    wally.wally_base58_from_bytes(pub, 1).then(function (s) {
      console.log('privkey:', s);
    });
  });
  wally.bip32_pubkey_from_parent(s, 1, 0).then(function (pub) {
    wally.wally_base58_from_bytes(pub, 1).then(function (s) {
      console.log('pubkey:', s);
    });
  });
});

const VERSION_PREFIX_LIQUID = 'eb';
const VERSION_PREFIX_LIQUID_PRIV = 'ef';
const masterxpriv = 'tprv8ZgxMBicQKsPcuogWvhWjtavfxAeQRvemzQALexrMaMLrtojqA2bUMTkviPBH7YqiPeZ5uTobozpbfodRyHt7ZYkPxncAKk7mSGat5tWQRC'
wally.wally_base58_to_bytes(masterxpriv, 1).then(function (s) {
  console.log("master ext priv m/: ", Buffer.from(s))
  return wally.bip32_privkey_from_parent(s, 0x80000000, 0)
}).then((xpriv) => {
  console.log("extended xpriv m/0': ", Buffer.from(xpriv).slice(45, 78))
  return wally.bip32_privkey_from_parent(xpriv, 0x80000000, 0)
}).then((xpriv) => {
  console.log("extended xpriv m/0'/0': ", Buffer.from(xpriv).slice(45, 78))
  return wally.bip32_privkey_from_parent(xpriv, 0x80000046, 0)
}).then((xpriv) => {
  console.log("extended xpriv m/0'/0'/0': ", Buffer.from(xpriv).slice(45, 78))
  let privkey = Buffer.from(xpriv).slice(46, 78)

  //  return wally.wally_ec_public_key_from_private_key(privkey)
  return privkey
  // }).then((pubkey) => {
  //   console.log("pubkey m/0'/0'/0': ", Buffer.from(pubkey))
  //   return wally.wally_hash160(pubkey)

}).then((pubkey_hash) => {

  //  return wally.wally_base58_from_bytes(Buffer.concat([Buffer.from(VERSION_PREFIX_LIQUID, 'hex'), Buffer.from(pubkey_hash)]), 1)
  return wally.wally_base58_from_bytes(Buffer.concat([Buffer.from(VERSION_PREFIX_LIQUID_PRIV, 'hex'), Buffer.from('5a63dd9ce18f0ee108202e82c4cff3cf1b960e7df40d7aded8cc3a50fbe4c0d0', 'hex')]), 1)

}).then((addr) => {
  console.log("pubkey m/0'/0'/0': address: ", addr);
});


const xpub = 'xpub6ANLQrVhxpdoWTczon1R9an4GBqYEdMhUTcWynJSnKMw5w8VV4YWEqxwpyqH3MA3t6heJEAeeXZgdkZXVA1sYKD1xsPjwmB1FErM8Z5A6Hn';
const tx = '0200000000012e4c6db69a4b99dee5a17a430fb57f84d45a6bb36abd0d1008bae22727a5c9e00000000000ffffffff0201f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000025408d6c0001976a9147f06a3ce008dbee41566aeb7cad70472e097cd9888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000000030d40000000000000';
const index = 0;
const script = '76a914275f1c4afe86b62e0c8b4dfa7ee4dc74367206b488ac';

// create address
wally.wally_base58_to_bytes(xpub, 1)
  .then((xpub_bytes) => {
    var pubkey = Buffer.from(xpub_bytes).slice(45, 78);

    return wally.wally_hash160(pubkey)

  }).then((pubkey_hash) => {

    return wally.wally_base58_from_bytes(Buffer.concat([Buffer.from(VERSION_PREFIX_LIQUID, 'hex'), Buffer.from(pubkey_hash)]), 1)

  }).then((addr) => {
    console.log('address: ', addr);
  });

// generate hash signed by a private key
wally.wally_tx_get_elements_signature_hash(
  tx,
  3,
  index,
  Buffer.from(script, 'hex'),
  null,
  1,
  0
).then((tx_hash) => {
  console.log('tx_hash: ', Buffer.from(tx_hash).toString('hex'));
})

const signature = '9c201fca946afc6ca1a865b2398b82f03de52e0da71bc24ad8a5996effe5f62f349b324da19f84a18e59f533cc950377396541f661920cbb9454ebdc468d5751';
// build a signed transaction
var _xpub = wally.wally_base58_to_bytes(xpub, 1)
var _der = wally.wally_ec_sig_to_der(Buffer.from(signature, 'hex'))
Promise.all([_xpub, _der])
  .then((results) => {
    var sig_der = Buffer.from(results[1]);
    var sighash_byte = Buffer.from([0x01]);
    var _signature = Buffer.concat([sig_der, sighash_byte]);
    var sig_len = Buffer.from(_signature.byteLength.toString(16), 'hex');
    var pub_buf = Buffer.from(results[0]).slice(45, 78);
    var pub_len = Buffer.from(pub_buf.byteLength.toString(16), 'hex');

    var scriptsig = Buffer.concat([
      sig_len,
      _signature,
      pub_len,
      pub_buf
    ]);

    var tx_length = Buffer.from(tx, 'hex').byteLength;
    var script_len = scriptsig.byteLength;

    return wally.wally_tx_set_input_script(
      tx,
      3,
      index,
      scriptsig,
      tx_length + script_len
    )

  }).then((signed_tx) => {
    console.log('tx: ', Buffer.from(signed_tx).toString('hex'));
  });
