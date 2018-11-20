var wally = require('./wally');

wally.wally_tx_from_hex('02000000000001010b000000000000000000000000000000000000000000000000000000000000000100000000053ec600001976a914e008c86ad0b8662fa2b5bd7c68f418213d1873b988ac00000000', 3)
.then((result) => {
  console.log(result);
});

wally.wally_sha256(Buffer.from('test', 'ascii')).then(function(uint8Array) {
  console.log(Buffer.from(uint8Array).toString('hex'))
});
wally.wally_base58_from_bytes(Buffer.from('xyz', 'ascii'), 0).then(function(s) {
  console.log(s);
  wally.wally_base58_to_bytes(s, 0).then(function(bytes_) {
    console.log(Buffer.from(bytes_).toString('ascii'));
  });
});
var zeroes = [];
for (var i = 0; i < 16; ++i) {
    zeroes.push(0);
}
wally.bip32_key_from_seed(Buffer.from(zeroes), 0x0488ADE4, 0).then(function(s) {
  wally.wally_base58_from_bytes(s, 1).then(function (s) {
    console.log('privkey:', s);
  });
  wally.bip32_pubkey_from_parent(s, 1, 0).then(function (pub) {
    wally.wally_base58_from_bytes(pub, 1).then(function (s) {
      console.log('pubkey:', s);
    });
  });
});
