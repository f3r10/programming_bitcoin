# programming_bitcoin
## 🌅 Getting Started
### Dependencies
**Required**
- [rustc 1.69.0-nightly](https://www.rust-lang.org/tools/install)
  - to change to nighhtly version only on the current folder ```rustup override set nightly```
- Cargo
## 🚀 Usage
### How to create public/private keys
```rust
  let secret = BigInt::from(12345); // this should be a really large number
  let p = PrivateKey::new(e);
```
### How to create a signature / verification 
```rust
  let passphrase = "Programming Bitcoin!";
  let p = PrivateKey::new(PrivateKey::generate_secret(passphrase));
  let signature_hash = Signature::signature_hash(passphrase);
  let sig = p.sign(&signature_hash, None);
  p.point.verify(&signature_hash, sig)
```
### How to create a private key and get the a valid compressed address for the testnet
```rust
  let passphrase = "f3r10@programmingblockchain.com my secret";
  let p = PrivateKey::new(PrivateKey::generate_secret(passphrase));
  priva.point.address(Some(true), Some(true))  // mzzLk9MmXzmjCBLgjoeNDxrbdrt511t5Gm
```
- If the generated address is valid, it is possible to send some testnet coins to it.
- It is possible to use this service to test if the address is valid and send some testnet coins: https://testnet-faucet.com/btc-testnet/
- An example using the previous generated address: https://live.blockcypher.com/btc-testnet/address/mzzLk9MmXzmjCBLgjoeNDxrbdrt511t5Gm/

### How to create script_pubkey, script_sig and evaluate the combined script
```rust
  let z = Signature::signature_hash_from_hex(
      "7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d",
  );
  let sec = "04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34";
  let sec_encode = hex::decode(sec).unwrap();
  let sig = "3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6";
  let sig_encode = hex::decode(sig).unwrap();
  let cmd = vec![
      Command::Element(sec_encode),
      Command::Operation(op::parse_raw_op_codes(0xac)), //OpChecksig
  ];
  let script_pubkey = Script::new(Some(cmd));
  let script_sig = Script::new(Some(vec![Command::Element(sig_encode)]));
  let combined_script = script_sig + script_pubkey;
  assert!(combined_script.evaluate(z))
```
### How to create a raw TX
#### The first step is to define one or more inputs from where the coins have to come. It is also necessary to define which index has to be used:
```rust
  let prev_tx_faucet =
      hex::decode("177546b0d70663917f9dbe3dc6ddf05289d0a43d6cd721bf79f62581bc75a1cc")
          .unwrap();
  let prev_tx_faucet_index = BigInt::from(0);
  let prev_tx_ex4 =
      hex::decode("3fd155536987271e0f94358e9fa2e135bb620981ea8dbe8e60645d0daa2ffe3b")
          .unwrap();
  let prev_tx_ex4_index = BigInt::from(1);
  let mut tx_ins: Vec<TxIn> = Vec::new();
  tx_ins.push(TxIn::new(prev_tx_faucet, prev_tx_faucet_index, None, None));
  tx_ins.push(TxIn::new(prev_tx_ex4, prev_tx_ex4_index, None, None));
```
#### Then it is necessary to define the output or the outputs where we want to send the coins, and the ammount to transfer.
```rust
  let target_address = "mzzLk9MmXzmjCBLgjoeNDxrbdrt511t5Gm";
  let target_amount = 0.01728903;
  let mut tx_outs: Vec<TxOut> = Vec::new();
  let h160 = utils::decode_base58(target_address);
  let script_pubkey = utils::p2pkh_script(h160);
  let target_satoshis = BigInt::from((target_amount * 100_000_000_f64) as u64);
  tx_outs.push(TxOut::new(target_satoshis, script_pubkey));
```
#### After the input and output lists are ready, we can create a TX struct almost ready to be broadcasted.
```rust
  let mut tx_obj = Tx::new(BigInt::from(1), tx_ins, tx_outs, BigInt::from(0), true);
```
#### The last step is to sign each input. For this step is necessary to use the pair (private key) of the public key defined on the inputs (the outputs of previous TX) in which we were the recipients.
```rust
let secret = "f3r10@programmingblockchain.com my secret";
let priva = PrivateKey::new(&PrivateKey::generate_secret(secret));
assert!(tx_obj.sign_input(0, priva.clone()));
assert!(tx_obj.sign_input(1, priva.clone()));
```
#### Finally, we can get the serialized TX ready for broadcasting.
```rust
  hex::encode(tx_obj.serialize())
```
#### Some useful links:
  - [An online TX decode](https://live.blockcypher.com/btc/decodetx/)
  - [For broadcast the TX](https://tbtc.bitaps.com/broadcast)
### Testing
```bash
cargo test
```
### TODOs
- [x] implement deterministic_k
- [ ] using this simple ervice for checking the fee: https://blockstream.info/api/tx/d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81/hex
