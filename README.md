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
### Testing
```bash
cargo test
```
### TODOs
- [ ] implement deterministic_k
