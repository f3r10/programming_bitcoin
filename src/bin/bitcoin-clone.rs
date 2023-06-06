use std::io::Cursor;

use anyhow::{bail, Context, Result};
use bitcoin_clone::{
    finite_field::FiniteField,
    merkle_tree::MerkleTree,
    op,
    private_key::PrivateKey,
    s256_field::S256Field,
    s256_point::S256Point,
    script::{Command, Script},
    signature::Signature,
    utils, PointWrapper, G, N,
};
use num_bigint::BigInt;

fn main() -> Result<()> {
    println!("(17, 64) over F_103 -> {}", check(17, 64, 103));
    println!("(192, 105) over F_223 -> {}", check(192, 105, 223));
    println!("(17, 56) over F_223 -> {}", check(17, 56, 223));
    println!("(200, 119) over F_223 -> {}", check(200, 119, 223));
    println!("(1, 193) over F_223 -> {}", check(1, 193, 223));
    println!("(42, 99) over F_223 -> {}", check(42, 99, 223));
    let prime = 223;
    let a = FiniteField::new(0, prime)?;
    let b = FiniteField::new(7, prime)?;
    let x1 = FiniteField::new(170, prime)?;
    let y1 = FiniteField::new(142, prime)?;
    let x2 = FiniteField::new(60, prime)?;
    let y2 = FiniteField::new(139, prime)?;
    let p1 = PointWrapper::new(x1, y1, a.clone(), b.clone());
    let p2 = PointWrapper::new(x2, y2, a.clone(), b.clone());
    println!("{}", p1 + p2);
    println!("=====exercise 4=======");
    let p3 = PointWrapper::new(
        FiniteField::new(192, prime)?,
        FiniteField::new(105, prime)?,
        a.clone(),
        b.clone(),
    );
    println!("{} * {} = {}", 2, p3.clone(), p3.clone() + p3);
    let p4 = PointWrapper::new(
        FiniteField::new(143, prime)?,
        FiniteField::new(98, prime)?,
        a.clone(),
        b.clone(),
    );
    println!("{}", p4.clone() + p4);
    let p5 = PointWrapper::new(
        FiniteField::new(47, prime)?,
        FiniteField::new(71, prime)?,
        a.clone(),
        b.clone(),
    );
    println!("{} * {} = {}", 2, p5.clone(), p5.clone() + p5.clone());
    println!(
        "{} * {} = {}",
        4,
        p5.clone(),
        p5.clone() + p5.clone() + p5.clone() + p5.clone()
    );
    println!(
        "{} * {} = {}",
        8,
        p5.clone(),
        p5.clone()
            + p5.clone()
            + p5.clone()
            + p5.clone()
            + p5.clone()
            + p5.clone()
            + p5.clone()
            + p5.clone()
    );
    println!(
        "{} * {} = {}",
        21,
        p5.clone(),
        p5.clone()
            + p5.clone()
            + p5.clone()
            + p5.clone()
            + p5.clone()
            + p5.clone()
            + p5.clone()
            + p5.clone()
            + p5.clone()
            + p5.clone()
            + p5.clone()
            + p5.clone()
            + p5.clone()
            + p5.clone()
            + p5.clone()
            + p5.clone()
            + p5.clone()
            + p5.clone()
            + p5.clone()
            + p5.clone()
            + p5.clone()
    );
    println!("=====exercise 5=======");
    let p5 = PointWrapper::new(
        FiniteField::new(15, prime)?,
        FiniteField::new(86, prime)?,
        a.clone(),
        b.clone(),
    );
    let mut count = 0;
    let inf = PointWrapper::new_inf();
    let mut inc = PointWrapper::new_inf();
    loop {
        inc = inc + p5.clone();
        count += 1;
        if inc == inf {
            break;
        }
    }
    println!("The order of the group generate by (15, 86) is {}", count);
    let p6 = count * p5.clone();
    println!("{} * {} = {}", count, p5, p6);
    println!("with big ints {}", BigInt::from(count) * p5.clone());

    println!("=====exercise 6=======");
    let z: BigInt = BigInt::parse_bytes(
        b"bc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423",
        16,
    )
    .context("unable to parse hex to bigint")?;
    let r: BigInt = BigInt::parse_bytes(
        b"37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6",
        16,
    )
    .context("unable to parse hex to bigint")?;
    let s: BigInt = BigInt::parse_bytes(
        b"8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec",
        16,
    )
    .context("unable to parse hex to bigint")?;
    let px: BigInt = BigInt::parse_bytes(
        b"04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574",
        16,
    )
    .context("unable to parse hex to bigint")?;
    let py: BigInt = BigInt::parse_bytes(
        b"82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4",
        16,
    )
    .context("unable to parse hex to bigint")?;
    let point = S256Point::new(S256Field::new(px)?, S256Field::new(py)?)?;
    println!("{}", hex::encode(point.clone().sec(Some(false))?));
    let n = match N.as_ref() {
        Ok(it) => it,
        Err(_) => bail!("unable to get N"),
    };
    let g = match G.as_ref() {
        Ok(it) => it,
        Err(_) => bail!("unable to get G"),
    };
    let n_2: BigInt = n - 2;
    let s_inv = s.modpow(&n_2, n);
    let u_1: BigInt = z * s_inv.clone();
    let v_1: BigInt = r.clone() * s_inv.clone();
    let u = u_1.modpow(&BigInt::from(1), n);
    let v = v_1.modpow(&BigInt::from(1), n);
    match (u * g) + (v * &point) {
        PointWrapper::Inf => println!("this is invalid"),
        PointWrapper::Point {
            x,
            y: _,
            a: _,
            b: _,
        } => println!("r==n: {}", x.num == r.clone()),
    }
    let e = PrivateKey::generate_simple_secret(BigInt::from(5000));
    let p = PrivateKey::new(&e)?;
    println!("{}", hex::encode(p.point.clone().sec(Some(false))?));
    println!("{}", p.point.clone().address(Some(true), Some(false))?);
    let p_bytes = [
        4, 255, 229, 88, 227, 136, 133, 47, 1, 32, 228, 106, 242, 209, 179, 112, 248, 88, 84, 168,
        235, 8, 65, 129, 30, 206, 14, 62, 3, 210, 130, 213, 124, 49, 93, 199, 40, 144, 164, 241,
        10, 20, 129, 192, 49, 176, 59, 53, 27, 13, 199, 153, 1, 202, 24, 160, 12, 240, 9, 219, 219,
        21, 122, 29, 16,
    ];
    let parsed = S256Point::parse(&p_bytes);
    println!("before: {:?}", p.point);
    println!("parsed: {:?}", parsed);
    // example tx https://live.blockcypher.com/btc-testnet/address/mzzLk9MmXzmjCBLgjoeNDxrbdrt511t5Gm/
    let passphrase = "f3r10@programmingblockchain.com my secret";
    let priva = PrivateKey::new(&PrivateKey::generate_secret(passphrase))?;
    println!("{}", priva.point.address(Some(true), Some(true))?);

    let script_pub_key = Script::new(Some(vec![
        Command::Operation(op::parse_raw_op_codes(0x76)),
        Command::Operation(op::parse_raw_op_codes(0x76)),
        Command::Operation(op::parse_raw_op_codes(0x95)),
        Command::Operation(op::parse_raw_op_codes(0x93)),
        Command::Operation(op::parse_raw_op_codes(0x56)),
        Command::Operation(op::parse_raw_op_codes(0x87)),
    ]));

    let script_sig = Script::new(Some(vec![Command::Operation(op::parse_raw_op_codes(0x52))]));
    let combined_script = script_sig + script_pub_key;
    println!(
        "eval script: {}",
        combined_script.evaluate(Signature::signature_hash(""))?
    );
    println!("=====exercise chapter6:4=======");
    let script_pub_key = Script::new(Some(vec![
        Command::Operation(op::parse_raw_op_codes(0x6e)),
        Command::Operation(op::parse_raw_op_codes(0x87)),
        Command::Operation(op::parse_raw_op_codes(0x91)),
        Command::Operation(op::parse_raw_op_codes(0x69)),
        Command::Operation(op::parse_raw_op_codes(0xa7)),
        Command::Operation(op::parse_raw_op_codes(0x7c)),
        Command::Operation(op::parse_raw_op_codes(0xa7)),
        Command::Operation(op::parse_raw_op_codes(0x87)),
    ]));
    let script_sig = Script::new(Some(vec![
        Command::Element("this is sentence a".as_bytes().to_vec()),
        Command::Element("this is sentence b".as_bytes().to_vec()),
    ]));
    let combined_script = script_sig + script_pub_key;
    println!(
        "checking collision: {}",
        combined_script.evaluate(Signature::signature_hash(""))?
    );

    let modified_tx = hex::decode("0100000001868278ed6ddfb6c1ed3ad5f8181eb0c7a385aa0836f01d5e4789e6bd304d87221a000000475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152aeffffffff04d3b11400000000001976a914904a49878c0adfc3aa05de7afad2cc15f483a56a88ac7f400900000000001976a914418327e3f3dda4cf5b9089325a4b95abdfa0334088ac722c0c00000000001976a914ba35042cfe9fc66fd35ac2224eebdafd1028ad2788acdc4ace020000000017a91474d691da1574e6b3c192ecfb52cc8984ee7b6c56870000000001000000")?;
    let h256 = utils::hash256(&modified_tx);
    let z = Signature::signature_hash_from_vec(h256);
    let sec1 = hex::decode("022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb70")?;
    let der1 = hex::decode("3045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4ee942a89937")?;
    let mut der1_cursor = Cursor::new(der1);
    let point1 = S256Point::parse(&sec1)?;
    let sig1 = Signature::parse(&mut der1_cursor)?;
    println!("{}", point1.verify(&z, sig1)?);
    let sec2 = hex::decode("03b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb71")?;
    let der2 = hex::decode("3045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e754022")?;
    let mut der2_cursor = Cursor::new(der2);
    let point2 = S256Point::parse(&sec2)?;
    let sig2 = Signature::parse(&mut der2_cursor)?;
    println!("{}", point2.verify(&z, sig2)?);

    println!("=====exercise chapter11:5=======");
    let total = 16_f32;
    let max_depth = total.log2().ceil() as i32;
    let mut merkle_tree: Vec<Vec<Vec<u8>>> = vec![];
    for depth in 0..(max_depth + 1) {
        let num_items = (total / 2.0_f32.powi(max_depth - depth)).ceil() as usize;
        let level_hashes = vec![vec![0_u8]; num_items.try_into()?];
        merkle_tree.push(level_hashes);
    }
    for level in &merkle_tree {
        println!("{:?}", level)
    }

    let hex_hashes = vec![
        "9745f7173ef14ee4155722d1cbf13304339fd00d900b759c6f9d58579b5765fb",
        "5573c8ede34936c29cdfdfe743f7f5fdfbd4f54ba0705259e62f39917065cb9b",
        "82a02ecbb6623b4274dfcab82b336dc017a27136e08521091e443e62582e8f05",
        "507ccae5ed9b340363a0e6d765af148be9cb1c8766ccc922f83e4ae681658308",
        "a7a4aec28e7162e1e9ef33dfa30f0bc0526e6cf4b11a576f6c5de58593898330",
        "bb6267664bd833fd9fc82582853ab144fece26b7a8a5bf328f8a059445b59add",
        "ea6d7ac1ee77fbacee58fc717b990c4fcccf1b19af43103c090f601677fd8836",
        "457743861de496c429912558a106b810b0507975a49773228aa788df40730d41",
        "7688029288efc9e9a0011c960a6ed9e5466581abf3e3a6c26ee317461add619a",
        "b1ae7f15836cb2286cdd4e2c37bf9bb7da0a2846d06867a429f654b2e7f383c9",
        "9b74f89fa3f93e71ff2c241f32945d877281a6a50a6bf94adac002980aafe5ab",
        "b3a92b5b255019bdaf754875633c2de9fec2ab03e6b8ce669d07cb5b18804638",
        "b5c0b915312b9bdaedd2b86aa2d0f8feffc73a2d37668fd9010179261e25e263",
        "c9d52c5cb1e557b92c84c52e7c4bfbce859408bedffc8a5560fd6e35e10b8800",
        "c555bc5fc3bc096df0a0c9532f07640bfb76bfe4fc1ace214b8b228a1297a4c2",
        "f9dbfafc3af3400954975da24eb325e326960a25b87fffe23eef3e7ed2fb610e",
    ];
    let tx_hashes: Vec<Vec<u8>> = hex_hashes
        .iter()
        .map(|tx| hex::decode(tx).unwrap())
        .collect();
    let mut tree = MerkleTree::new(hex_hashes.len() as f32)?;
    tree.nodes[4] = tx_hashes.clone();
    tree.nodes[3] = utils::merkle_parent_level(tree.nodes[4].clone())?;
    tree.nodes[2] = utils::merkle_parent_level(tree.nodes[3].clone())?;
    tree.nodes[1] = utils::merkle_parent_level(tree.nodes[2].clone())?;
    tree.nodes[0] = utils::merkle_parent_level(tree.nodes[1].clone())?;
    println!("{}", tree);

    let mut tree2 = MerkleTree::new(hex_hashes.len() as f32)?;
    tree2.nodes[4] = tx_hashes;
    while tree2.root().len() == 1 {
        if tree2.is_leaf() {
            tree2.up();
        } else {
            let left_hash = tree2.get_left_node();
            let right_hash = tree2.get_right_node();
            if left_hash.len() == 1 {
                tree2.left()
            } else if right_hash.len() == 1 {
                tree2.right()
            } else {
                tree2.set_current_node(utils::merkle_parent(left_hash, right_hash));
                tree2.up();
            }
        }
    }
    println!("{}", tree2);
    Ok(())
}

// y^2 = x^3 + y
fn check(x: i64, y: i64, f: i64) -> bool {
    let y_2 = (((y.pow(2)) % f) + f) % f;
    // println!("{}", y_2);
    let right = (((x.pow(3) + 7) % f) + f) % f;
    // println!("{}", right);
    y_2 == right
}
