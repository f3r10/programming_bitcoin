use chapter3::{finite_field::FiniteField, PointWrapper, S256Point, S256Field, N, G};
use num_bigint::BigInt;

fn main() {
    println!("(17, 64) over F_103 -> {}", check(17, 64, 103));
    println!("(192, 105) over F_223 -> {}", check(192, 105, 223));
    println!("(17, 56) over F_223 -> {}", check(17, 56, 223));
    println!("(200, 119) over F_223 -> {}", check(200, 119, 223));
    println!("(1, 193) over F_223 -> {}", check(1, 193, 223));
    println!("(42, 99) over F_223 -> {}", check(42, 99, 223));
    let prime = 223;
    let a = FiniteField::new(0, prime);
    let b = FiniteField::new(7, prime);
    let x1 = FiniteField::new(170, prime);
    let y1 = FiniteField::new(142, prime);
    let x2 = FiniteField::new(60, prime);
    let y2 = FiniteField::new(139, prime);
    let p1 = PointWrapper::new(x1, y1, a.clone(), b.clone());
    let p2 = PointWrapper::new(x2, y2, a.clone(), b.clone());
    println!("{}", p1 + p2);
    println!("=====exercise 4=======");
    let p3 = PointWrapper::new(
        FiniteField::new(192, prime),
        FiniteField::new(105, prime),
        a.clone(),
        b.clone(),
    );
    println!("{} * {} = {}", 2, p3.clone(), p3.clone() + p3);
    let p4 = PointWrapper::new(
        FiniteField::new(143, prime),
        FiniteField::new(98, prime),
        a.clone(),
        b.clone(),
    );
    println!("{}", p4.clone() + p4);
    let p5 = PointWrapper::new(
        FiniteField::new(47, prime),
        FiniteField::new(71, prime),
        a.clone(),
        b.clone(),
    );
    println!("{} * {} = {}", 2, p5.clone(), p5.clone() + p5.clone());
    println!("{} * {} = {}", 4, p5.clone(), p5.clone() + p5.clone() + p5.clone() + p5.clone());
    println!(
        "{} * {} = {}",
        8, p5.clone(),
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
        21, p5.clone(),
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
        FiniteField::new(15, prime),
        FiniteField::new(86, prime),
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
    let z: BigInt = BigInt::parse_bytes(b"bc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423", 16).unwrap();
    let r: BigInt = BigInt::parse_bytes(b"37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6", 16).unwrap();
    let s: BigInt = BigInt::parse_bytes(b"8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec", 16).unwrap();
    let px: BigInt = BigInt::parse_bytes(b"04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574", 16).unwrap();
    let py: BigInt = BigInt::parse_bytes(b"82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4", 16).unwrap();
    let point = S256Point::new(S256Field::new(px), S256Field::new(py));
    let n_2: BigInt = N.to_owned() - 2;
    let s_inv = s.modpow(&n_2, &N);
    let u_1:BigInt = z * s_inv.clone();
    let v_1:BigInt = r.clone() * s_inv.clone();
    let u = u_1.modpow(&BigInt::from(1), &N);
    let v = v_1.modpow(&BigInt::from(1), &N);
    match (u*G.to_owned()) + (v *point){
        PointWrapper::Inf => println!("this is invalid"),
        PointWrapper::Point { x, y: _, a: _, b: _ } => println!("num: {}, r: {}, r==n: {}", x.num, r.clone(), x.num == r.clone()),
    }
}

// y^2 = x^3 + y
fn check(x: i64, y: i64, f: i64) -> bool {
    let y_2 = (((y.pow(2)) % f) + f) % f;
    // println!("{}", y_2);
    let right = (((x.pow(3) + 7) % f) + f) % f;
    // println!("{}", right);
    y_2 == right
}
