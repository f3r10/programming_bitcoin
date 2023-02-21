use chapter3::{finite_field::FiniteField, PointWrapper};
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
}

// y^2 = x^3 + y
fn check(x: i64, y: i64, f: i64) -> bool {
    let y_2 = (((y.pow(2)) % f) + f) % f;
    // println!("{}", y_2);
    let right = (((x.pow(3) + 7) % f) + f) % f;
    // println!("{}", right);
    y_2 == right
}
