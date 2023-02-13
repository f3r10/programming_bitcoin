use chapter3::{finite_field::FiniteField, PointWrapper};

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
    let p2 = PointWrapper::new(x2, y2, a, b);
    println!("{}", p1 + p2)
}

// y^2 = x^3 + y
fn check(x: i64, y: i64, f: i64) -> bool {
    let y_2 = (((y.pow(2)) % f) + f) % f;
    // println!("{}", y_2);
    let right = (((x.pow(3) + 7) % f) + f) % f;
    // println!("{}", right);
    y_2 == right
}
