fn main() {
   println!("(17, 64) over F_103 -> {}", check(17, 64, 103));
   println!("(192, 105) over F_223 -> {}", check(192, 105, 223));
   println!("(17, 56) over F_223 -> {}", check(17, 56, 223));
   println!("(200, 119) over F_223 -> {}", check(200, 119, 223));
   println!("(1, 193) over F_223 -> {}", check(1, 193, 223));
   println!("(42, 99) over F_223 -> {}", check(42, 99, 223));
   
}

// y^2 = x^3 + y
fn check(x: i64, y: i64, f: i64) -> bool {
    let y_2 = (((y.pow(2)) % f) + f) % f;
    // println!("{}", y_2);
    let right = (((x.pow(3) + 7) % f) + f) % f;
    // println!("{}", right);
    y_2 == right
}

#[cfg(test)]
mod point_finite_field_test {
    use chapter3::{finite_field::FiniteField, PointWrapper};

   #[test]
   fn test_on_curve() -> Result<(), String> {
      let prime = 223;
      let a = FiniteField::new(0, prime);
      let b = FiniteField::new(7, prime);
      let valid_points = vec![(192, 105), (17, 56), (1, 193)];
      for (x_raw, y_raw) in valid_points {
         let x = FiniteField::new(x_raw, prime);
         let y = FiniteField::new(y_raw, prime);
         PointWrapper::new(x, y, a.clone(), b.clone());
      }
      Ok(())
   }

   #[test]
   fn test_no_on_curve() {
      let prime = 223;
      let a = FiniteField::new(0, prime);
      let b = FiniteField::new(7, prime);
      let invalid_points = vec![(200, 119), (42, 99)];
      for (x_raw, y_raw) in invalid_points {
         let x = FiniteField::new(x_raw, prime);
         let y = FiniteField::new(y_raw, prime);
         let result = std::panic::catch_unwind(|| PointWrapper::new(x, y, a.clone(), b.clone()));
         assert!(result.is_err())
      }
   }

}
