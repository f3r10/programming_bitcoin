use std::{
    fmt,
    ops::{Add, Mul},
    rc::Rc,
};

use num_bigint::BigInt;

use crate::{finite_field::FiniteField, PointWrapper};

//https://www.desmos.com/calculator/ialhd71we3
impl crate::PointWrapper<FiniteField> {
    pub fn new(x: FiniteField, y: FiniteField, a: FiniteField, b: FiniteField) -> Self {
        if y.pow(BigInt::from(2)) != (x.pow(BigInt::from(3)) + a.clone() * x.clone() + b.clone()) {
            panic!("({:?}, {:?}) is not on the curve", x, y);
        }
        PointWrapper::Point { x, y, a, b }
    }

    pub fn new_inf() -> Self {
        PointWrapper::Inf
    }
}

impl PartialEq for PointWrapper<FiniteField> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PointWrapper::Inf, PointWrapper::Inf) => true,
            (PointWrapper::Inf, PointWrapper::Point { .. }) => false,
            (PointWrapper::Point { .. }, PointWrapper::Inf) => false,
            (
                PointWrapper::Point {
                    x: x1,
                    y: y1,
                    a: a1,
                    b: b1,
                },
                PointWrapper::Point {
                    x: x2,
                    y: y2,
                    a: a2,
                    b: b2,
                },
            ) => x1 == x2 && y1 == y2 && a1 == a2 && b1 == b2,
        }
    }

    fn ne(&self, other: &Self) -> bool {
        !(self == other)
    }
}

impl fmt::Display for PointWrapper<FiniteField> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // write!(f, "({:?}, {:?})", self.x.clone().take(), self.y.clone().take())
        match self {
            PointWrapper::Inf => {
                write!(f, "infinity")
            }
            PointWrapper::Point {
                x: x1,
                y: y1,
                a: a1,
                b: b1,
            } => {
                write!(
                    f,
                    "Point({:#x}, {:#x})_{}_{} FieldElement({})",
                    x1.num, y1.num, a1.num, b1.num, x1.prime
                )
            }
        }
    }
}

impl Add for PointWrapper<FiniteField> {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        match (&self, &other) {
            (PointWrapper::Inf, PointWrapper::Inf) => PointWrapper::Inf,
            (PointWrapper::Inf, p @ PointWrapper::Point { .. }) => p.clone(),
            (p @ PointWrapper::Point { .. }, PointWrapper::Inf) => p.clone(),
            (
                p1 @ PointWrapper::Point {
                    x: x1,
                    y: y1,
                    a: a1,
                    b: b1,
                },
                p2 @ PointWrapper::Point {
                    x: x2,
                    y: y2,
                    a: a2,
                    b: b2,
                },
            ) => {
                // todo!()
                if a1 != a2 || b1 != b2 {
                    panic!("Points {}, {} are not on the same curve", p1, p2)
                }
                // Additive inverses points
                if x1 == x2 && y1 != y2 {
                    return PointWrapper::Inf;
                } else if x1 != x2 {
                    let s = (y2.clone() - y1.clone()) / (x2.clone() - x1.clone());
                    let x = s.pow(BigInt::from(2)) - x1.clone() - x2.clone();
                    let y = s * (x1.clone() - x.clone()) - y1.clone();
                    return PointWrapper::Point {
                        x,
                        y,
                        a: a1.clone(),
                        b: b1.clone(),
                    };
                } else if p1 == p2
                    && y1.clone()
                        == FiniteField::new_big_int(BigInt::from(0), x1.clone().prime).unwrap()
                {
                    PointWrapper::Inf
                } else if p1 == p2 {
                    let s = (FiniteField::new_big_int(BigInt::from(3), x1.clone().prime).unwrap()
                        * x1.clone().pow(BigInt::from(2))
                        + a1.clone())
                        / (FiniteField::new_big_int(BigInt::from(2), x1.clone().prime).unwrap()
                            * y1.clone());
                    let x = s.pow(BigInt::from(2))
                        - FiniteField::new_big_int(BigInt::from(2), x1.clone().prime).unwrap()
                            * x1.clone();
                    let y = s * (x1.clone() - x.clone()) - y1.clone();
                    return PointWrapper::Point {
                        x,
                        y,
                        a: a1.clone(),
                        b: b1.clone(),
                    };
                } else {
                    panic!("no more cases")
                }
            }
        }
    }
}

impl Mul<PointWrapper<FiniteField>> for i32 {
    type Output = PointWrapper<FiniteField>;

    fn mul(self, rhs: PointWrapper<FiniteField>) -> Self::Output {
        let mut coef = self;
        let mut current = rhs;
        let mut result = PointWrapper::new_inf();
        while coef > 0 {
            if coef & 1 == 1 {
                result = result + current.clone();
            }
            current = current.clone() + current;
            coef >>= 1
        }
        return result;
    }
}

impl Mul<PointWrapper<FiniteField>> for BigInt {
    type Output = PointWrapper<FiniteField>;

    fn mul(self, rhs: PointWrapper<FiniteField>) -> Self::Output {
        let mut coef = Rc::new(self);
        let mut current = rhs;
        let mut result = PointWrapper::new_inf();
        while coef.as_ref() > &BigInt::from(0) {
            if coef.as_ref() & BigInt::from(1) == BigInt::from(1) {
                result = result + current.clone();
            }
            current = current.clone() + current;
            *Rc::get_mut(&mut coef).unwrap() >>= 1
        }
        return result;
    }
}

#[cfg(test)]
mod point_finite_field_test {
    use crate::{finite_field::FiniteField, PointWrapper};
    use anyhow::Result;

    struct TestPoint {
        p1: (i32, i32),
        p2: (i32, i32),
        res: (i32, i32),
    }

    #[test]
    fn test_on_curve() -> Result<()> {
        let prime = 223;
        let a = FiniteField::new(0, prime)?;
        let b = FiniteField::new(7, prime)?;
        let valid_points = vec![(192, 105), (17, 56), (1, 193)];
        for (x_raw, y_raw) in valid_points {
            let x = FiniteField::new(x_raw, prime)?;
            let y = FiniteField::new(y_raw, prime)?;
            PointWrapper::new(x, y, a.clone(), b.clone());
        }
        Ok(())
    }

    #[test]
    fn test_no_on_curve() -> Result<()> {
        let prime = 223;
        let a = FiniteField::new(0, prime)?;
        let b = FiniteField::new(7, prime)?;
        let invalid_points = vec![(200, 119), (42, 99)];
        for (x_raw, y_raw) in invalid_points {
            let x = FiniteField::new(x_raw, prime)?;
            let y = FiniteField::new(y_raw, prime)?;
            let result = std::panic::catch_unwind(|| PointWrapper::new(x, y, a.clone(), b.clone()));
            assert!(result.is_err())
        }
        Ok(())
    }
    #[test]
    fn test_add() -> Result<()> {
        let test_points = vec![
            TestPoint {
                p1: (170, 142),
                p2: (60, 139),
                res: (220, 181),
            },
            TestPoint {
                p1: (47, 71),
                p2: (17, 56),
                res: (215, 68),
            },
            TestPoint {
                p1: (143, 98),
                p2: (76, 66),
                res: (47, 71),
            },
            TestPoint {
                p1: (192, 105),
                p2: (192, 105),
                res: (49, 71),
            },
        ];
        for p in test_points {
            let prime = 223;
            let a = FiniteField::new(0, prime)?;
            let b = FiniteField::new(7, prime)?;
            let x1 = FiniteField::new(p.p1.0, prime)?;
            let y1 = FiniteField::new(p.p1.1, prime)?;
            let x2 = FiniteField::new(p.p2.0, prime)?;
            let y2 = FiniteField::new(p.p2.1, prime)?;
            let p1 = PointWrapper::new(x1, y1, a.clone(), b.clone());
            let p2 = PointWrapper::new(x2, y2, a.clone(), b.clone());
            let x_res = FiniteField::new(p.res.0, prime)?;
            let y_res = FiniteField::new(p.res.1, prime)?;
            let p_res = PointWrapper::new(x_res, y_res, a, b);
            assert_eq!(p_res, p1 + p2)
        }
        Ok(())
    }
    #[test]
    fn test_mul_binary_expansion() -> Result<()> {
        let prime = 223;
        let a = FiniteField::new(0, prime)?;
        let b = FiniteField::new(7, prime)?;
        let p5 = PointWrapper::new(
            FiniteField::new(15, prime)?,
            FiniteField::new(86, prime)?,
            a.clone(),
            b.clone(),
        );
        assert_eq!(PointWrapper::new_inf(), 7 * p5);
        let p5 = PointWrapper::new(
            FiniteField::new(47, prime)?,
            FiniteField::new(71, prime)?,
            a.clone(),
            b.clone(),
        );

        let res8 = PointWrapper::new(
            FiniteField::new(116, prime)?,
            FiniteField::new(55, prime)?,
            a.clone(),
            b.clone(),
        );
        let res4 = PointWrapper::new(
            FiniteField::new(194, prime)?,
            FiniteField::new(51, prime)?,
            a.clone(),
            b.clone(),
        );
        let res2 = PointWrapper::new(
            FiniteField::new(36, prime)?,
            FiniteField::new(111, prime)?,
            a.clone(),
            b.clone(),
        );
        assert_eq!(res2, 2 * p5.clone());
        assert_eq!(res4, 4 * p5.clone());
        assert_eq!(res8, 8 * p5.clone());
        assert_eq!(PointWrapper::new_inf(), 21 * p5.clone());
        Ok(())
    }
}
