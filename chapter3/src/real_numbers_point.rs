use std::{fmt, ops::Add};

use crate::PointWrapper;

//https://www.desmos.com/calculator/ialhd71we3
impl crate::PointWrapper<i32> {
    pub fn new_old(x: i32, y: i32, a: i32, b: i32) -> PointWrapper<i32> {
        if y.pow(2) != (x.pow(3) + a * x + b) {
            panic!("({:?}, {:?}) is not on the curve", x, y);
        }
        PointWrapper::Point { x, y, a, b }
    }

    pub fn new_inf_old() -> Self {
        PointWrapper::Inf
    }
}

impl PartialEq for PointWrapper<i32> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PointWrapper::Inf, PointWrapper::Inf) => true,
            (PointWrapper::Inf, PointWrapper::Point {..}) => false,
            (PointWrapper::Point {..}, PointWrapper::Inf) => false,
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

impl fmt::Display for PointWrapper<i32> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // write!(f, "({:?}, {:?})", self.x.clone().take(), self.y.clone().take())
        match self {
            PointWrapper::Inf => {
                write!(f, "infinity")
            }
            PointWrapper::Point{
                x: x1,
                y: y1,
                a: a1,
                b: b1,
            } => {
                write!(f, "Point({:?}, {:?})_{}_{}", x1, y1, a1, b1)
            }
        }
    }
}

impl Add for PointWrapper<i32> {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        match (self, other) {
            (PointWrapper::Inf, PointWrapper::Inf) => PointWrapper::Inf,
            (PointWrapper::Inf, p @ PointWrapper::Point{..}) => p,
            (p @ PointWrapper::Point{..}, PointWrapper::Inf) => p,
            (
                p1 @ PointWrapper::Point{
                x: x1,
                y: y1,
                a: a1,
                b: b1,
            },
                p2 @ PointWrapper::Point{
                x: x2,
                y: y2,
                a: a2,
                b: b2,
            },
            ) => {
                if a1 != a2 || b1 != b2 {
                    panic!("Points {}, {} are not on the same curve", p1, p2)
                }
                // Additive inverses points
                if x1 == x2 && y1 != y2 {
                    return PointWrapper::Inf;
                } else if x1 != x2 {
                    let s = (y2 - y1) / (x2 - x1);
                    let x = s.pow(2) - x1 - x2;
                    let y = s * (x1 - x) - y1;
                    return PointWrapper::Point{ x, y, a: a1, b: b1 };
                } else if p1 == p2 && y1 == 0 {
                    PointWrapper::Inf
                } else if p1 == p2 {
                    let s: i32 = (3 * x1.pow(2) + a1) / (2 * y1);
                    let x = s.pow(2) - 2 * x1;
                    let y = s * (x1 - x) - y1;
                    return PointWrapper::Point{ x, y, a: a1, b: b1 };
                } else {
                    panic!("no more cases")
                }
            }
        }
    }
}
