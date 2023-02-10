use std::{fmt, ops::Add};

#[derive(Debug, Clone, Copy)]
enum Point {
    Inf,
    Point { x: i32, y: i32, a: i32, b: i32 },
}
//https://www.desmos.com/calculator/ialhd71we3
impl Point {
    pub fn new(x: i32, y: i32, a: i32, b: i32) -> Point {
        if y.pow(2) != (x.pow(3) + a * x + b) {
            panic!("({:?}, {:?}) is not on the curve", x, y);
        }
        Point::Point { x, y, a, b }
    }

    pub fn new_inf() -> Point {
        Point::Inf
    }
}

impl PartialEq for Point {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Point::Inf, Point::Inf) => true,
            (Point::Inf, Point::Point {..}) => false,
            (Point::Point {..}, Point::Inf) => false,
            (
                Point::Point {
                    x: x1,
                    y: y1,
                    a: a1,
                    b: b1,
                },
                Point::Point {
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

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // write!(f, "({:?}, {:?})", self.x.clone().take(), self.y.clone().take())
        match self {
            Point::Inf => {
                write!(f, "infinity")
            }
            Point::Point{
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

impl Add for Point {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        match (self, other) {
            (Point::Inf, Point::Inf) => Point::Inf,
            (Point::Inf, p @ Point::Point{..}) => p,
            (p @ Point::Point{..}, Point::Inf) => p,
            (
                p1 @ Point::Point{
                x: x1,
                y: y1,
                a: a1,
                b: b1,
            },
                p2 @ Point::Point{
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
                    return Point::Inf;
                } else if x1 != x2 {
                    let s = (y2 - y1) / (x2 - x1);
                    let x = s.pow(2) - x1 - x2;
                    let y = s * (x1 - x) - y1;
                    return Point::Point{ x, y, a: a1, b: b1 };
                } else if p1 == p2 && y1 == 0 {
                    Point::Inf
                } else if p1 == p2 {
                    let s = (3 * x1.pow(2) + a1) / (2 * y1);
                    let x = s.pow(2) - 2 * x1;
                    let y = s * (x1 - x) - y1;
                    return Point::Point{ x, y, a: a1, b: b1 };
                } else {
                    panic!("no more cases")
                }
            }
        }
    }
}

fn main() {
    let p = Point::new(-1, -1, 5, 7);
    let inf = Point::new_inf();
    let res = p + inf;
    print!("{}", res)
}

#[cfg(test)]
mod point_test {
    use crate::Point;

    #[test]
    fn point_inside_curve() {
        let _p = Point::new(-1, -1, 5, 7);
        let _p = Point::new(18, 77, 5, 7);
    }
    #[test]
    #[should_panic]
    fn point_outside_curve() {
        let _p = Point::new(-1, -2, 5, 7);
        let _p = Point::new(2, 4, 5, 7);
        let _p = Point::new(5, 7, 5, 7);
    }
    #[test]
    fn add_inf() {
        let p1 = Point::new(-1, -1, 5, 7);
        let p2 = Point::new(-1, 1, 5, 7);
        let inf = Point::new_inf();
        assert_eq!(p1 + inf, p1);
        assert_eq!(inf + p2, p2);
        assert_eq!(p1 + p2, inf);
    }
    #[test]
    fn add_different_x() {
        let p1 = Point::new(3, 7, 5, 7);
        let p2 = Point::new(-1, -1, 5, 7);
        let p3 = Point::new(2, -5, 5, 7);
        assert_eq!(p1 + p2, p3);
    }
    #[test]
    fn add_same_point() {
        let p = Point::new(-1, -1, 5, 7);
        let p2 = Point::new(18, 77, 5, 7);
        assert_eq!(p + p, p2);
    }
    #[test]
    fn add_same_x_different_y() {
        let p1 = Point::new(-1, 1, 5, 7);
        let p2 = Point::new(-1, -1, 5, 7);
        assert_eq!(p1 + p2, Point::new_inf());
    }
}
