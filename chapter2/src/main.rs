use std::{ops::Add, fmt};

#[derive(Debug, Clone, Copy)]
struct Point2 {
    x: i32,
    y: i32,
    a: i32,
    b: i32
}

#[derive(Debug, Clone, Copy)]
enum Point {
    Inf,
    Point(Point2),
}

impl Point {
    pub fn new(x: Option<i32>, y: Option<i32>, a: i32, b: i32) -> Point {
        if x.is_none() && y.is_none() {
            return Point::Inf
        }
         match x {
             Some(x_l) => {
                match y {
                    Some(y_l) => {
                        if y_l.pow(2) != (x_l.pow(3) + a * x_l + b) {
                            panic!("({:?}, {:?}) is not on the curve", x, y);
                        }
                        let a = Point2 { x: x_l, y: y_l , a, b};
                        Point::Point(a)
                    }
                    None =>
                        {panic!("invalid inf point")}
                }
            },
             None => {panic!("invalid inf point")},
         }
    }
    
}

impl PartialEq for Point{
    fn eq(&self, other: &Self) -> bool {
        match self {
            Point::Inf => {
                match other {
                    Point::Inf => true,
                    Point::Point(Point2 { x: x2, y: y2, a: a2, b: b2 }) => {
                        false 
                    }
                }
            }
            Point::Point(Point2 { x: x1, y: y1, a: a1, b: b1 }) => {
                match other {
                    Point::Inf => false,
                    Point::Point(Point2 { x: x2, y: y2, a: a2, b: b2 }) => {
                        x1 == x2 && y1 == y2 && a1 == a2 && b1 == b2 
                    }
                }

            }
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
                write!(f, "Inf")
            }
            Point::Point(Point2 { x: x1, y: y1, a: _a1, b: _b1 }) => {
                write!(f, "({:?}, {:?})", x1, y1)
            }
        }
    }
}

impl Add for Point{
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        match self {
            Point::Inf => {
                return other
            }
            Point::Point(Point2 { x: x1, y: y1, a: a1, b: b1 }) => {
                match other {
                    Point::Inf => self,
                    Point::Point(Point2 { x: x2, y: y2, a: a2, b: b2 }) => {
                        if x1 == x2 && y1 != y2 {
                            return Point::Inf
                        }
                        else if x1 != x2  {
                            let s = (y2 - y1) / (x2 - x1);
                            let x = s.pow(2)- x1 - x2;
                            let y = s * (x1 - x) - y1;
                            let p = Point2 {x, y, a: a1, b: b1};
                            return Point::Point(p)
                            
                        }

                        else {
                            let s = (3 * x1.pow(2) + a1)  / (2 * y1);
                            let x = s.pow(2) - 2 * x1;
                            let y = s * (x1 - x) - y1;
                            let p = Point2 {x, y, a: a1, b: b1};
                            return Point::Point(p)

                        }
                        // if a1 !=  a2 || b1 != b2 {
                        //     panic!("Points {}, {} are not on the same curve", self, other);
                        // }
                    }
                }

            }
        }
    }
}


fn main() {
    let p11 = Point::new(Some(-1), Some(-1), 5, 7);
    // let p2 = Point::new(-1, -2, 5, 7);
    // let p2 = Point::new(2, 4, 5, 7);
    let p3 = Point::new(Some(-1), Some(-1), 5, 7);
    let p4 = Point::new(Some(18), Some(77), 5, 7);
    let inf = Point::new(None, None, 5, 7);
    println!("{:?}", p11);
    println!("(-1, -1) different from (18, 77) -> {}", p3 != p4);
    // let p5 = Point::new(5, 7, 5, 7);
    let p1 = Point::new(Some(2), Some(5), 5, 7);
    let p2 = Point::new(Some(-1), Some(-1), 5, 7);
    let p3 = p1 + p2;
    println!("{:?}", p3);
    let p4 = p11 + p11;
    println!("{:?}", p4);

}
