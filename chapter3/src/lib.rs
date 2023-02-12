pub mod real_numbers_point;
pub mod finite_field;
pub mod finite_field_point;

#[derive(Debug, Clone, Copy)]
pub enum PointWrapper<A> {
    Inf,
    Point { x: A, y: A, a: A, b: A },
}

