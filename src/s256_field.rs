use std::fmt::Display;

use num_bigint::BigInt;

use crate::{finite_field::FiniteField, P};
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct S256Field {
    pub field: FiniteField,
}

impl S256Field {
    pub fn new(num: BigInt) -> Result<S256Field> {
        Ok(S256Field {
            field: FiniteField::new_big_int(num, P.to_owned())?,
        })
    }

    pub fn sqrt(self) -> Self {
        let new_field = self.field.pow((P.to_owned() + 1) / 4);
        S256Field { field: new_field }
    }
}

impl Display for S256Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#064x}", self.field.num)
    }
}
