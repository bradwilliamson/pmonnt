//! The original (pre-optimization) view-model code, compiled only for tests. The
//! differential tests in `super::tests` check that the optimized builders produce exactly
//! the same rows for randomized inputs.

#![allow(clippy::too_many_arguments, dead_code)]

pub mod grouped;
pub mod tree;
