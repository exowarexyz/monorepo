pub mod sql {
    pub mod v1 {
        #![allow(non_camel_case_types)]
        #![allow(unused_imports)]
        #![allow(clippy::derivable_impls)]
        #![allow(clippy::match_single_binding)]
        #![allow(elided_lifetimes_in_paths)]
        #![allow(clippy::use_self)]
        include!("gen/sql.v1.rs");
    }
}
