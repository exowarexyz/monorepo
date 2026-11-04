pub mod common {
    pub mod kv {
        pub mod v1 {
            pub use exoware_sdk::common::kv::v1::*;
        }
    }
}

pub mod qmdb {
    pub mod v1 {
        #![allow(non_camel_case_types)]
        #![allow(unused_imports)]
        #![allow(clippy::derivable_impls)]
        #![allow(clippy::match_single_binding)]
        #![allow(elided_lifetimes_in_paths)]
        #![allow(clippy::use_self)]
        #![allow(clippy::missing_const_for_fn)]
        #![allow(clippy::multiple_inherent_impl)]
        #![allow(clippy::unused_async)]
        include!("../gen/qmdb.v1.rs");
    }
}
