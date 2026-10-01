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
        include!("../gen/qmdb.v1.rs");
    }
}
