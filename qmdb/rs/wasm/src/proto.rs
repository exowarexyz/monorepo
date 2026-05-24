pub mod qmdb {
    pub mod v1 {
        #![allow(non_camel_case_types)]
        #![allow(unused_imports)]
        #![allow(clippy::derivable_impls)]
        #![allow(clippy::match_single_binding)]
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../src/gen/qmdb.v1.rs"
        ));
    }
}

pub mod store {
    pub mod common {
        pub mod v1 {
            #![allow(non_camel_case_types)]
            #![allow(unused_imports)]
            #![allow(clippy::derivable_impls)]
            #![allow(clippy::match_single_binding)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../sdk/rs/src/gen/store.common.v1.rs"
            ));
        }
    }
}
