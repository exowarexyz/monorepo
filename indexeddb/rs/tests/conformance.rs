//! The conformance suite every Store backend passes, run against the IndexedDB store in
//! headless Chrome.
#![cfg(target_arch = "wasm32")]

mod support;

use wasm_bindgen_test::wasm_bindgen_test_configure;

wasm_bindgen_test_configure!(run_in_browser);

exoware_conformance::tests!(
    #[wasm_bindgen_test::wasm_bindgen_test],
    support::IndexedDbBackend
);
