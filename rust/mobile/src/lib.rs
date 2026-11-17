//! The static library the React Native C++ `TurboModule` (`cpp/KryptokronaCryptoModule.cpp`)
//! links: the C ABI of `xkr_crypto_ffi::ffi`, declared in `cpp/xkr_crypto_ffi.h`. A staticlib
//! carries every `#[no_mangle]` function of its dependencies; this crate only names the module
//! so the dependency is linked.

pub use xkr_crypto_ffi::ffi;

/// The ABI version the library was built with (`XKR_CRYPTO_ABI_VERSION` of the header).
pub const ABI_VERSION: u32 = xkr_crypto_ffi::ffi::ABI_VERSION;
