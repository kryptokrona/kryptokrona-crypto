# The C++ Turbo Native Module KryptokronaCrypto for Android. Added to the app's appmodules
# library by React Native autolinking (../react-native.config.js: cxxModule* keys); the
# generated autolinking_cxxModuleProvider then creates the module by name.
cmake_minimum_required(VERSION 3.13)

set(KRYPTOKRONA_CRYPTO_ROOT ${CMAKE_CURRENT_LIST_DIR}/..)

# The Rust crypto core (scripts/build-android.sh -> prebuilt/android/<abi>/)
add_library(kryptokrona_crypto_ffi STATIC IMPORTED)
set_target_properties(kryptokrona_crypto_ffi PROPERTIES
    IMPORTED_LOCATION ${KRYPTOKRONA_CRYPTO_ROOT}/prebuilt/android/${ANDROID_ABI}/libkryptokrona_crypto_mobile.a)

add_library(kryptokrona_crypto_module OBJECT ${KRYPTOKRONA_CRYPTO_ROOT}/cpp/KryptokronaCryptoModule.cpp)

target_include_directories(kryptokrona_crypto_module PUBLIC ${KRYPTOKRONA_CRYPTO_ROOT}/cpp)

target_compile_features(kryptokrona_crypto_module PRIVATE cxx_std_20)

# The compile flags React Native's own C++ targets use (folly configuration among them);
# defined by ReactNative-application.cmake.
if(COMMAND target_compile_reactnative_options)
    target_compile_reactnative_options(kryptokrona_crypto_module PRIVATE)
else()
    target_compile_options(kryptokrona_crypto_module PRIVATE
        -fexceptions -frtti
        -DFOLLY_NO_CONFIG=1 -DFOLLY_HAVE_CLOCK_GETTIME=1 -DFOLLY_USE_LIBCPP=1
        -DFOLLY_CFG_NO_COROUTINES=1 -DFOLLY_MOBILE=1 -DFOLLY_HAVE_RECVMMSG=1
        -DFOLLY_HAVE_PTHREAD=1 -DFOLLY_HAVE_XSI_STRERROR_R=1)
endif()

# react_codegen_KryptokronaCryptoSpec: the codegen output of this library (the C++ spec base
# class); jsi / reactnative: provided by the app's ReactNative-application.cmake.
target_link_libraries(kryptokrona_crypto_module
    react_codegen_KryptokronaCryptoSpec
    jsi
    reactnative
    kryptokrona_crypto_ffi
    log
    dl
    m)
