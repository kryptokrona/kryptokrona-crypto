# Pure C++ Turbo Native Module KryptokronaCrypto (cpp/) on the Rust crypto core
# (prebuilt/ios/KryptokronaCryptoFFI.xcframework, built by scripts/build-ios.sh on macOS).
require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "kryptokrona-crypto"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]
  s.platforms    = { :ios => "15.1" }
  s.source       = { :git => "https://github.com/kryptokrona/kryptokrona-crypto.git", :tag => "v#{s.version}" }

  s.source_files = "cpp/**/*.{h,cpp}", "ios/**/*.{h,mm}"
  s.public_header_files = "ios/**/*.h"
  s.vendored_frameworks = "prebuilt/ios/KryptokronaCryptoFFI.xcframework"
  # The Rust code reads operating-system randomness through SecRandomCopyBytes.
  s.frameworks = "Security"

  s.pod_target_xcconfig = {
    "CLANG_CXX_LANGUAGE_STANDARD" => "c++20",
    "HEADER_SEARCH_PATHS" => "\"$(PODS_TARGET_SRCROOT)/cpp\""
  }

  install_modules_dependencies(s)
end
