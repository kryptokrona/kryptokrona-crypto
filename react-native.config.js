// React Native autolinking of kryptokrona-crypto.
//
// Android: the C++ module (cpp/KryptokronaCryptoModule.*) is built by android/CMakeLists.txt as
// the target kryptokrona_crypto_module and created by the app's generated
// autolinking_cxxModuleProvider (the app's OnLoad.cpp calls it).
// iOS: the podspec builds cpp/ and ios/; codegenConfig.ios.modulesProvider in package.json
// registers the module.
module.exports = {
    dependency: {
        platforms: {
            android: {
                cxxModuleCMakeListsModuleName: 'kryptokrona_crypto_module',
                cxxModuleCMakeListsPath: 'CMakeLists.txt',
                cxxModuleHeaderName: 'KryptokronaCryptoModule'
            }
        }
    }
};
