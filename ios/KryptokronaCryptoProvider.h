// Copyright (c) 2026, The Kryptokrona Developers
//
// Please see the included LICENSE file for more information.

/* Hands the pure C++ module to React Native on iOS (package.json codegenConfig.ios
   .modulesProvider maps KryptokronaCrypto to this class). No logic of its own. */

#import <Foundation/Foundation.h>
#import <ReactCommon/RCTTurboModule.h>

NS_ASSUME_NONNULL_BEGIN

@interface KryptokronaCryptoProvider : NSObject <RCTModuleProvider>

@end

NS_ASSUME_NONNULL_END
