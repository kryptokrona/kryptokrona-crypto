// Copyright (c) 2026, The Kryptokrona Developers
//
// Please see the included LICENSE file for more information.

#import "KryptokronaCryptoProvider.h"

#import <ReactCommon/CallInvoker.h>
#import <ReactCommon/TurboModule.h>

#import "KryptokronaCryptoModule.h"

@implementation KryptokronaCryptoProvider

- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
    return std::make_shared<facebook::react::KryptokronaCryptoModule>(params.jsInvoker);
}

@end
