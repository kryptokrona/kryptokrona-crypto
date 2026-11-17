// Copyright (c) 2026, The Kryptokrona Developers
//
// Please see the included LICENSE file for more information.

package se.kryptokrona.crypto;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.facebook.react.BaseReactPackage;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.module.model.ReactModuleInfo;
import com.facebook.react.module.model.ReactModuleInfoProvider;

import java.util.HashMap;
import java.util.Map;

/**
 * Lets React Native autolinking include this library (codegen, CMake). It provides no Java
 * module: KryptokronaCrypto is a C++ Turbo Native Module created by the app's
 * autolinking_cxxModuleProvider.
 */
public class KryptokronaCryptoPackage extends BaseReactPackage {
    @Nullable
    @Override
    public NativeModule getModule(@NonNull String name, @NonNull ReactApplicationContext reactContext) {
        return null;
    }

    @NonNull
    @Override
    public ReactModuleInfoProvider getReactModuleInfoProvider() {
        return () -> {
            final Map<String, ReactModuleInfo> modules = new HashMap<>();
            return modules;
        };
    }
}
