#!/bin/bash

# This script will create Semaphore library in XCFramework format.
# Before using it, you must first build libary for each architecture with these commands.
# cargo build --release --lib --target aarch64-apple-ios
# cargo build --release --lib --target=aarch64-apple-ios-sim
# cargo build --release --lib --target=x86_64-apple-ios


DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd $DIR

# Location for arm64-simulator and x86_64-simulator library
SIMULATOR_PATH="SemaphoreSDK/Simulator"

# Location for arm64 library
DEVICE_PATH="SemaphoreSDK/Device"

# Location for C headers file
HEADERS_PATH="SemaphoreSDK/Headers"

# Location of XCFramework output
XCFRAMEWORK_PATH="SemaphoreSDK/SemaphoreSDK.xcframework"

# Create temporary directories
mkdir -p $SIMULATOR_PATH
mkdir -p $DEVICE_PATH
mkdir -p $HEADERS_PATH

# Merge libraries for simulator platform since XCFramework does not support multiple libraries for the same platform (simulator).
lipo -create target/aarch64-apple-ios-sim/release/libcryptonative.a target/x86_64-apple-ios/release/libcryptonative.a -output $SIMULATOR_PATH/libsemaphore.a

# Just copy library for device platform
cp target/aarch64-apple-ios/release/libcryptonative.a $DEVICE_PATH/libsemaphore.a

# Copy headers
cp src/libsemaphore.h $HEADERS_PATH

# Create XCFramework
rm -rf $XCFRAMEWORK_PATH
xcodebuild -create-xcframework -library $SIMULATOR_PATH/libsemaphore.a -headers $HEADERS_PATH -library $DEVICE_PATH/libsemaphore.a -headers $HEADERS_PATH -output $XCFRAMEWORK_PATH

#Create module.modulemap file
cat > SemaphoreSDK/SemaphoreSDK.xcframework/module.modulemap << EOF
module SemaphoreSDK {
    header "ios-arm64/Headers/libsemaphore.h"
    link "libsemaphore"
    export *
}
EOF

# Remove temporary directories
rm -rf $SIMULATOR_PATH
rm -rf $DEVICE_PATH
rm -rf $HEADERS_PATH