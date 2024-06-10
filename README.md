- [TOTP RFC](https://datatracker.ietf.org/doc/html/rfc6238)
- [Mozilla Gradle plugin](https://github.com/mozilla/rust-android-gradle)
- [Rust Java bindings](https://github.com/jni-rs/jni-rs)
- [andOTP compatible backups](https://github.com/andOTP/andOTP)
- [testdata](https://github.com/asmw/andOTP-decrypt)
```sh
export RELEASE_STORE_PASS=123456
export RELEASE_KEY_PASS=123456
keytool -genkeypair -v \
        -keystore app/release_key.keystore \
        -alias release_key \
        -keyalg RSA \
        -keysize 2048 \
        -validity 10000 \
        -storepass $RELEASE_STORE_PASS \
        -keypass $RELEASE_KEY_PASS
./gradlew assembleRelease
```
