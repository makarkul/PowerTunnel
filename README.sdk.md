# PowerTunnel SDK and Core Update Process

## Problem Diagnosis
We identified that the `NoSuchMethodError` for the `content()` method was occurring because the Android app was using an older version of the SDK in which the `ProxyResponse` interface didn't include the `content()` method.

## Solution Steps

### 1. Build the SDK
```bash
cd /Users/makarand/PowerTunnel
./gradlew :sdk:clean :sdk:build :sdk:jar
```
This builds the SDK module with the updated `ProxyResponse` interface that includes the `content()` method.

### 2. Verify SDK Contents
We extracted and examined the SDK JAR to confirm it contains the `content()` method:
```bash
cd /tmp && mkdir -p sdk_extract && cd sdk_extract
jar -xf /Users/makarand/PowerTunnel/sdk/build/libs/sdk-2.0.jar io/github/krlvm/powertunnel/sdk/http/ProxyResponse.class
javap -p io/github/krlvm/powertunnel/sdk/http/ProxyResponse
```
The output confirmed that our SDK includes the `content()` method:
```
public abstract byte[] content();
public abstract void setContent(byte[]);
```

### 3. Copy SDK to Android Project
```bash
cp /Users/makarand/PowerTunnel/sdk/build/libs/sdk-2.0.jar /Users/makarand/PowerTunnel-Android/app/libs/
```
This updates the SDK JAR in the Android project with our newly built version.

### 4. Build Core Module with Updated SDK
```bash
cd /Users/makarand/PowerTunnel
./gradlew :core:clean :core:build
```
This builds the core module using the updated SDK.

### 5. Build Fat JAR for Core
```bash
cd /Users/makarand/PowerTunnel
./gradlew :core:fatJar
```
This creates a fat JAR for the core module that includes all dependencies, including our updated SDK.

### 6. Copy Core JAR to Android Project
```bash
cp /Users/makarand/PowerTunnel/core/build/libs/core-2.5.2-all.jar /Users/makarand/PowerTunnel-Android/app/libs/
```
This replaces the existing core JAR in the Android project with our newly built version.

### 7. Build the Android App
```bash
cd /Users/makarand/PowerTunnel-Android
./aio.sh
```
This builds the Android app with the updated libraries.

## Key Findings
1. The `NoSuchMethodError` was caused by a version mismatch between the SDK used to build the plugin and the SDK included in the Android app.
2. The SDK in the Android app didn't have the `content()` method in the `ProxyResponse` interface.
3. By rebuilding the SDK and core modules and updating the JARs in the Android project, we've ensured that the Android app will use the same SDK version as the plugin.

This approach ensures that the plugin's calls to `response.content()` will now work correctly, as the Android app is using an SDK version that includes this method.

## Important Notes
- Always ensure that plugins and the Android app use the same version of the SDK to avoid compatibility issues.
- When developing new plugins that use new SDK methods, make sure to update the SDK and core JARs in the Android project.
- The `aio.sh` script in the PowerTunnel-Android project handles building and deploying the app, but it doesn't automatically update the SDK and core JARs.
