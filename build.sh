#!/bin/bash
# Build wxtrace-demo Android app
# Usage: ./build.sh [debug|release|clean]
# Environment: ANDROID_HOME must point to the Android SDK.

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODE="${1:-debug}"

if [ -z "$ANDROID_HOME" ]; then
    # Try common locations
    for candidate in /home/OGC/Android/Sdk "$HOME/Android/Sdk" /opt/android-sdk; do
        if [ -d "$candidate" ]; then
            ANDROID_HOME="$candidate"
            break
        fi
    done
fi

if [ -z "$ANDROID_HOME" ] || [ ! -d "$ANDROID_HOME" ]; then
    echo "[-] ANDROID_HOME not set or invalid: ${ANDROID_HOME:-<empty>}" >&2
    echo "    Please set ANDROID_HOME to your Android SDK directory." >&2
    exit 1
fi

export ANDROID_HOME
cd "$SCRIPT_DIR"

case "$MODE" in
    debug)
        echo "[*] Building debug APK..."
        ./gradlew :app:assembleDebug
        echo "[+] APK: $SCRIPT_DIR/app/build/outputs/apk/debug/app-debug.apk"
        ;;
    release)
        echo "[*] Building release APK..."
        ./gradlew :app:assembleRelease
        echo "[+] APK: $SCRIPT_DIR/app/build/outputs/apk/release/app-release.apk"
        ;;
    clean)
        echo "[*] Cleaning..."
        ./gradlew clean
        echo "[+] Cleaned"
        ;;
    *)
        echo "Usage: $0 [debug|release|clean]"
        exit 1
        ;;
esac
