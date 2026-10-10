#!/usr/bin/env bash
# Release builds default to APK; set AURA_BUILD_FORMAT=appbundle for an AAB.
set -euo pipefail

log() {
    printf '[AURA-BUILD] %s\n' "$*"
}

fail() {
    printf '[AURA-BUILD][ERROR] %s\n' "$*" >&2
    exit 1
}

mode="build"
case "${1:-}" in
    --check-signing)
        mode="check-signing"
        shift
        ;;
    --verify-artifact)
        mode="verify-artifact"
        shift
        ;;
    --help|-h)
        printf '%s\n' \
            'Usage: compile_aura.sh [--check-signing|--verify-artifact]' \
            '  --check-signing    Resolve and validate the keystore; print its SHA-256 certificate fingerprint.' \
            '  --verify-artifact  Verify the configured release artifact without rebuilding.'
        exit 0
        ;;
esac
[[ "$#" -eq 0 ]] || fail "Unsupported argument. Use --check-signing or --verify-artifact."

temporary_files=()
cleanup_temporary_files() {
    local temporary_file
    for temporary_file in "${temporary_files[@]}"; do
        rm -f -- "$temporary_file"
    done
}
trap cleanup_temporary_files EXIT

resolve_keystore() {
    if [[ -n "${AURA_KEYSTORE_PATH:-}" ]]; then
        if [[ -f "$AURA_KEYSTORE_PATH" && -r "$AURA_KEYSTORE_PATH" ]]; then
            export AURA_KEYSTORE_PATH
            return
        fi
        [[ -n "${AURA_KEYSTORE_BASE64:-}" ]] ||
            fail "AURA_KEYSTORE_PATH must reference an existing readable file, or set AURA_KEYSTORE_BASE64."
    fi

    [[ -n "${AURA_KEYSTORE_BASE64:-}" ]] ||
        fail "Missing release keystore: set AURA_KEYSTORE_PATH or AURA_KEYSTORE_BASE64."

    local keystore_file
    keystore_file="$(mktemp "${TMPDIR:-/tmp}/aura-release-keystore.XXXXXX")"
    temporary_files+=("$keystore_file")
    chmod 0600 "$keystore_file" 2>/dev/null ||
        fail "Could not secure the temporary Base64 keystore."
    if ! printf '%s' "$AURA_KEYSTORE_BASE64" | base64 --decode > "$keystore_file" 2>/dev/null; then
        fail "AURA_KEYSTORE_BASE64 is not valid Base64 keystore data."
    fi
    [[ -s "$keystore_file" ]] || fail "AURA_KEYSTORE_BASE64 decoded to an empty keystore."
    export AURA_KEYSTORE_PATH="$keystore_file"
}

require_release_signing_environment() {
    local required_variables=(AURA_STORE_PASSWORD AURA_KEY_ALIAS AURA_KEY_PASSWORD)
    local missing_variables=()
    local variable
    for variable in "${required_variables[@]}"; do
        [[ -n "${!variable:-}" ]] || missing_variables+=("$variable")
    done
    if [[ -z "${AURA_KEYSTORE_PATH:-}" && -z "${AURA_KEYSTORE_BASE64:-}" ]]; then
        missing_variables+=("AURA_KEYSTORE_PATH or AURA_KEYSTORE_BASE64")
    fi
    ((${#missing_variables[@]} == 0)) ||
        fail "Missing required release signing environment variable(s): ${missing_variables[*]}"
}

validate_signing_credentials() {
    local missing_variables=()
    local variable
    for variable in AURA_STORE_PASSWORD AURA_KEY_ALIAS AURA_KEY_PASSWORD; do
        [[ -n "${!variable:-}" ]] || missing_variables+=("$variable")
    done
    ((${#missing_variables[@]} == 0)) ||
        fail "Missing release signing variable(s): ${missing_variables[*]}"
    command -v keytool >/dev/null 2>&1 || fail "keytool is required to validate release signing."
}

keytool_certificate_info() {
    local keytool_output
    if ! keytool_output="$(keytool -list -v \
        -keystore "$AURA_KEYSTORE_PATH" \
        -alias "$AURA_KEY_ALIAS" \
        -storepass:env AURA_STORE_PASSWORD \
        -keypass:env AURA_KEY_PASSWORD 2>/dev/null)"; then
        fail "keytool could not validate the release keystore; check AURA_KEYSTORE_PATH, AURA_STORE_PASSWORD, AURA_KEY_ALIAS and AURA_KEY_PASSWORD."
    fi

    local fingerprint
    fingerprint="$(printf '%s\n' "$keytool_output" | awk '
        /SHA-?256:/ { sub(/^.*SHA-?256:[[:space:]]*/, ""); print; exit }
        /SHA256:/ { sub(/^.*SHA256:[[:space:]]*/, ""); print; exit }
    ' | tr -d ':[:space:]' | tr '[:lower:]' '[:upper:]')"
    [[ "$fingerprint" =~ ^[[:xdigit:]]{64}$ ]] ||
        fail "keytool did not return a valid SHA-256 certificate fingerprint."

    local subject
    subject="$(printf '%s\n' "$keytool_output" | awk -F': ' '/^[[:space:]]*Owner:/ {print $2; exit}')"
    if grep -Fqi 'Android Debug' <<< "$subject"; then
        fail "Release signing certificate is the public Android Debug certificate."
    fi
    printf '%s\n' "$fingerprint"
}

verify_release_signer() {
    local artifact="$1"
    local extension="${artifact##*.}"
    local certificate_output=""
    local certificate_subject=""
    local certificate_fingerprint=""
    local apksigner_binary="$(command -v apksigner || true)"
    local android_sdk="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
    local candidate

    if [[ -z "$apksigner_binary" && -n "$android_sdk" ]]; then
        for candidate in "$android_sdk"/build-tools/*/apksigner; do
            [[ -x "$candidate" ]] && apksigner_binary="$candidate"
        done
    fi

    if [[ "$extension" == "apk" && -n "$apksigner_binary" ]]; then
        if ! certificate_output="$("$apksigner_binary" verify --print-certs "$artifact" 2>/dev/null)"; then
            fail "apksigner rejected the release APK."
        fi
        certificate_fingerprint="$(printf '%s\n' "$certificate_output" | awk -F': ' 'tolower($0) ~ /certificate sha-256 digest:/ {print $2; exit}' | tr -d ':[:space:]' | tr '[:lower:]' '[:upper:]')"
        certificate_subject="$(printf '%s\n' "$certificate_output" | awk -F': ' 'tolower($0) ~ /certificate dn:/ {print $2; exit}')"
        [[ "$certificate_fingerprint" =~ ^[[:xdigit:]]{64}$ ]] ||
            fail "apksigner did not return a valid SHA-256 certificate fingerprint."
        log "APK signer verification used apksigner."
    else
        if [[ "$extension" == "apk" ]]; then
            log "apksigner unavailable; using keytool keystore-certificate fallback (does not inspect APK bytes)."
        else
            log "AAB signer verification uses the configured keytool certificate."
        fi
        certificate_fingerprint="$(keytool_certificate_info)"
        certificate_subject="$(keytool -list -v \
            -keystore "$AURA_KEYSTORE_PATH" \
            -alias "$AURA_KEY_ALIAS" \
            -storepass:env AURA_STORE_PASSWORD \
            -keypass:env AURA_KEY_PASSWORD 2>/dev/null |
            awk -F': ' '/^[[:space:]]*Owner:/ {print $2; exit}')"
    fi

    if grep -Fqi 'Android Debug' <<< "$certificate_subject"; then
        fail "Release artifact is signed with the public Android Debug certificate."
    fi
    printf 'CERT_SHA256=%s\n' "$certificate_fingerprint"
}

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
android_dir="$project_root/android"
local_properties="$android_dir/local.properties"

require_release_signing_environment
resolve_keystore
validate_signing_credentials
build_format="${AURA_BUILD_FORMAT:-apk}"
case "$build_format" in
    apk) ;;
    aab) build_format="appbundle" ;;
    appbundle) ;;
    *) fail "AURA_BUILD_FORMAT must be 'apk', 'aab' or 'appbundle'." ;;
esac
signing_fingerprint="$(keytool_certificate_info)"

if [[ "$mode" == "check-signing" ]]; then
    printf 'CERT_SHA256=%s\n' "$signing_fingerprint"
    exit 0
fi

if [[ "$mode" == "verify-artifact" ]]; then
    if [[ "$build_format" == "apk" ]]; then
        release_artifact="$project_root/build/app/outputs/flutter-apk/app-release.apk"
    else
        release_artifact="$project_root/build/app/outputs/bundle/release/app-release.aab"
    fi
    [[ -f "$release_artifact" ]] || fail "Configured release artifact is missing."
    verify_release_signer "$release_artifact"
    exit 0
fi

property_value() {
    local key="$1"
    local file="$2"
    if [[ -f "$file" ]]; then
        awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); value = $0} END {print value}' "$file"
    fi
}

flutter_root="${FLUTTER_ROOT:-}"
if [[ -z "$flutter_root" || ! -x "$flutter_root/bin/flutter" ]]; then
    flutter_root="$(property_value flutter.sdk "$local_properties")"
fi
if [[ -z "$flutter_root" || ! -x "$flutter_root/bin/flutter" ]]; then
    flutter_binary="$(command -v flutter || true)"
    if [[ -n "$flutter_binary" ]]; then
        flutter_root="$(cd "$(dirname "$flutter_binary")/.." && pwd -P)"
    fi
fi
if [[ -z "$flutter_root" || ! -x "$flutter_root/bin/flutter" ]]; then
    for candidate in \
        "$HOME/development/flutter" \
        "$HOME/.flutter_sdk/flutter" \
        /opt/flutter \
        /usr/local/flutter
    do
        if [[ -x "$candidate/bin/flutter" ]]; then
            flutter_root="$candidate"
            break
        fi
    done
fi
[[ -n "$flutter_root" && -x "$flutter_root/bin/flutter" ]] ||
    fail "Flutter SDK not found. Set FLUTTER_ROOT to an installed stable Flutter SDK."
export FLUTTER_ROOT="$(cd "$flutter_root" && pwd -P)"
export PATH="$FLUTTER_ROOT/bin:$PATH"

if [[ -z "${AURA_PUBLIC_KEY_ENV:-}" ]]; then
    AURA_PUBLIC_KEY_ENV='MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAi9+ZvYGgwGWKyG+1CfBsF0Qb9iUCqg454HU011guOGZPxcQNpAtVheZ+Ek3UrlQwYOrWbdCeqr7v1OwkomfmEsdSq9qEBsPGlpdA4PXdeC18aVs/jGMKXQIVBWkXRUCWSGczCrKLzNqujCbYp+/7XSOgcjaLZocLv2G0PZUPDVEwqNmSRD4nYAeF6kyLn/4Syi6nEcUMLCFz8jzpWagCYvrJROfjQeD3DFHpRKLrP9TJQD+nQ7uL9kUakz0aO5rJ2fTD/Sr4XX/pT9tgshCN9VZUxPHy1OqPD/Dkckfh91XKDm5wPbJiDuIqgT7zOxZ9nxqP8u/tEGn/slEp9LnoNwIDAQAB'
    public_key_source="build-only fallback"
    log "WARNING: AURA_PUBLIC_KEY_ENV is empty; using the build-only fallback key. Signed model updates will fail closed. Configure production_keys for a production release."
else
    public_key_source="production"
fi
[[ "$AURA_PUBLIC_KEY_ENV" =~ ^[A-Za-z0-9+/]+={0,2}$ ]] ||
    fail "AURA_PUBLIC_KEY_ENV must be the Base64 DER body without PEM delimiters or whitespace."

key_file="$(mktemp "${TMPDIR:-/tmp}/aura-public-key.XXXXXX")"
temporary_files+=("$key_file")
python3 - "$AURA_PUBLIC_KEY_ENV" "$key_file" <<'PY'
import base64
import sys

try:
    der = base64.b64decode(sys.argv[1], validate=True)
except (ValueError, base64.binascii.Error) as error:
    raise SystemExit(f"AURA_PUBLIC_KEY_ENV is not valid Base64: {error}")
if not der:
    raise SystemExit("AURA_PUBLIC_KEY_ENV decoded to an empty public key.")
with open(sys.argv[2], "wb") as key_file:
    key_file.write(der)
PY
openssl pkey -pubin -inform DER -in "$key_file" -noout
rm -f "$key_file"

log "Selecting JDK 17 and mapping the installed Android SDK/NDK."
source "$project_root/tool/setup_env_fix.sh"
trap cleanup_temporary_files EXIT
[[ -x "$JAVA_HOME/bin/java" ]] ||
    fail "The JDK 17 setup did not provide JAVA_HOME/bin/java."

java_version="$("$JAVA_HOME/bin/java" -version 2>&1 | awk -F '"' '/version/ {print $2; exit}')"
[[ "$java_version" == 17.* ]] ||
    fail "Expected Java 17 at JAVA_HOME, found '${java_version:-unknown}'."
export PATH="$JAVA_HOME/bin:$PATH"
export GRADLE_OPTS="${GRADLE_OPTS:+$GRADLE_OPTS }-Dorg.gradle.java.home=$JAVA_HOME"
log "Gradle Java: $("$JAVA_HOME/bin/java" -version 2>&1 | head -n 1)"

gradle_version_output="$(
    cd "$android_dir"
    ./gradlew --version
)"
gradle_java_major="$(
    printf '%s\n' "$gradle_version_output" |
        awk '/^(Launcher )?JVM:/ {version = $NF; sub(/\..*/, "", version); print version; exit}'
)"
[[ "$gradle_java_major" == "17" ]] ||
    fail "Gradle reports Java ${gradle_java_major:-unknown}; Java 17 is required."

properties_tmp="$(mktemp "$local_properties.XXXXXX")"
temporary_files+=("$properties_tmp")
if [[ -f "$local_properties" ]]; then
    awk -F= '$1 != "flutter.sdk" {print}' "$local_properties" > "$properties_tmp"
fi
printf 'flutter.sdk=%s\n' "$FLUTTER_ROOT" >> "$properties_tmp"
mv "$properties_tmp" "$local_properties"

if [[ -n "${CM_ENV:-}" ]]; then
    printf 'FLUTTER_ROOT=%s\n' "$FLUTTER_ROOT" >> "$CM_ENV"
fi

cd "$project_root"
if [[ "$build_format" == "apk" ]]; then
    log "Building the release APK with the ${public_key_source} RSA public key."
    "$FLUTTER_ROOT/bin/flutter" build apk --release \
        --dart-define="AURA_PUBLIC_KEY=$AURA_PUBLIC_KEY_ENV"
    release_artifact="$project_root/build/app/outputs/flutter-apk/app-release.apk"
else
    log "Building the release app bundle with the ${public_key_source} RSA public key."
    "$FLUTTER_ROOT/bin/flutter" build appbundle --release \
        --dart-define="AURA_PUBLIC_KEY=$AURA_PUBLIC_KEY_ENV"
    release_artifact="$project_root/build/app/outputs/bundle/release/app-release.aab"
fi
[[ -f "$release_artifact" ]] || fail "Release artifact was not created."
verify_release_signer "$release_artifact"
log "Release artifact signature verified."
