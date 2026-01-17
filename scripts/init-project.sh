#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./scripts/init-project.sh tripzy-payment-api

NEW_NAME="${1:-}"
if [[ -z "$NEW_NAME" ]]; then
  echo "Usage: $0 <new-project-name>"
  exit 1
fi

# -------------------------
# TEMPLATE CONSTANTS
# -------------------------
OLD_NAME="spring-template"
OLD_PACKAGE="com.nduyhai.template"
OLD_APP="TemplateApplication"
OLD_TEST="TemplateApplicationTests"

# -------------------------
# DERIVED VALUES
# -------------------------
# tripzy-payment-api -> TripzyPaymentApi
CAMEL_NAME="$(echo "$NEW_NAME" | sed -E 's/(^|-)([a-z])/\U\2/g')"

NEW_PACKAGE="com.nduyhai.${NEW_NAME//-/.}"
NEW_APP="${CAMEL_NAME}Application"
NEW_TEST="${CAMEL_NAME}ApplicationTests"

OLD_PKG_PATH="${OLD_PACKAGE//./\/}"
NEW_PKG_PATH="${NEW_PACKAGE//./\/}"

echo "==> Initializing project"
echo "    name:      $OLD_NAME -> $NEW_NAME"
echo "    package:   $OLD_PACKAGE -> $NEW_PACKAGE"
echo "    app:       $OLD_APP -> $NEW_APP"
echo "    test:      $OLD_TEST -> $NEW_TEST"

# -------------------------
# sed compatibility (macOS/Linux)
# -------------------------
sedi() {
  if sed --version >/dev/null 2>&1; then
    sed -i -e "$1" "$2"
  else
    sed -i '' -e "$1" "$2"
  fi
}

# -------------------------
# 1) Replace text everywhere
# -------------------------
find . -type f \
  ! -path "./.git/*" \
  ! -path "./target/*" \
  ! -path "./build/*" \
  ! -path "./.idea/*" \
  ! -name "*.jar" \
  ! -name "*.png" \
  ! -name "*.jpg" \
  -print0 | while IFS= read -r -d '' f; do
    sedi "s/${OLD_NAME}/${NEW_NAME}/g" "$f" || true
    sedi "s/${OLD_PACKAGE}/${NEW_PACKAGE}/g" "$f" || true
    sedi "s/${OLD_APP}/${NEW_APP}/g" "$f" || true
    sedi "s/${OLD_TEST}/${NEW_TEST}/g" "$f" || true
done

# -------------------------
# 2) Move Java package folders (main + test)
# -------------------------
for SRC in src/main/java src/test/java; do
  if [[ -d "$SRC/$OLD_PKG_PATH" ]]; then
    mkdir -p "$SRC/$NEW_PKG_PATH"
    mv "$SRC/$OLD_PKG_PATH"/* "$SRC/$NEW_PKG_PATH"/
    rmdir -p "$SRC/$OLD_PKG_PATH" || true
  fi
done

# -------------------------
# 3) Rename Java files
# -------------------------
for SRC in src/main/java src/test/java; do
  if [[ -f "$SRC/$NEW_PKG_PATH/${OLD_APP}.java" ]]; then
    mv "$SRC/$NEW_PKG_PATH/${OLD_APP}.java" \
       "$SRC/$NEW_PKG_PATH/${NEW_APP}.java"
  fi

  if [[ -f "$SRC/$NEW_PKG_PATH/${OLD_TEST}.java" ]]; then
    mv "$SRC/$NEW_PKG_PATH/${OLD_TEST}.java" \
       "$SRC/$NEW_PKG_PATH/${NEW_TEST}.java"
  fi
done

echo "✅ Project initialized successfully"
echo ""
echo "Next:"
echo "  mvn clean test"
echo "  Run: ${NEW_PACKAGE}.${NEW_APP}"
