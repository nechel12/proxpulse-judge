#!/usr/bin/env bash
# Вывести раздел CHANGELOG.md одной версии (без его заголовка).
# Использование: scripts/release-notes.sh <X.Y.Z> [changelog]
# Завершается ошибкой, если раздел отсутствует или пуст, поэтому релиз не может
# выйти без заметок.
set -euo pipefail

VERSION="${1:?usage: $0 <X.Y.Z> [changelog]}"
FILE="${2:-$(dirname "$0")/../CHANGELOG.md}"

NOTES="$(awk -v v="$VERSION" '
  /^## / {
    if (found) exit
    if (index($0, "## " v " ") == 1 || index($0, "## [" v "]") == 1) { found = 1; next }
  }
  found { print }
' "$FILE")"

if [ -z "$(printf '%s' "$NOTES" | tr -d '[:space:]')" ]; then
  echo "error: no CHANGELOG section for $VERSION in $FILE" >&2
  exit 1
fi
printf '%s\n' "$NOTES"
