#!/usr/bin/env bash

echo "Checking Kaevo Cloud tools..."
echo ""

check_tool() {
  if command -v "$1" >/dev/null 2>&1; then
    echo "✅ $1 installed"
  else
    echo "❌ $1 missing"
  fi
}

check_tool git
check_tool aws
check_tool sam
check_tool python3
check_tool docker

echo ""
echo "Done."
