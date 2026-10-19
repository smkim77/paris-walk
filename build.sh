#!/usr/bin/env sh
# Builds docs/index.html for GitHub Pages from index.html.
# index.html is written as a page fragment (the claude.ai artifact adds the document
# skeleton when publishing), so this wraps it in a full HTML document: everything
# before <div class="wrap"> goes into <head>, the rest into <body>.
set -e
cd "$(dirname "$0")"
mkdir -p docs
split=$(grep -n '<div class="wrap">' index.html | head -1 | cut -d: -f1)
{
  printf '%s\n' '<!doctype html>' '<html lang="ko">' '<head>'
  printf '%s\n' '<meta charset="utf-8">'
  printf '%s\n' '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">'
  printf '%s\n' '<style>:root{padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px);box-sizing:border-box}body{margin:0}img{max-width:100%}</style>'
  head -n $((split - 1)) index.html | grep -v 'claude:viewport-fit-sides'
  printf '%s\n' '</head>' '<body>'
  tail -n +"$split" index.html
  printf '%s\n' '</body>' '</html>'
} > docs/index.html
echo "built docs/index.html"
