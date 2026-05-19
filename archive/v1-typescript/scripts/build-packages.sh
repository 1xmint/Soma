#!/bin/bash
# Build and assemble soma-heart and soma-sense npm packages
set -e

echo "Building TypeScript..."
npx tsc -p tsconfig.build.json

echo "Assembling soma-heart..."
rm -rf packages/soma-heart/dist
mkdir -p packages/soma-heart/dist
cp -r dist/heart packages/soma-heart/dist/
cp -r dist/core packages/soma-heart/dist/

echo "Assembling soma-sense..."
rm -rf packages/soma-sense/dist
mkdir -p packages/soma-sense/dist
cp -r dist/sensorium packages/soma-sense/dist/
cp -r dist/mcp packages/soma-sense/dist/
cp -r dist/core packages/soma-sense/dist/
cp -r dist/heart packages/soma-sense/dist/
# Include signals.ts bridge (sensorium depends on it)
mkdir -p packages/soma-sense/dist/experiment
cp dist/experiment/signals.js packages/soma-sense/dist/experiment/
cp dist/experiment/signals.d.ts packages/soma-sense/dist/experiment/
cp dist/experiment/signals.js.map packages/soma-sense/dist/experiment/ 2>/dev/null || true
cp dist/experiment/signals.d.ts.map packages/soma-sense/dist/experiment/ 2>/dev/null || true

echo ""
echo "Package contents:"
echo "  soma-heart: $(find packages/soma-heart/dist -name '*.js' | wc -l) JS files"
echo "  soma-sense: $(find packages/soma-sense/dist -name '*.js' | wc -l) JS files"
echo ""
echo "Ready to publish:"
echo "  cd packages/soma-heart && npm publish"
echo "  cd packages/soma-sense && npm publish"
