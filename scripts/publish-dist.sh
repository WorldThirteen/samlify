#!/bin/bash

# Script to build and publish to a distribution branch
# This allows installation directly from GitHub without publishing to npm

set -e  # Exit on error

DIST_BRANCH="dist"
CURRENT_BRANCH=$(git branch --show-current)

echo "📦 Publishing build to '$DIST_BRANCH' branch..."
echo "Current branch: $CURRENT_BRANCH"

# Ensure we're on the correct source branch
if [ "$CURRENT_BRANCH" != "master" ]; then
  echo "⚠️  Warning: You're not on ec-keys-support or master branch"
  read -p "Continue anyway? (y/N) " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
  fi
fi

# Check for uncommitted changes
if ! git diff-index --quiet HEAD --; then
  echo "❌ Error: You have uncommitted changes. Please commit or stash them first."
  exit 1
fi

echo "🧹 Cleaning old build..."
rm -rf build types

echo "🔨 Building project..."
yarn install --frozen-lockfile
make rebuild

# Generate type definitions if not already done
if [ ! -d "types" ]; then
  echo "📝 Generating type definitions..."
  npx tsc --declaration --emitDeclarationOnly --outDir types
fi

echo "✅ Build complete!"

# Get current commit info for reference
COMMIT_HASH=$(git rev-parse --short HEAD)
COMMIT_MSG=$(git log -1 --pretty=%B)

echo "📤 Preparing to push to $DIST_BRANCH..."

# Create or checkout dist branch
if git show-ref --verify --quiet refs/heads/$DIST_BRANCH; then
  echo "Checking out existing $DIST_BRANCH branch..."
  git checkout $DIST_BRANCH
else
  echo "Creating new $DIST_BRANCH branch..."
  git checkout --orphan $DIST_BRANCH
  git rm -rf . 2>/dev/null || true
fi

# Copy essential files to dist branch
echo "📋 Copying files to $DIST_BRANCH..."

# Checkout essential files from source branch
git checkout $CURRENT_BRANCH -- package.json
git checkout $CURRENT_BRANCH -- README.md
git checkout $CURRENT_BRANCH -- LICENSE
git checkout $CURRENT_BRANCH -- index.ts
git checkout $CURRENT_BRANCH -- CHANGELOG.md 2>/dev/null || true

# Copy build output (these are gitignored in source branch)
cp -r build .
cp -r types .

# Create/update .gitignore for dist branch (we want to commit build artifacts here)
cat > .gitignore << 'EOF'
# Only ignore dependencies in dist branch
node_modules
.nyc_output
.vscode
.idea
*.log
*.tgz
package-lock.json
EOF

# Create README for dist branch
cat > DIST_README.md << EOF
# Samlify (Distribution Branch)

This is an automated distribution branch containing pre-built files.

**Source:** $CURRENT_BRANCH branch (commit: $COMMIT_HASH)

## Installation

\`\`\`bash
npm install github:WorldThirteen/samlify#dist
# or
yarn add github:WorldThirteen/samlify#dist
\`\`\`

## Source Repository

For source code and development, see the main branch:
https://github.com/WorldThirteen/samlify

---

Built from commit: $COMMIT_HASH
Original commit message: $COMMIT_MSG
EOF

# Stage all changes
git add -A

# Commit
echo "💾 Committing to $DIST_BRANCH..."
git commit -m "Build from $CURRENT_BRANCH@$COMMIT_HASH

Original commit: $COMMIT_MSG

Auto-generated distribution build" || {
  echo "ℹ️  No changes to commit"
}

# Push to remote
echo "🚀 Pushing $DIST_BRANCH to remote..."
git push origin $DIST_BRANCH --force

echo "✨ Done! Your package is now installable via:"
echo ""
echo "    npm install github:WorldThirteen/samlify#dist"
echo "    or"
echo "    yarn add github:WorldThirteen/samlify#dist"
echo ""

# Return to original branch
git checkout $CURRENT_BRANCH

echo "🔄 Returned to $CURRENT_BRANCH branch"
