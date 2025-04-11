#!/bin/bash

# Script to push the recon_framework to GitHub
# This script will create a new repository on GitHub and push your code

echo "=== GitHub Repository Setup ==="
echo "This script will create a new repository on GitHub and push your code."

# Set GitHub token from command line argument
GITHUB_TOKEN=$1
if [ -z "$GITHUB_TOKEN" ]; then
    echo "Error: GitHub token not provided"
    echo "Usage: $0 <github_token>"
    exit 1
fi

# Set repository details
GITHUB_USERNAME="0init"
REPO_NAME="recon_framework"
REPO_DESCRIPTION="Automated Reconnaissance and Vulnerability Scanning Framework"
VISIBILITY="public"  # or "private" if you prefer

echo "Creating GitHub repository: $REPO_NAME"

# Create GitHub repository using GitHub API
response=$(curl -s -X POST \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/user/repos \
  -d "{\"name\":\"$REPO_NAME\",\"description\":\"$REPO_DESCRIPTION\",\"private\":$([ "$VISIBILITY" = "private" ] && echo "true" || echo "false")}")

# Check if repository was created successfully
if echo "$response" | grep -q "\"name\":\"$REPO_NAME\""; then
  echo "Repository created successfully!"
else
  error=$(echo "$response" | grep -o '"message":"[^"]*"')
  echo "Failed to create repository. Error: $error"
  
  # Check if repository already exists
  if echo "$error" | grep -q "already exists"; then
    echo "Repository might already exist. Attempting to push anyway."
  else
    exit 1
  fi
fi

# Add GitHub remote
echo "Adding GitHub remote..."
git remote add origin https://github.com/$GITHUB_USERNAME/$REPO_NAME.git 2>/dev/null || git remote set-url origin https://github.com/$GITHUB_USERNAME/$REPO_NAME.git

# Push to GitHub using the token
echo "Pushing code to GitHub..."
git push -u https://$GITHUB_TOKEN@github.com/$GITHUB_USERNAME/$REPO_NAME.git master

echo "Done! Your code has been pushed to GitHub."
echo "Repository URL: https://github.com/$GITHUB_USERNAME/$REPO_NAME"
