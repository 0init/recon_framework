#!/bin/bash

# Simple script to push to GitHub
# Usage: ./push_to_github.sh <github_username> <repository_name> <github_token>

if [ $# -ne 3 ]; then
    echo "Usage: $0 <github_username> <repository_name> <github_token>"
    exit 1
fi

GITHUB_USERNAME=$1
REPO_NAME=$2
GITHUB_TOKEN=$3

echo "Setting up GitHub repository: $REPO_NAME"

# Set up the remote repository URL with the token
GITHUB_URL="https://$GITHUB_TOKEN@github.com/$GITHUB_USERNAME/$REPO_NAME.git"

# Add or update the remote
if git remote | grep -q "origin"; then
    echo "Updating remote URL..."
    git remote set-url origin "$GITHUB_URL"
else
    echo "Adding remote..."
    git remote add origin "$GITHUB_URL"
fi

# Push to GitHub
echo "Pushing code to GitHub..."
git push -u origin master

echo "Done! Your code has been pushed to GitHub."
echo "Repository URL: https://github.com/$GITHUB_USERNAME/$REPO_NAME"
