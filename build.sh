#!/bin/bash
# Career Pathway Booklet - Build Script for Render
# This script downloads and sets up the complete application

set -e

echo "=== Career Pathway Booklet Build Script ==="
echo "Starting build process..."

# Download the application zip file
echo "Downloading application package..."
curl -L -o app.zip "https://files.manuscdn.com/user_upload_by_module/session_file/310519663141642807/yCJTqzYKNHmalUhV.zip"

# Extract the application
echo "Extracting application files..."
unzip -o app.zip

# Remove the zip file
rm -f app.zip

# Create necessary directories
mkdir -p static/uploads/photos
mkdir -p uploads

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

echo "=== Build completed successfully ==="
echo "Application is ready to run!"
