#!/bin/bash
# Build script for Render deployment
# This script organizes files into proper folder structure

echo "Organizing files into proper folder structure..."

# Create directories
mkdir -p templates
mkdir -p static/css

# Move HTML files to templates folder if they exist in root
for file in base.html dashboard.html login.html profile.html register.html; do
    if [ -f "$file" ]; then
        echo "Moving $file to templates/"
        mv "$file" templates/
    fi
done

# Move CSS file to static/css folder if it exists in root
if [ -f "style.css" ]; then
    echo "Moving style.css to static/css/"
    mv "style.css" static/css/
fi

echo "File organization complete!"
echo "Installing Python dependencies..."
pip install -r requirements.txt

echo "Build complete!"
