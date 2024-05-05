#!/bin/bash

# Set the path to the virtual environment
VENV_DIR="venv"
export PATH="$VENV_DIR/bin:$PATH"

if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv $VENV_DIR
    if [ $? -ne 0 ]; then
        echo "Failed to create virtual environment."
        exit 1
    fi

    source $VENV_DIR/bin/activate
    echo "Installing necessary libraries..."
    pip install -r requirements.txt

    deactivate
fi
source $VENV_DIR/bin/activate
python3 main.py

# Deactivate the virtual environment
#deactivate
