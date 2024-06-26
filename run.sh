#!/bin/bash

# Check if exactly 1 argument is given
if [ "$#" -ne 1 ]; then
    echo "Error: Incorrect number of arguments."
    echo "Usage: ./run.sh <config file name>.json"
    exit 1
fi

# Assign the config file
config_file="$1"

# Navigate to the app directory and make the executable
cd app || { echo "Error: Failed to change directory to app."; exit 1; }
make || { echo "Error: Make failed."; exit 1; }

# Run the program
sudo ./compdetect "$config_file" || { echo "Error: Failed to execute client."; exit 1; }

