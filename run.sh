#!/bin/bash

# Check if exactly two arguments are given
if [ "$#" -ne 2 ]; then
    echo "Error: Incorrect number of arguments."
    echo "Usage: ./run.sh <config file name>.json"
    exit 1
fi


# Navigate to the app directory and make the executable
cd app || { echo "Error: Failed to change directory to app."; exit 1; }
make || { echo "Error: Make failed."; exit 1; }

# Run the program
./compdetect "$arg" || { echo "Error: Failed to execute client."; exit 1; }

