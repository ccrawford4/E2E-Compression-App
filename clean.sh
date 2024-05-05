#!/bin/bash

# Navigate to the app directory and clean up
cd app || { echo "Error: Failed to change directory to app."; exit 1; }
make clean || { echo "Error: Make clean failed."; exit 1; }
