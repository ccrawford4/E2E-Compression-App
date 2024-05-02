#!/bin/bash

SCRIPT_PATH="$(realpath "$0")"

if [ ! -x "$SCRIPT_PATH" ]; then
    chmod +x "$SCRIPT_PATH"
fi

cd json-api

./configure

make

make install
