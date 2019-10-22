#!/bin/bash

echo "Using node to test syntax of config.json:"
node -e 'console.log(JSON.parse(require("fs").readFileSync("config.json")));' && echo "Syntax OK" || echo "Syntax error"
