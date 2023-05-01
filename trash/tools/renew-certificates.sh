#!/bin/sh

node -e 'require("./acme_challenge.js").renewCertificates().then(data => process.stdout.write(data)).catch(err => {process.stdout.write(err); process.exit(1);});'
