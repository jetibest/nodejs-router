#!/bin/bash

echo "Executing openssl to generate a self-signed certificate:"
# Use this as local SSL certificate for HTTPS requests between this server and HA-proxy of the hosting party
openssl req -x509 -newkey rsa:4096 -nodes -keyout private/key.pem -out certs/cert.pem
