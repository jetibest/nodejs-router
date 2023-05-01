#!/bin/bash

DEFAULT_TLS_KEY_PATH="/etc/router/default.key"
DEFAULT_TLS_CERT_PATH="/etc/router/default.crt"

echo "Executing openssl to generate a self-signed certificate..."
echo ""

if [ -e "$DEFAULT_TLS_KEY_PATH" ]
then
	echo "error: $DEFAULT_TLS_KEY_PATH already exists, will not overwrite."
	exit 1
fi
if [ -e "$DEFAULT_TLS_CERT_PATH" ]
then
	echo "error: $DEFAULT_TLS_CERT_PATH already exists, will not overwrite."
	exit 1
fi

echo "Will output key and certificate at:"
echo " - $DEFAULT_TLS_KEY_PATH"
echo " - $DEFAULT_TLS_CERT_PATH"
echo ""

# Use this as local SSL certificate for HTTPS requests between this server and HA-proxy of the hosting party
openssl req -x509 -newkey rsa:4096 -nodes -keyout "$DEFAULT_TLS_KEY_PATH" -out "$DEFAULT_TLS_CERT_PATH"

