#!/bin/sh

domain_name="$1"
email_address="$2"

print_usage()
{
	echo "Usage:"
	echo "  $0 <domain> <email>"
	echo ""
	echo "Example:"
	echo "  $0 'example.org' 'webmaster@example.org'"
	echo ""
}

if [ -z "$domain_name" ]
then
	echo "Invalid usage. No domain name specified."
	echo ""
	print_usage
	exit 1
fi

case "$email_address" in
	*@*) ;;
	*)
		echo "Invalid usage. No e-mail address specified."
		echo ""
		print_usage
		exit 1
	;;
esac

escaped_domain_name="$(/usr/bin/printf '%q' "$domain_name")"
escaped_email_address="$(/usr/bin/printf '%q' "$email_address")"

exec node -e 'require("./acme_challenge.js").createCertificate({domain: "'"$escaped_domain_name"'", email: "'"$escaped_email_address"'"}).then(data => process.stdout.write(data)).catch(err => {process.stdout.write(err); process.exit(1); });'
