# nodejs-router
Simple NodeJS router for local HTTP/HTTPS webapplications

# Recommended setup

Download the code from the repository:
```sh
cd /srv && git clone https://github.com/jetibest/nodejs-router.git
```

While JSON is supported out-of-the-box, JINI is more comfortable for humans.
JINI is an extension of INI, with support for nested arrays and objects.

```sh
cd /srv/router && npm install jini
```

```sh
cat <<EOF >/etc/router/80.ini
vhosts[] = {
  host = *
  
  routes[] = {
    redirect = https:// 
  }
}
EOF
```

```sh
cat <<EOF >/etc/router/443.ini
vhosts[] = {
  host = *
  
  [routes]
  (
    {
      path = /app1
      address = :8081
    }
    {
      path = /app2
      address = :8082/some-dir/
    }
    {
      address = :8080
    }
  )
}
EOF
```

To use JINI, adjust the service file to pass `--config /etc/router/<port>.ini`.

```sh
systemctl link /srv/router/router@.service
systemctl link /srv/router/router-tls@.service

systemctl enable router@80
systemctl start router@80
systemctl enable router-tls@443
systemctl start router-tls@443
```

# Manual

```
Usage: /usr/bin/node /srv/router/router.js [OPTIONS] [[bind-host:]listen-port]

Where
 listen-port defaults to "80".
 bind-host defaults to "::".

 Use host "::" to listen on every interface for both IPv4 and IPv6.

OPTIONS

 -c,--config <file>  Path to configuration file of this instance.
                     Defaults to: "/etc/router/<port>.json"
 --no-tls            Disable TLS layer. This is the default.
                     Overrides any option that may enable TLS.
 --tls               Enable TLS layer.
 --tls-key <file>    Specify default TLS key (override by a virtual host).
                     Defaults to: "/etc/router/default.key"
 --tls-cert <file>   Specify default TLS certificate (override by a virtual
                     host).
                     Defaults to: "/etc/router/default.crt"
 --acme-challenge    Enable a ACME challenge server as a virtual host.
                     Implies --tls
                     Runs on any freely available port.
                     Matches only for path: "/.well-known/acme-challenge/"
                     Matches any virtual host.
 -h,[-[-]]help       Show this help.


CONFIG

{
  debug: true               
  proxy: <proxy>            If false, overwrites X-Forwarded-* headers.
  acmeChallenge: {          Only used if --acme-challenge has been set.
    host: <host-match>      Only apply ACME challenge for matching hosts.
          [<host-match>]    Defaults to: "*"
    renewInterval: 2419200  Number of seconds to auto-renew certificates.
                            Any falsy value (like 0) disables auto-renewal.
                            Defaults to: 2419200 (28 days).
    renewRetry: 60          Number of seconds to wait before retrying in
                            case of an error.
  }                         
  vhosts: [<vhost>]         Apply vhosts in given order to requests.
                            First vhost route that matches, will handle the
                            request, and no further vhosts that might also
                            potentially match are considered anymore.
                            That is even if the matching vhost route fails
                            to give a response.
                            If no vhosts are matched, for HTTP 404 Not Found
                            is returned, and for WebSockets the socket is
                            simply ended and destroyed.
}

vhost {
  host: <host-match>               Defaults to: "*"
        [<host-match>]             
  name: <string>                   Set a convenient name to use for logs.
  webmasterEmailAddress: <string>  E-mail address of the webmaster, for
                                   receiving feedback on ACME challenges.
  proxy: <proxy>                   Override global default proxy options.
  routes: [<route>]                Apply routes if vhost matches.
}

route {
  path: "/"
  address: "<route-address>"
  proxy: <proxy>               Override global/vhost default proxy options.
         "<route-address>"
         true
  redirect: "<route-address>"
            true
}

proxy {
  If proxy is set, any request that matches the route will be proxied to
  the configured route address.
  By default, headers from the original request are copied to the proxy
  request.
  If the original request method is DELETE or OPTIONS
  and the Content-Length header is falsy,
  then the proxy request's Transfer-Encoding header is unset,
  and the Content-Length header is set to 0.

  timeout: 0           Set a socket timeout for the proxy request.
                       Does not apply to WebSockets.
  requestTimeout: 0    Set a socket timeout for the original request.
                       Does not apply to WebSockets.
  changeOrigin: false  
  headers: {}          Overwrite HTTP headers for the proxy request.
                       
  trustProxy: true     If false, overwrites X-Forwarded-* headers.

                     > From node:http.request(...), for HTTP/HTTPS:
  method               Override the HTTP original request method.
  socketPath           Unix domain socket.
  localAddress         Local interface to bind for network connections.
  auth                 Set HTTP Basic Authorization ("<user>:<password>").

                     > From node:https.request(...), for HTTPS:
  pfx                  PFX or PKCS12 encoded private key and cert chain.
  passphrase           Shared passphrase used for private key and/or PFX.
  key                  Private keys in PEM format.
  cert                 Cert chains in PEM format.
  ca                   Optionally override the trusted CA certificates.
                       Defaults to: well-known CAs curated by Mozilla.
  rejectUnauthorized   Server cert is verified against the given CAs.
                       Defaults to: true
  ciphers              Cipher suite specification, replacing the default.
  minVersion           Optionally set the minimum TLS version to allow.
                       Defaults to: "TLSv1.2"
  maxVersion           Optionally set the maximum TLS version to allow.
                       Defaults to: "TLSv1.3"
}

route-address {
  If route address is a string, it must encode a URL.
  If route address is an object, it must encode a URL like so:
  protocol: <string>   Set a fixed protocol.
  hostname: <string>   Set a fixed hostname.
  port: <int>          Set a fixed port.
  pathname: <string>   Set the pathname.
  
  Any query string or hash (anchor) is ignored.
  
  For a redirect, if the protocol or port is given, the hostname defaults
  to the host from the original request.
  For a proxy request, the hostname defaults to "localhost".
  For a proxy request, the port defaults to 80, or 443 when using TLS.
  
}

host-match {
  If host match is a string, the match is literal, except for the use of a
  wildcard character (*). The wildcard matches any (empty) string, except
  for the dot character (.). Therefore,
    - to match any IPv4 address, use: *.*.*.*
    - every subdomain level must be separately matched:
      example.org, *.example.org, *.*.example.org, ...
  
  If host match is an object, it must encode a RegExp like so:
  type: "RegExp"         Must be set literally, case-sensitive, not optional.
  pattern: <string>      RegExp pattern, do not put between forward slashes.
  flags: <string>        RegExp flags.
                         Defaults to: "i"
}


SIGNALS

  SIGHUP      Reload configuration from filesystem. A new configuration is only
              applied if it contains no errors. If an error occurs, the current
              configuration remains, and a warning or error message is printed.

  SIGUSR1     Print the current configuration.

  SIGUSR2     Renew certificates. Requires TLS and ACME challenge options to be
              enabled. These options cannot be dynamically changed.


NOTES



  Instead of JSON, JINI might be more human-friendly. But must be installed
  separately (npm install jini).

EXAMPLES


 1. Forward port 80 to 443 using a JSON configuration:

    router :80

    {
      "vhosts": [
        {
          "host": ["example.org", "*.example.org"],
          "routes": [
            {"redirect": "https://localhost:443"}
          ]
        }
      ]
    }

    Note: This redirects to "localhost", which means that the server locally
    listening at :443 must support both IPv4 and IPv6 connections depending
    on the client connection.

 2. Forward apps to different webservers for the same domain.

    router --tls :443

    {
      "vhosts": [
        {
          "host": ["example.org", "*.example.org"],
          "routes": [
            {"path": "/app1", "address": ":8081"},
            {"path": "/app2", "address": ":8082"},
            {"path": "/app3", "address": ":8082/some/base-path"},
            {"address": ":8080"}
          ]
        }
      ]
    }

    Note: The first matching path takes all. Even if the proxied server does not
    handle the request, or returns a request error (i.e. HTTP status 404, 500).

    Note: The last route is a catch-all, where the default path ("/") will match
    any path. The path could also have explicitly been set as "/" for clarity.

    Note: A request to:
      https://example.org/app3/sub/path
    will be proxied to
      http://localhost:8082/some/base-path/sub/path

    Note: If no catch-all is defined for a vhost, it is possible that if no
    route matched, another vhost may still match that route provided that the
    vhost also matches the request host.
    Therefore, both the order of vhosts and the order of routes is important.



```
