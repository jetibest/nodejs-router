#!/usr/bin/env node

// TODO: package.json to define as npm module
// TODO: detect if certbot is installed, crash if --acme-challenge but no certbot installed
// TODO: automatically fill config defaults
// TODO: add manual/readme from --help

const fs = require('fs');
const http = require('http');
const https = require('https');
const tls = require('tls');
const path = require('path');
const util = require('util');
const acme_challenge = require('./acme_challenge.js');

const DEFAULT_CONFIG_PARSER = JSON;
const DEFAULT_TLS_KEY_PATH = '/etc/router/default.key';
const DEFAULT_TLS_CERT_PATH = '/etc/router/default.crt';
const DEFAULT_CONFIG_FILE = '/etc/router/<port>.json';
const DEFAULT_LISTEN_HOST = '::';
const DEFAULT_LISTEN_PORT = 80;

function print_usage()
{
	console.log([
	     // '--------------------------------------------------------------------------------',
		'Usage: ' + process.argv.slice(0, 2).join(' ') + ' [OPTIONS] [[bind-host:]listen-port]',
		'',
		'Where',
		' listen-port defaults to "' + DEFAULT_LISTEN_PORT + '".',
		' bind-host defaults to "' + DEFAULT_LISTEN_HOST + '".',
		'',
		' Use host "::" to listen on every interface for both IPv4 and IPv6.',
		'',
		'OPTIONS',
		'',
		' -c,--config <file>  Path to configuration file of this instance.',
		'                     Defaults to: "' + DEFAULT_CONFIG_FILE + '"',
		' --no-tls            Disable TLS layer. This is the default.',
		'                     Overrides any option that may enable TLS.',
		' --tls               Enable TLS layer.',
		' --tls-key <file>    Specify default TLS key (override by a virtual host).',
		'                     Defaults to: "' + DEFAULT_TLS_KEY_PATH + '"',
		' --tls-cert <file>   Specify default TLS certificate (override by a virtual',
		'                     host).',
		'                     Defaults to: "' + DEFAULT_TLS_CERT_PATH + '"',
		' --acme-challenge    Enable a ACME challenge server as a virtual host.',
		'                     Implies --tls',
		'                     Runs on any freely available port.',
		'                     Matches only for path: "/.well-known/acme-challenge/"',
		'                     Matches any virtual host.',
		' -h,[-[-]]help       Show this help.',
		'',
		'',
		'CONFIG',
		'',
		'{',
		'  debug: true               ',
		'  proxy: <proxy>            If false, overwrites X-Forwarded-* headers.',
		'  acmeChallenge: {          Only used if --acme-challenge has been set.',
		'    host: <host-match>      Only apply ACME challenge for matching hosts.',
		'          [<host-match>]    Defaults to: "*"',
		'    renewInterval: 2419200  Number of seconds to auto-renew certificates.',
		'                            Any falsy value (like 0) disables auto-renewal.',
		'                            Defaults to: 2419200 (28 days).',
		'    renewRetry: 60          Number of seconds to wait before retrying in',
		'                            case of an error.',
		'  }                         ',
		'  vhosts: [<vhost>]         Apply vhosts in given order to requests.',
		'                            First vhost route that matches, will handle the',
		'                            request, and no further vhosts that might also',
		'                            potentially match are considered anymore.',
		'                            That is even if the matching vhost route fails',
		'                            to give a response.',
		'                            If no vhosts are matched, for HTTP 404 Not Found',
		'                            is returned, and for WebSockets the socket is',
		'                            simply ended and destroyed.',
		'}',
		'',
		'vhost {',
		'  host: <host-match>               Defaults to: "*"',
		'        [<host-match>]             ',
		'  name: <string>                   Set a convenient name to use for logs.',
		'  webmasterEmailAddress: <string>  E-mail address of the webmaster, for',
		'                                   receiving feedback on ACME challenges.',
		'  proxy: <proxy>                   Override global default proxy options.',
		'  routes: [<route>]                Apply routes if vhost matches.',
		'}',
		'',
		'route {',
		'  path: "/"',
		'  address: "<route-address>"',
		'  proxy: <proxy>               Override global/vhost default proxy options.',
		'         "<route-address>"',
		'         true',
		'  redirect: "<route-address>"',
		'            true',
		'}',
		'',
		'proxy {',
		'  If proxy is set, any request that matches the route will be proxied to',
		'  the configured route address.',
		'  By default, headers from the original request are copied to the proxy',
		'  request.',
		'  If the original request method is DELETE or OPTIONS',
		'  and the Content-Length header is falsy,',
		'  then the proxy request\'s Transfer-Encoding header is unset,',
		'  and the Content-Length header is set to 0.',
		'',
		'  timeout: 0           Set a socket timeout for the proxy request.',
		'                       Does not apply to WebSockets.',
		'  requestTimeout: 0    Set a socket timeout for the original request.',
		'                       Does not apply to WebSockets.',
		'  changeOrigin: false  ',
		'  headers: {}          Overwrite HTTP headers for the proxy request.',
		'                       ',
		'  trustProxy: true     If false, overwrites X-Forwarded-* headers.',
		'',
		'                     > From node:http.request(...), for HTTP/HTTPS:',
		'  method               Override the HTTP original request method.',
		'  socketPath           Unix domain socket.',
		'  localAddress         Local interface to bind for network connections.',
		'  auth                 Set HTTP Basic Authorization ("<user>:<password>").',
		'',
		'                     > From node:https.request(...), for HTTPS:',
		'  pfx                  PFX or PKCS12 encoded private key and cert chain.',
		'  passphrase           Shared passphrase used for private key and/or PFX.',
		'  key                  Private keys in PEM format.',
		'  cert                 Cert chains in PEM format.',
		'  ca                   Optionally override the trusted CA certificates.',
		'                       Defaults to: well-known CAs curated by Mozilla.',
		'  rejectUnauthorized   Server cert is verified against the given CAs.',
		'                       Defaults to: true',
		'  ciphers              Cipher suite specification, replacing the default.',
		'  minVersion           Optionally set the minimum TLS version to allow.',
		'                       Defaults to: "' + tls.DEFAULT_MIN_VERSION + '"',
		'  maxVersion           Optionally set the maximum TLS version to allow.',
		'                       Defaults to: "' + tls.DEFAULT_MAX_VERSION + '"',
		'}',
		'',
		'route-address {',
		'  If route address is a string, it must encode a URL.',
		'  If route address is an object, it must encode a URL like so:',
		'  protocol: <string>   Set a fixed protocol.',
		'  hostname: <string>   Set a fixed hostname.',
		'  port: <int>          Set a fixed port.',
		'  pathname: <string>   Set the pathname.',
		'  ',
		'  Any query string or hash (anchor) is ignored.',
		'  ',
		'  For a redirect, if the protocol or port is given, the hostname defaults',
		'  to the host from the original request.',
		'  For a proxy request, the hostname defaults to "localhost".',
		'  For a proxy request, the port defaults to 80, or 443 when using TLS.',
		'  ',
		'}',
		'',
		'host-match {',
		'  If host match is a string, the match is literal, except for the use of a',
		'  wildcard character (*). The wildcard matches any (empty) string, except',
		'  for the dot character (.). Therefore,',
		'    - to match any IPv4 address, use: *.*.*.*',
		'    - every subdomain level must be separately matched:',
		'      example.org, *.example.org, *.*.example.org, ...',
		'  ',
		'  If host match is an object, it must encode a RegExp like so:',
		'  type: "RegExp"         Must be set literally, case-sensitive, not optional.',
		'  pattern: <string>      RegExp pattern, do not put between forward slashes.',
		'  flags: <string>        RegExp flags.',
		'                         Defaults to: "i"',
		'}',
		'',
		'',
		'SIGNALS',
		'',
		'  SIGHUP      Reload configuration from filesystem. A new configuration is only',
		'              applied if it contains no errors. If an error occurs, the current',
		'              configuration remains, and a warning or error message is printed.',
		'',
		'  SIGUSR1     Print the current configuration.',
		'',
		'  SIGUSR2     Renew certificates. Requires TLS and ACME challenge options to be',
		'              enabled. These options cannot be dynamically changed.',
		'',
		'',
		'NOTES',
		'',
		'', // TODO: behavior for certain error handling stuff
		'', // TODO: about ACME challenge, and its certbot dependency
		'  Instead of JSON, JINI might be more human-friendly. But must be installed',
		'  separately (npm install jini).',
		'',
		'EXAMPLES',
		'',
		'',
		' 1. Forward port 80 to 443 using a JSON configuration:',
		'',
		'    router :80',
		'',
		'    {',
		'      "vhosts": [',
		'        {',
		'          "host": ["example.org", "*.example.org"],',
		'          "routes": [',
		'            {"redirect": "https://localhost:443"}',
		'          ]',
		'        }',
		'      ]',
		'    }',
		'',
		'    Note: This redirects to "localhost", which means that the server locally',
		'    listening at :443 must support both IPv4 and IPv6 connections depending',
		'    on the client connection.',
		'',
		' 2. Forward apps to different webservers for the same domain.',
		'',
		'    router --tls :443',
		'',
		'    {',
		'      "vhosts": [',
		'        {',
		'          "host": ["example.org", "*.example.org"],',
		'          "routes": [',
		'            {"path": "/app1", "address": ":8081"},',
		'            {"path": "/app2", "address": ":8082"},',
		'            {"path": "/app3", "address": ":8082/some/base-path"},',
		'            {"address": ":8080"}',
		'          ]',
		'        }',
		'      ]',
		'    }',
		'',
		'    Note: The first matching path takes all. Even if the proxied server does not',
		'    handle the request, or returns a request error (i.e. HTTP status 404, 500).',
		'',
		'    Note: The last route is a catch-all, where the default path ("/") will match',
		'    any path. The path could also have explicitly been set as "/" for clarity.',
		'',
		'    Note: A request to:',
		'      https://example.org/app3/sub/path',
		'    will be proxied to',
		'      http://localhost:8082/some/base-path/sub/path',
		'',
		'    Note: If no catch-all is defined for a vhost, it is possible that if no',
		'    route matched, another vhost may still match that route provided that the',
		'    vhost also matches the request host.',
		'    Therefore, both the order of vhosts and the order of routes is important.',
		'',
		''
	].join('\n'));
}

async function parse_args()
{
	var opts = {
		config_file: DEFAULT_CONFIG_FILE,
		listen_host: DEFAULT_LISTEN_HOST,
		listen_port: DEFAULT_LISTEN_PORT,
		tls: null
	};
	
	// parse command-line arguments
	for(var i=2;i<process.argv.length;++i)
	{
		var arg = process.argv[i];
		
		// check if we want to print help
		if(arg === '-h' || arg === '--help' || arg === '-help' || arg === 'help')
		{
			print_usage();
			return process.exit(0);
		}
		// match config argument
		else if(arg === '-c' || arg === '--config')
		{
			var argv = process.argv[++i];

			opts.config_file = argv;
		}
		// match tls enable or disable
		else if(arg === '--no-tls' || arg === '--no-ssl')
		{
			opts.tls = false;
		}
		else if(arg === '--tls' || arg === '--ssl')
		{
			opts.tls = true;
		}
		// set custom key/cert
		else if(arg === '--tls-key')
		{
			var argv = process.argv[++i];
			
			opts.tls_key = argv;
		}
		else if(arg === '--tls-cert')
		{
			var argv = process.argv[++i];
			
			opts.tls_cert = argv;
		}
		// setup an acme-challenge server
		else if(arg === '--acme-challenge')
		{
			opts.acme_challenge = true;
		}
		// match port (no argument, but possibly with host, or with leading colon :1234)
		else if(/^(|[^-]+.*:|:)[0-9]+$/g.test(arg))
		{
			opts.listen_host = arg.replace(/(:|)[0-9]+$/gi, '').trim() || opts.listen_host;
			opts.listen_port = parseInt(arg.replace(/^.*[^0-9]/g, '')) || opts.listen_port;
		}
		else
		{
			console.log('error: Failed to parse argument: ' + arg);
			return process.exit(1);
		}
	}
	
	// tls is enabled if not explicitly disabled and either --tls flag is provided or --tls-key/--tls-cert is specified
	opts.tls = opts.tls !== false && !!(opts.tls || (opts.tls_key && opts.tls_cert));
	
	// now we set defaults for tls_key and tls_cert
	opts.tls_key = opts.tls_key || DEFAULT_TLS_KEY_PATH;
	opts.tls_cert = opts.tls_cert || DEFAULT_TLS_CERT_PATH;
	
	return opts;
}
async function parse_config(opts)
{
	var config = {};
	
	// load and parse config
	if(typeof opts.config_file === 'string')
	{
		try
		{
			var filename = opts.config_file.replace('<port>', opts.listen_port);
			var cfg = DEFAULT_CONFIG_PARSER;

			if(filename.endsWith('.jini') || filename.endsWith('.ini'))
			{
				cfg = require('jini');
			}
			else if(filename.endsWith('.json'))
			{
				cfg = JSON;
			}
			// else: use default
			
			config = cfg.parse(await fs.promises.readFile(filename, {encoding: 'utf8'}));
		}
		catch(err)
		{
			throw err;
		}
	}
	
	// enfore 'camelCase' (from camel_case or CamelCase) for all keys
	function fix_keys(obj)
	{
		for(const k in obj)
		{
			const v = obj[k];
			
			if(!Array.isArray(obj))
			{
				var old_key = k;
				
				// if using underscores, convert to CamelCase
				const keyparts = k.split('_');
				if(keyparts.length > 1)
				{
					k = keyparts.map(k => k.length > 0 ? k.charAt(0).toUpperCase() + k.slice(1) : k).join('');
				}
				
				// enforce first character of the key to be lowercase
				if(/^[A-Z]/.test(k))
				{
					k = k.charAt(0).toLowerCase() + k.slice(1);
				}
				
				// apply new key
				if(k !== old_key)
				{
					delete obj[old_key];
					obj[k] = v;
				}
			}
			
			if(typeof v === 'object' && v !== null)
			{
				fix_keys(v);
			}
		}
	}
	fix_keys(config);
	
	// ensure acmeChallenge exists
	if(typeof config.acmeChallenge !== 'object' || config.acmeChallenge === null) config.acmeChallenge = {};
	
	if(!('renewInterval' in config.acmeChallenge)) config.acmeChallenge.renewInterval = 0;
	
	if(!config.acmeChallenge.renewRetry) config.acmeChallenge.renewRetry = 60;
	
	// ensure vhosts array exists
	if(!Array.isArray(config.vhosts)) config.vhosts = [];
	
	// ensure trustProxy boolean value, defaults to false
	config.trustProxy = !!config.trustProxy;
	
	// ensure debug boolean value, defaults to true
	config.debug = 'debug' in config ? !!config.debug : true;
	
	// ensure correct configuration for vhosts
	for(var i=0;i<config.vhosts.length;++i)
	{
		var vhost = config.vhosts[i];
		
		// ensure default host: '*'
		if(!('host' in vhost)) vhost.host = '*';
		
		var routes = vhost.routes;
		if(!Array.isArray(routes))
		{
			if('routes' in vhost)
			{
				throw new Error('vhosts[' + i + '] has an invalid routes property (' + vhost.routes + '), must be an Array');
			}
			
			// initialize an empty Array
			routes = vhost.routes = [];
		}
		
		for(var j=0;j<routes.length;++j)
		{
			var route = routes[j];
			
			// ensure default path: '/'
			if(!('path' in route)) route.path = '/';
			
			
		}
	}
	
	return config;
}

function get_host(req, trustProxy)
{
	// try to use the HTTP header value of X-Forwarded-For
	var req_host = trustProxy ? req.headers['x-forwarded-for'] : null;
	
	if(typeof req_host !== 'string')
	{
		// try to use the HTTP header value of Host
		req_host = req.headers['host'];
	}
	else if(req_host.indexOf(',') !== -1)
	{
		// X-Forwarded-For might have multiple values, if so, only use the first
		// because if a proxy is setup, and it is the first proxy in a chain of trusted proxies
		// then it should overwrite X-Forwarded-For instead of appending to it
		req_host = req_host.substring(0, req_host.indexOf(',')).trimRight();
	}
	
	if(typeof req_host === 'string')
	{
		// trim the port from the end (with IPv6 support)
		var offset = req_host[0] === '[' ? req_host.indexOf(']') + 1 : 0;
		var index = req_host.indexOf(':', offset);
		if(index !== -1)
		{
			req_host = req_host.substring(0, index);
		}
	}
	
	return req_host;
}

// integrated version based on the https://github.com/expressjs/vhost/(index.js) (npm vhost) module
// including support for x-forwarded-for based on https://github.com/expressjs/express/(lib/request.js) (npm express) module
function test_vhost(config, req, matches, trustProxy)
{
	// try to use the HTTP header value of X-Forwarded-For
	const req_host = get_host(req, trustProxy);
	
	// assume false if host is not set and thus unknown
	if(!req_host) return false;

	if(config.debug === true) console.error('debug: Trying to match host in request: ' + req_host + ' with matches: ', matches);
	
	// check if any of the matches can match the req_host
	for(var i=0;i<matches.length;++i)
	{
		var m = matches[i];
		
		m.lastIndex = 0; // reset lastIndex in case g or y flags have been set
		var match = m.exec(req_host);
		
		if(match)
		{
			// set the current request vhost-property
			var obj = Object.create(null);
			obj.host = req.headers.host;
			obj.hostname = req_host;
			obj.length = match.length - 1;
			
			for(var j=1;j<match.length;++j)
			{
				obj[j - 1] = match[j];
			}
			
			req.vhost = obj;

			if(config.debug === true) console.error('debug: vhost matched: ', req.vhost);

			return true;
		}
	}
	
	return false;
}

function test_route(config, req, matches)
{
	if(config.debug === true) console.error('debug: Trying to match route path: ' + matches + ' with request: ' + req.url);
	
	for(var i=0;i<matches.length;++i)
	{
		var m = matches[i];
		
		m.lastIndex = 0; // reset lastIndex in case g or y flags have been set
		var match = m.exec(req.url);
		
		if(match)
		{
			if(config.debug === true) console.error('debug: route matched: ' + m);
			
			return true;
		}
	}
	
	return false;
}

// key must be 'local' or 'remote'
function test_address_whitelist(config, req, key, matches)
{
	var reqSocketAddress = req.socket[key + 'Address'];
	
	if(config.debug === true) console.error('debug: Trying to match ' + key + 'Address in request: ' + reqSocketAddress);
	
	var found = false;
	for(var i=0;i<matches.length;++i)
	{
		var m = matches[i];
		
		m.lastIndex = 0; // reset lastIndex in case g or y flags have been set
		var match = m.exec(reqSocketAddress);
		
		if(match)
		{
			if(config.debug === true) console.error('debug: ' + key + 'Address matched: ' + m);
			
			return true;
		}
	}
	
	return false;
}


function create_chain(stack)
{
	return function chain()
	{
		const args = Array.from(arguments);
		var index = -1;
		
		function next()
		{
			if(++index < stack.length) stack[index].apply(null, args);
		}
		
		args.push(next);
		next();
	};
}

function create_http_header(line, headers)
{
	return Object
		.keys(headers)
		.reduce(
			function(head, key)
			{
				var value = headers[key];
				
				if(!Array.isArray(value)) value = [value];
				
				for(var i=0;i<value.length;++i)
				{
					head.push(key + ': ' + value[i]);
				}
				return head;
			},
			[line]
		).join('\r\n') + '\r\n\r\n';
}

function create_proxy_request(req, socket, targetURL, proxy)
{
	// set protocol, and determine if using TLS, defaults to no
	const protocol = targetURL.protocol || (socket.encrypted ? 'https:' : 'http:');
	const targetIsTLS = protocol === 'https:';
	
	// note: socketPath is not allowed when targetIsTLS is true
	const allowed_opts = [
		'method',
		'socketPath',
		'localAddress',
		'auth'
	].concat(targetIsTLS ? [
		'pfx',
		'passphrase',
		'key',
		'cert',
		'ca',
		'rejectUnauthorized',
		'ciphers',
		'minVersion',
		'maxVersion'
	] : []);
	
	// only keep properties given in the array
	const req_opts = Object.fromEntries(allowed_opts.map(k => [k, proxy[k]]));
	
	// unless using Unix Domain Socket (socketPath refers to tls.connect's path option)
	if(!req_opts.socketPath)
	{
		req_opts.hostname = targetURL.hostname || 'localhost';
		req_opts.port = parseInt(((targetURL.port || '') +'').replace(/^:/, '')) || (targetIsTLS ? 443 : 80);
		req_opts.family = socket.localFamily === 'IPv4' ? 4 : socket.localFamily === 'IPv6' ? 6 : 0;
	}

	// copy request method, unless specifically specified to override
	if(typeof req_opts.method !== 'string') req_opts.method = req.method;
	
	// combine pathname (is never empty, is always at least '/') with the req.url which is stripped from its root path at the very least (strip if empty, is at least '/')
	// careful, when prefix is stripped, then the target application cannot reproduce original URL's for the client from behind the proxy
	// to allow for this, we send an additional header to the proxy, that provides the proxy app with the path that was stripped
	req_opts.path = targetURL.pathname + (req.url.startsWith(targetURL.strip) ? req.url.substring(targetURL.strip.length) : req.url);

	console.log(req_opts.path + ' from ' + targetURL.pathname + ' and ' + req.url + ' with strip: ' + targetURL.strip);
	
	// copy request headers, and possibly overwrite with proxy-options headers
	const headers = Object.assign(Object.assign({}, req.headers), proxy.headers);
	
	// if not upgrading, set connection: close (see: https://github.com/http-party/node-http-proxy/blob/master/lib/http-proxy/common.js)
	if(typeof headers.connection !== 'string' || !/(^|,)\s*upgrade\s*($|,)/i.test(headers.connection))
	{
		headers.connection = 'close';
	}
	
	// if changeOrigin, we should overwrite headers.host
	if(proxy.changeOrigin && !req_opts.socketPath)
	{
		headers.host = req_opts.hostname + ':' + req_opts.port;
	}
	
	req_opts.headers = headers;
	
	return (targetIsTLS ? https : http).request(req_opts);
}
function apply_xfwd_headers(headers, trustProxy, proto, addr, port, strip)
{
	// append x-forwarded headers, only if we trust the proxy, otherwise we overwrite
	if(!trustProxy)
	{
		headers['x-forwarded-for'] = addr;
		headers['x-forwarded-port'] = port +'';
		headers['x-forwarded-proto'] = proto;
		headers['x-forwarded-host'] = addr;
		headers['x-forwarded-prefix'] = strip;
	}
	else
	{
		var addr_cur = headers['x-forwarded-for'];
		var port_cur = headers['x-forwarded-port'];
		var proto_cur = headers['x-forwarded-proto'];
		var strip_cur = headers['x-forwarded-prefix'];
		
		headers['x-forwarded-for'] = addr_cur ? (addr_cur + ',' + addr) : addr;
		headers['x-forwarded-port'] = port_cur ? (port_cur + ',' + port) : (port +'');
		headers['x-forwarded-proto'] = proto_cur ? (proto_cur + ',' + proto) : proto;
		headers['x-forwarded-prefix'] = strip_cur ? (strip_cur + ',' + strip) : strip;
		
		headers['x-forwarded-host'] = headers['x-forwarded-host'] || headers.host || '';
	}
}
function parse_matches(matches, customRegExpFn, customWildcardSplitFn, customWildcardJoinFn, filterInputStrFn)
{
	if(!Array.isArray(matches))
	{
		matches = [matches];
	}
	
	// split, flatten, trim, filter empty/null/false/undefined
	matches = matches
		.map(m => typeof m !== 'string' ? m : m
			.split(/[,\r\n]/)
		)
		.flat()
		.map(m =>
		{
			if(typeof m !== 'string')
			{
				return m;
			}
			else
			{
				m = m.trim();

				if(typeof filterInputStrFn === 'function')
				{
					var m_arr = filterInputStrFn(m);
					if(!Array.isArray(m_arr))
					{
						m_arr = [m_arr];
					}
					return m_arr.map(m => typeof m !== 'string' ? m : m
							.split(/[,\r\n]/)
						)
						.flat();
				}
				else
				{
					return m;
				}
			}
		})
		.flat()
		.filter(m => !!m);

	// turn strings into regular expressions
	matches = matches
		.map(m =>
		{
			if(typeof m !== 'string')
			{
				return m;
			}
			else
			{
				var m_arr = typeof customWildcardSplitFn === 'function' ? customWildcardSplitFn(m) : m.split('*');
				
				if(!Array.isArray(m_arr))
				{
					return m_arr;
				}
				else
				{
					// escape regex symbols
					m_arr = m_arr.map(p => p.replace(/[/\-\\^$*+?.()|[\]{}]/g, '\\$&'));
					
					return typeof customWildcardJoinFn === 'function' ? customWildcardJoinFn(m_arr) : m_arr.join('(.*)');
				}
			}
		})
		.map(m =>
		{
			if(typeof m !== 'string')
			{
				return m;
			}
			else
			{
				if(typeof customRegExpFn === 'function')
				{
					return customRegExpFn(m);
				}
				else
				{
					return new RegExp('^' + m + '$', 'i');
				}
			}
		});

	// deserialize existing regular expressions
	matches = matches
		.map(m => typeof m === 'object' && m !== null && m.type === 'RegExp' ? new RegExp(m.pattern || '', m.flags || 'i') : m);

	// remove any non-regex matches
	matches = matches
		.filter(m => typeof m.exec === 'function');

	return matches;
}

function create_app(config, local_server_str)
{
	const http_stack = [];
	const ws_stack = [];

	const http_chain = create_chain(http_stack);
	const ws_chain = create_chain(ws_stack);
	
	// use vhost for every catch
	config.vhosts.forEach(function(v)
	{
		// sub app
		// const p = connect();
		
		var host_matches = parse_matches(
			v.host || '*',
			null,
			m => // split
			{
				// a single '*' should match any domain:
				m = m === '*' ? new RegExp('^.*$', 'i') : m;
				
				return typeof m !== 'string' ? m : m.split('*');
			},
			m => // join
			{
				// note: *.example.org does not match example.org or sub.any.example.org
				return m.join('([^.]+)');
			}
		);
		
		// store normalized hostname for later use
		v._hostname = v.name || host_matches.map(m => ''+ m).join(', ');
		
		// store preprocessed matches for later use
		v._host_matches = host_matches;
		
		// possibly add {address,redirect} routes (path = source, address = destination)
		// array may be specified, or directly address/redirect route (path is always / in this case, since it is the only route for the given host)
		var routes = v.routes || [];
		
		// for each route
		routes.forEach(function(subroute)
		{
			var trustProxy = false;
			if(subroute.proxy && ('trustProxy' in subroute.proxy)) trustProxy = subroute.proxy.trustProxy;
			else if(v.proxy && ('trustProxy' in v.proxy)) trustProxy = v.trustProxy;
			else if(config.proxy && ('trustProxy' in config.proxy)) trustProxy = config.trustProxy;
			
			var path_matches = parse_matches(
				subroute.path || '/',
				// note: /aoeu does not match /aoeux, since /aoeu implies /aoeu$ or /aoeu/*, in order to match any prefix, use the wildcard like so: /aoeu*
				m => new RegExp('^' + m + (m.endsWith('/') ? '.*' : '(|/.*)') + '$', 'i')
			);
			
			// usage: {redirect: <address>}, {redirect: true, address: <address>}, {address: <address>}, {redirect: {code: 302}, address: <address>}
			// usage: {proxy: {auth: ...}, address: <address>}
			// if only an address is given, proxy is implied
			const targetAddr = subroute.address || subroute.redirect || subroute.proxy;
			var targetURL = null;
			if(typeof targetAddr === 'string')
			{
				if(targetAddr.indexOf('://') === targetAddr.length - 3 || targetAddr.endsWith(':') === targetAddr.length - 1)
				{
					targetURL = {
						protocol: targetAddr
					};
				}
				else
				{
					targetURL = new URL(targetAddr.indexOf('://') === -1 ? 'http://' + targetAddr : targetAddr);
				}
			}
			else
			{
				targetURL = targetAddr;
			}
			if(targetURL)
			{
				targetURL.protocol = ((targetURL.protocol || '') + ':').replace(/:.*$/, '://').replace(/^:\/\/$/, '').replace(/^ws/i, 'http');
				targetURL.hostname = targetURL.hostname || '';
				targetURL.port = (':' + (targetURL.port || '')).replace(/^:$/, '');
				// remove trailing '/' from pathname, since req.url will be added, which is always at least starting with '/'
				targetURL.pathname = targetURL.pathname || '/'; // = path without querystring
				targetURL.strip = subroute.strip || '/';
				// querystring is not supported: it is not easy to configure/understand how a custom querystring would be merged with an existing request's querystring
			}
			
			// add support for allowing only certain local or remote IP-addresses
			// important note: an empty whitelist is a special whitelist, which means that anyone is allowed
			//                 which prevents the need for distinction of explicit declaration of this property in the configuration
			//                 anyway, denying everyone is probably a bad configuration anyway, as the service could also simply be turned off
			var localAddressWhitelist = parse_matches(subroute.localAddressWhitelist || v.localAddressWhitelist || config.localAddressWhitelist || [], null, null, null, str => str === 'localhost' ? '::ffff:127.0.0.1,127.0.0.1' : str);
			var remoteAddressWhitelist = parse_matches(subroute.remoteAddressWhitelist || v.remoteAddressWhitelist || config.remoteAddressWhitelist || [], null, null, null, str => str === 'localhost' ? '::ffff:127.0.0.1,127.0.0.1' : str);
			
			// set subroute.proxy.socketPath if protocol is file
			console.log('info: CONFIG ROUTE: ', subroute);

			// handle redirect
			if(subroute.redirect)
			{
				if(subroute.proxy)
				{
					throw new Error('Syntax error: Both redirect and proxy defined, at route. These options are mutually exclusive.');
				}
				
				const redirectCode = (typeof subroute.redirect === 'object' ? subroute.redirect.code : typeof subroute.redirect === 'number' ? parseInt(subroute.redirect) : 0) || 302;
				
				// if location is explicitly defined, then this is a literal string to pass in the Location header
				var literalTargetLocation = subroute.redirect.location;
				
				// construct Location value
				var targetLocation = '';
				if(targetURL)
				{
					// if proto, host, or port is given, autofill the rest
					if(targetURL.protocol || targetURL.hostname || targetURL.port)
					{
						targetLocation += targetURL.protocol + (targetURL.hostname || '<host>') + targetURL.port;
					}
					
					// add path and query, autofill path
					targetLocation += targetURL.pathname + '<url>';
				}
				
				if(!targetLocation && !literalTargetLocation)
				{
					throw new Error('Syntax error: No redirect.location or address configured, at route redirect.');
				}
				
				console.log('info: ' + local_server_str + ' will redirect: ' + v._hostname + '' + JSON.stringify(path_matches) + ' -> ' + (literalTargetLocation || targetLocation));
				
				http_stack.push(function(req, res, next)
				{
					// skip if request host does not match vhost
					if(!test_vhost(config, req, host_matches, trustProxy)) return next();
					
					// skip if request path does not match subroute path
					if(!test_route(config, req, path_matches)) return next();

					// skip if request socket localAddress does not match respective subroute whitelist
					if(localAddressWhitelist.length > 0 && !test_address_whitelist(config, req, 'local', localAddressWhitelist)) return next();

					// skip if request socket remoteAddress does not match respective subroute whitelist
					if(remoteAddressWhitelist.length > 0 && !test_address_whitelist(config, req, 'remote', remoteAddressWhitelist)) return next();
					
					// apply redirect
					res.writeHead(redirectCode, {
						'Location': literalTargetLocation ||
						            targetLocation
						                .replace(/<(domain|domainname|host|hostname)>/gi, req.vhost.hostname)
						                .replace(/([/]|)<(url)>/gi, ($0, $1) => (req.url || '')) // note: consume slash before <url> when possible, since req.url always starts with a slash
					});
					res.end(); // optional message that says a redirect is sent? or maybe even use HTML?
				});
			}
			// handle address (proxy by default)
			else if(targetURL)
			{
				console.log('info: ' + local_server_str + ' will reroute: ' + v._hostname + '' + JSON.stringify(path_matches) + ' -> ' + targetAddr);
				
				// grab proxy options
				var route_opts = typeof subroute.proxy === 'object' ? subroute.proxy : null;
				var vhost_opts = typeof v.proxy === 'object' ? v.proxy : null;
				
				const proxy = Object.assign(Object.assign({}, vhost_opts), route_opts);
				
				http_stack.push(function(req, res, next)
				{
					// skip if request host does not match vhost
					if(!test_vhost(config, req, host_matches, trustProxy)) return next();
					
					// skip if request path does not match subroute path
					if(!test_route(config, req, path_matches)) return next();
					
					// skip if request socket localAddress does not match respective subroute whitelist
					if(localAddressWhitelist.length > 0 && !test_address_whitelist(config, req, 'local', localAddressWhitelist)) return next();

					// skip if request socket remoteAddress does not match respective subroute whitelist
					if(remoteAddressWhitelist.length > 0 && !test_address_whitelist(config, req, 'remote', remoteAddressWhitelist)) return next();
					
					// if not set yet, set Content-Length header to 0 if request method is DELETE or OPTIONS
					if((req.method === 'DELETE' || req.method === 'OPTIONS') && !req.headers['content-length'])
					{
						req.headers['content-length'] = '0';
						delete req.headers['transfer-encoding'];
					}
					
					const socket = req.socket;
					
					// set timeout of the request socket
					if(proxy.requestTimeout)
					{
						socket.setTimeout(proxy.requestTimeout);
					}
					
					var addr = socket.remoteAddress;
					var port = socket.remotePort;
					var proto = req.isSpdy || socket.encrypted ? 'https' : 'http';
					
					apply_xfwd_headers(req.headers, trustProxy, proto, addr, port, targetURL.strip);

					// forward request
					const proxyReq = create_proxy_request(req, socket, targetURL, proxy);
					
					// this is the timeout of the proxy request
					if(proxy.timeout)
					{
						// outgoing timeout
						proxyReq.setTimeout(proxy.timeout, function()
						{
							proxyReq.abort();
						});
					}
					
					// if request was aborted, then abort proxyRequest as well
					req.on('aborted', function()
					{
						proxyReq.abort();
					});
					
					function onProxyError(err, context)
					{
						console.error('proxy.onError (subRoute = ' + JSON.stringify(path_matches) + '): ' + req.protocol + ':' + req.url + ' --> ' + targetAddr);
						
						if(req.socket.destroyed && err.code === 'ECONNRESET')
						{
							proxyReq.abort();
						}
						
						if(!res.headersSent)
						{
							// note: be careful to not leak information about internal architecture to the public
							res.writeHead(500, {'Content-Type': 'text/plain'});
							res.end('[router] Warning: Proxy error for virtual host at: ' + (req.originalUrl || req.url) + ', headers: ' + JSON.stringify(req.headers) + '\n');
						}
						
						// proxy connection may have been interrupted, since headers were sent already
						// don't just end, but destroy, to let the other party know something went wrong
						res.socket.destroySoon();
					}
					
					req.on('error', err => onProxyError(err, 'request'));
					proxyReq.on('error', err => onProxyError(err, 'proxy request'));
					
					// pipe request to proxy
					req.pipe(proxyReq);
					
					// wait for response
					proxyReq.on('response', function(proxyRes)
					{
						if(!res.headersSent)
						{
							// if HTTP 1.0 request, remove chunk headers
							if(req.httpVersion === '1.0')
							{
								delete proxyRes.headers['transfer-encoding'];
							}
							
							// if HTTP 1.0 request, set correct connection header (or fallback to keep-alive)
							if(req.httpVersion ===  '1.0')
							{
								proxyRes.headers.connection = req.headers.connection || 'close';
							}
							else if(req.httpVersion !== '2.0' && !proxyRes.headers.connection)
							{
								proxyRes.headers.connection = req.headers.connection || 'keep-alive';
							}
							
							// optionally rewrite host here, implement hostRewrite, autoRewrite, protocolRewrite
							
							// implement cookieDomainRewrite, cookiePathRewrite, preserveHeaderKeyCase
							
							// copy headers from proxyRes to res
							const proxyRawHeaders = proxyRes.rawHeaders;
							for(var i=0;i<proxyRawHeaders.length;++i)
							{
								res.setHeader(proxyRawHeaders[i].trim(), proxyRawHeaders[++i]);
							}
							
							// copy statusCode from proxyRes
							res.statusCode = proxyRes.statusCode;
							if(proxyRes.statusMessage) res.statusMessage = proxyRes.statusMessage;
						}
						
						if(!res.finished)
						{
							proxyRes.on('end', function()
							{
								// log that proxy response was finished (we could keep an accurate count of current proxy requests, and request it with SIGUSR1)
							});
							
							proxyRes.pipe(res);
						}
						else
						{
							// log that proxy response was finished
						}
					});
				});

				// proxy websocket (see: https://github.com/http-party/node-http-proxy/blob/master/lib/http-proxy/passes/ws-incoming.js)
				ws_stack.push((req, socket, head, next) =>
				{
					// check method and header
					if(req.method !== 'GET' || !req.headers.upgrade || req.headers.upgrade.toLowerCase() !== 'websocket') return next();
					
					// skip if request host does not match vhost
					if(!test_vhost(config, req, host_matches, trustProxy)) return next();
					
					// skip if request path does not match subroute path
					if(!test_route(config, req, path_matches)) return next();
					
					// skip if request socket localAddress does not match respective subroute whitelist
					if(localAddressWhitelist.length > 0 && !test_address_whitelist(config, req, 'local', localAddressWhitelist)) return next();

					// skip if request socket remoteAddress does not match respective subroute whitelist
					if(remoteAddressWhitelist.length > 0 && !test_address_whitelist(config, req, 'remote', remoteAddressWhitelist)) return next();
					
					var addr = socket.remoteAddress;
					var port = socket.remotePort;
					var proto = socket.encrypted ? 'wss' : 'ws';
					
					apply_xfwd_headers(req.headers, trustProxy, proto, addr, port, targetURL.strip);
					
					// prepare socket
					socket.setTimeout(0);
					socket.setNoDelay(true);
					socket.setKeepAlive(true, 0);
					
					if(head && head.length) socket.unshift(head);
					
					const proxyReq = create_proxy_request(req, socket, targetURL, proxy);
					
					// emit proxyReqWs ...
					
					function onProxyError(err)
					{
						console.error('proxy.onError (subRoute = ' + JSON.stringify(path_matches) + '): ' + req.protocol + ':' + req.url + ' --> ' + targetAddr);
						socket.destroySoon();
					}
					
					proxyReq.on('error', onProxyError);
					proxyReq.on('response', function(proxyRes)
					{
						if(!proxyRes.upgrade)
						{
							socket.write(create_http_header('HTTP/' + proxyRes.httpVersion + ' ' + proxyRes.statusCode + ' ' + proxyRes.statusMessage, proxyRes.headers));
							proxyRes.pipe(socket);
						}
					});
					
					proxyReq.on('upgrade', function(proxyRes, proxySocket, proxyHead)
					{
						// emit wsClose:
						// proxySocket.on('end', function(){});
						
						// prepare socket
						proxySocket.setTimeout(0);
						proxySocket.setNoDelay(true);
						proxySocket.setKeepAlive(true, 0);
						
						if(proxyHead && proxyHead.length) proxySocket.unshift(proxyHead);
						
						socket.write(create_http_header('HTTP/1.1 101 Switching Protocols', proxyRes.headers));

						// emit wsOpen ...
						
						// pipe both ways, and catch errors:
						
						proxySocket.on('error', onProxyError);
						socket.on('error', function()
						{
							proxySocket.end();
						});
						proxySocket.pipe(socket).pipe(proxySocket);
					});
					proxyReq.end();
				});
			}
		});
	});
	
	// final virtual host catch-all:
	http_stack.push((req, res, next) =>
	{
		console.error('warning: No virtual host matched for request (' + local_server_str + '): ' + req.url + ', headers: ' + JSON.stringify(req.headers));
		
		if(!res.headersSent)
		{
			// note: be careful to not leak information about internal architecture to the public
			res.writeHead(404);
			res.end('[router] Warning: No virtual host matched for request: ' + req.url + ', headers: ' + JSON.stringify(req.headers) + '\n');
		}
		
		next();
	});
	
	ws_stack.push((req, socket, head, next) =>
	{
		console.error('warning: No virtual host matched for upgrade (' + local_server_str + '): ' + req.url + ', headers: ' + JSON.stringify(req.headers));
		
		socket.destroySoon();
		
		next();
	});

	
	return {
		http: http_chain,
		ws: ws_chain
	};
}

async function create_sni_callback(server_opts, tls_conf, vhosts, has_acme_challenge, config_debug)
{
	const cache = {};
	async function get_cached_file(filename)
	{
		if(!filename) return null;
		
		const cached = cache[filename];
		
		if(cached)
		{
			try
			{
				return await cached;
			}
			catch(err)
			{
				// failed to read file, don't throw error, instead, try again
			}
		}
		
		return cache[filename] = fs.promises.readFile(filename);
	};
	async function tls_read_files(host_tls_array)
	{
		const errors = [];
		
		for(var i=0;i<host_tls_array.length;++i)
		{
			const host_tls = host_tls_array[i];
			
			try
			{
				// mark for this function (and any other parallel requests!) we are working on it
				if(config_debug === true) console.error('debug: Reading configured files in async (' + JSON.stringify(host_tls) + ').');
				
				const tls_opts = {
					key: await get_cached_file(host_tls.key),
					cert: await get_cached_file(host_tls.cert)
				};
				
				// optional: add ca
				if(host_tls.ca) tls_opts.ca = await get_cached_file(host_tls.ca);
				
				return tls.createSecureContext(tls_opts);
			}
			catch(err)
			{
				errors.push({
					host_tls: host_tls,
					error: err
				});
				if(config_debug === true) console.error('debug: Error (' + (err ? err.code : 'undefined') + ') while reading configured files (' + JSON.stringify(host_tls) + ').');
			}
		}
		
		throw (errors.length > 0 ? errors : new Error('Failed to find or load any TLS certificates.'));
	};
	
	const tls_lookup = {};
	
	return async function(domain, cb)
	{
		// once a secureContext is set, it will keep on using this certificate from memory
		// by sending a signal to the process, we can reload these by clearing the cache
		var secureContext = tls_lookup[domain];
		
		// if secureContext is a promise, wait for it, and check if it's fulfilled
		if(secureContext && typeof secureContext.then === 'function')
		{
			try
			{
				// wait until promise resolves
				return cb(null, await secureContext);
			}
			catch(err)
			{
				// promise rejected, try again
				secureContext = false;
			}
		}
		
		// if secureContext is falsy, grab the right TLS-certificate
		if(!secureContext)
		{
			for(var i=0;i<vhosts.length;++i)
			{
				const v = vhosts[i];
				const matches = v._host_matches;
				
				var found = false;
				for(var j=0;j<matches.length;++j)
				{
					const m = matches[j];
					
					m.lastIndex = 0; // reset lastIndex in case g or y flags have been set
					
					if(m.exec(domain))
					{
						found = true;
						break;
					}
				}

				if(!found) continue;
				
				const host_tls_array = [];
				
				// override any tls setting by a custom certificate in the vhost
				const vhost_tls = v.tls || v.ssl || null;
				if(typeof vhost_tls === 'object' && vhost_tls !== null && typeof vhost_tls.key === 'string' && typeof vhost_tls.cert === 'string')
				{
					host_tls_array.push(vhost_tls);
				}
				
				// fallback to acme_challenge default path, even when acme_challenge is not enabled, it cannot hurt to check its location (maybe it is used/enabled externally)
				host_tls_array.push(acme_challenge.getCertificate(domain));
				
				if(config_debug === true) console.error('debug: Dynamically loading custom TLS/SSL for domain (' + domain + ') which matched: ' + JSON.stringify(v.host) + '.');
				
				// grab the first TLS certificate that can be read
				tls_lookup[domain] = tls_read_files(host_tls_array);
				
				try
				{
					tls_lookup[domain] = secureContext = await tls_lookup[domain];
					
					if(secureContext) return cb(null, secureContext);
				}
				catch(err)
				{
					if(config_debug === true) console.error('debug: Failed to load TLS Certificate/Key files for request domain (' + domain + '):');
					if(config_debug === true) console.error(err);
					
					// automatically create a certificate for this domain, since it does not exist, only if acme_challenge is enabled through Router
					if(has_acme_challenge)
					{
						if(config_debug === true) console.error('debug: Going to create a new missing certificate for request domain (' + domain + ').');
						try
						{
							await acme_challenge.createCertificate({
								// for the given domain that matched this vhost:
								domain: domain,
								email: v.webmasterEmailAddress || false
							});
						
							if(config_debug === true) console.error('debug: Dynamically loading newly created certificate for domain (' + domain + ').');
							
							// try again, but only for the acme_challenge certificate
							tls_lookup[domain] = tls_read_files([acme_challenge.getCertificate(domain)]);
							
							try
							{
								tls_lookup[domain] = secureContext = await tls_lookup[domain];
								
								if(secureContext) return cb(null, secureContext);
							}
							catch(err_sub_sub)
							{
								if(config_debug === true) console.error('debug: Failed to load newly created certificate file for request domain (' + domain + '):');
								if(config_debug === true) console.error(err_sub_sub);
							}
						}
						catch(err_sub)
						{
							if(config_debug === true) console.error('debug: Failed to create new certificate for request domain (' + domain + '):');
							if(config_debug === true) console.error(err_sub);
						}
					}
				}
			}
		}
		
		if(!secureContext)
		{
			// no key/cert available for this domain
			if(config_debug === true) console.error('debug: No TLS Certificate/Key files available for request domain (' + domain + '). Fallback to default global TLS/SSL files.');
			secureContext = false;
		}
		
		// a falsy secureContext will lead to using the default
		cb(null, secureContext);
	};
}

(async function main()
{
	try
	{
		const router_opts = await parse_args();
		const server_opts = {};
		const local_server_str = (router_opts.listen_host === '::' ? '' : (router_opts.listen_host || '')) + ':' + router_opts.listen_port;

		var app = null;
		var config = null;
		var sni_callback = null;
		var acme_challenge_port = 0;
		
		// create acme_challenge server virtual host, only if TLS is disabled, because acme-challenge uses HTTP (without TLS!)
		if(router_opts.acme_challenge && !router_opts.tls)
		{
			try
			{
				const ac_server = await acme_challenge.createServer();
				ac_server.on('error', err => process.exit(1));
				
				// a random port is chosen, one from the dynamic ports range (typically 32768-60999, or as per RFC 6335 49152-65535)
				acme_challenge_port = ac_server.address().port;
				
				console.log('info: ACME challenge server listening at :' + acme_challenge_port);
			}
			catch(err)
			{
				console.log(err);
				return process.exit(1);
			}
		}
		
		// setup TLS-server options (if applicable)
		if(router_opts.tls)
		{
			// these files cannot be reloaded, or can they? that would depend on the HTTP Server implementation, and thus cannot be relied on (unless the docs specify this as a feature)
			server_opts.key = await fs.promises.readFile(router_opts.tls_key);
			server_opts.cert = await fs.promises.readFile(router_opts.tls_cert);
			server_opts.SNICallback = (domain, cb) => sni_callback ? sni_callback(domain, cb) : cb();
		}

		// create new server instance
		const server = (router_opts.tls ? https : http).createServer(server_opts);
		
		// setup renew certificates timing function
		var renew_certificates_timer;
		var renew_certificates_last_success = 0;
		var renew_certificates_last_attempt = 0;
		async function renew_certificates(manual_override)
		{
			if(!router_opts.acme_challenge)
			{
				console.log('info: Not renewing certificates, acme_challenge option is disabled.');
				return; // certificates cannot be renewed, acme_challenge is not enabled
			}
			
			if(renew_certificates_last_attempt === -1)
			{
				console.log('info: Certificates are still being renewed, not going to renew at this time.');
				return; // already working on it
			}
			
			var t0 = Date.now();
			
			// if manual override, don't check renew_interval_ms
			if(!manual_override)
			{
				var renew_interval_ms = config.acmeChallenge.renewInterval * 1000;
				var renew_retry_ms = (config.acmeChallenge.renewRetry || 60) * 1000;
				
				var renew_delay_ms = renew_interval_ms;
				
				// if last attempt failed, then use renew_retry_ms
				if(renew_certificates_last_success !== renew_certificates_last_attempt)
				{
					renew_delay_ms = Math.min(renew_interval_ms || renew_retry_ms, renew_retry_ms);
				}
				
				if(isNaN(renew_delay_ms) || renew_delay_ms === 0) return console.log('info: No certificate renewal delay set, not automatically renewing. Use acmeChallenge.renewInterval to set a time in seconds to automatically renew certificates.'); // no interval set, don't set timer to renew
				
				if(renew_certificates_last_attempt + renew_delay_ms > t0)
				{
					renew_delay_ms = Math.max(0, renew_delay_ms - (t0 - renew_certificates_last_attempt));
					
					console.log('info: Will renew certificates in ' + parseInt(renew_delay_ms/1000) + ' seconds from now.');
					
					clearTimeout(renew_certificates_timer);
					renew_certificates_timer = setTimeout(renew_certificates, renew_delay_ms);
					return;
				}
				// else: we should already renew now
			}
			
			// mark that we're busy renewing now
			renew_certificates_last_attempt = -1;
			
			try
			{
				console.log('info: Renewing certificates...');
				
				// actually renew certificates:
				await acme_challenge.renewCertificates();
				
				console.log('info: Certificates successfully renewed.');
				
				// set time that we last renewed certificates
				renew_certificates_last_success = t0;
			}
			catch(err)
			{
				// log error
				console.log('error: Failed to renew certificates (' + (err ? (err.code || err.message) : 'undefined') + '):');
				console.log(err);

			}
			
			// mark we're done with our attempt
			renew_certificates_last_attempt = t0;
			
			// check if we must set a timer to renew again
			renew_certificates();
		}
		
		// setup config reloader function including everything that depends on the configuration
		async function reload_config()
		{
			const new_config = await parse_config(router_opts);
			
			// inject acme_challenge virtual host into vhosts if it is enabled
			// by default this will match ANY host, will always come first, and assumes 'localhost' targets the bind address (both ipv4 and ipv6 are supported)
			if(acme_challenge_port > 0)
			{
				new_config.vhosts.unshift({
					host: new_config.acmeChallenge.host || '*',
					routes: [
						{
							path: '/.well-known/acme-challenge/',
							address: 'http://localhost:' + acme_challenge_port
						}
					]
				});
			}
			
			// create app with virtual host and redirect rules
			const new_app = await create_app(new_config, local_server_str);

			// setup TLS-server options, here router_opts.acme_challenge means that on the HTTP/:80 acme-challenge server is running and enabled
			const new_sni_callback = router_opts.tls ? await create_sni_callback(server_opts, new_config.tls, new_config.vhosts, router_opts.acme_challenge, new_config.debug) : null;
			
			// loading complete, now apply...
			
			// apply config
			config = new_config;
			
			// apply app
			if(app)
			{
				server.off('request', app.http);
				server.off('upgrade', app.ws);
			}
			server.on('request', new_app.http);
			server.on('upgrade', new_app.ws);
			app = new_app;
			
			if(router_opts.tls)
			{
				// apply SNICallback
				sni_callback = new_sni_callback;
			}
			if(router_opts.acme_challenge)
			{
				// renew certificates automatically at set intervals (e.g. once per 24 hours), depending on the configuration
				renew_certificates();
			}
		}
		
		// create HTTP server
		server.on('error', err =>
		{
			console.log('error: Router HTTP server instance unexpectedly stopped (' + (err ? err.code : 'undefined') + ').');
			console.log(err);
			process.exit(1);
		});
		
		// listening to clientError is not mandatory, but can be informative to see if clients had any failed requests
		server.on('clientError', err =>
		{
			if(config.debug === true) console.error('debug: Client error (' + (err ? err.code : 'undefined') + ').');
		});
		
		server.on('listening', () => console.log('info: Server listening on ' + local_server_str));
		server.on('close', () => console.log('info: Server stopped.'));
		
		// setup initial config
		try
		{
			await reload_config();
		}
		catch(err)
		{
			console.log('error: Loading configuration failed (' + (err ? (err.code || err.message) : 'undefined') + ').');
			console.log(err);
			return process.exit(1);
		}
		
		// start HTTP server...
		console.log(
			'info: Starting Router HTTP server on ' + local_server_str + 
			(router_opts.tls ? ' with TLS/SSL certificate support (using SNI for per host/domain configured certificates).' : ' without TLS/SSL certificate support.')
		);
		
		server.listen(router_opts.listen_port, router_opts.listen_host);
		
		// reload config on SIGHUP
		var reloading = false;
		process.on('SIGHUP', async () =>
		{
			if(reloading)
			{
				console.log('warning: SIGHUP received: Still busy reloading configuration...');
				return;
			}
			reloading = true;

			console.log('info: SIGHUP received: Reloading configuration...');
			
			try
			{
				await reload_config();
			}
			catch(err)
			{
				console.log('warning: Failed (' + (err ? (err.code || err.message) : 'undefined') + ') to load new configuration (did not apply):');
				console.log(err);
			}
			
			reloading = false;
		});
		
		// setup SIGUSR1 that prints the current configuration
		process.on('SIGUSR1', () =>
		{
			console.log('info: SIGUSR1 received: Printing current configuration:');
			console.log(util.inspect(config, {colors: true, maxArrayLength: Infinity, depth: Infinity, maxStringLength: Infinity}));
		});
		
		// setup SIGUSR2 that renews certificates manually per trigger
		process.on('SIGUSR2', async () =>
		{
			if(router_opts.acme_challenge)
			{
				if(!router_opts.tls)
				{
					console.log('info: SIGUSR2 received: Renewing certificates...');
					
					renew_certificates(true);
				}
				else
				{
					console.log('warning: SIGUSR2 received: Cannot renew certificates, acme_challenge must be renewed on the HTTP (normally :80), because acme_challenge uses HTTP without TLS. This server runs HTTPS.');
				}
			}
			else
			{
				console.log('warning: SIGUSR2 received: Cannot renew certificates, acme_challenge is not enabled. Note: This option can only be enabled through Router command-line arguments, and thus cannot be dynamically changed.');
			}
		});
	}
	catch(err)
	{
		console.log('error: Unexpected error in main().');
		console.log(err);
		process.exit(1);
	}
})();
