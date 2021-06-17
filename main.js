const fs = require('fs');
const http = require('http');
const https = require('https');
const tls = require('tls');
const url = require('url');
const connect = require('connect'); // npm install connect
const vhost = require('vhost'); // npm install vhost
const proxy = require('http-proxy-middleware').createProxyMiddleware; // npm install proxy

var config_filename = 'config.json';
var listen_host = 'localhost';
var listen_port = 80;

// parse command-line arguments
for(var i=2;i<process.argv.length;++i)
{
	var arg = process.argv[i];
	
	// match config argument
	if(arg === '-c' || arg === '--config')
	{
		var argv = process.argv[++i];
		
		if(argv && fs.existsSync(argv))
		{
			config_filename = argv;
		}
		else
		{
			console.error('argument error: No such file or directory (' + argv + '), expected a configuration file after "' + arg + '" (e.g. ' + arg + ' path/to/config.json).');
			process.exit(1);
		}
	}
	// match port (no argument, but possibly with host, or with leading colon :1234)
	else if(/^(|[^-]+.*:|:)[0-9]+$/g.test(arg))
	{
		listen_host = arg.replace(/(:|)[0-9]+$/gi, '').trim() || listen_host;
		listen_port = parseInt(arg.replace(/^.*[^0-9]/g, ''));
	}
}

// load configuration file
var config_data = fs.readFileSync(config_filename);
if(!config_data)
{
	console.error('file error: Failed to read the configuration file (' + config_filename + ').');
	process.exit(1);
}

// parse config
var config;
try
{
    config = JSON.parse(config_data);
}
catch(err)
{
	console.error('parse error: Failed to parse the configuration file (' + config_filename + '). Check your syntax.');
	console.error(err);
	process.exit(1);
}

// a file cache for TLS/SSL certificate files
const filecache = (function()
{
	var cache = {};
	return {
		getSync: function(filename)
		{
			var cached = cache[filename];
			if(cached && typeof cached.then !== 'function')
			{
				return cached;
			}
			return fs.readFileSync(filename);
		},
		get: async function(filename, cb)
		{
			var cached = cache[filename];
			if(cached)
			{
				if(typeof cached.then === 'function')
				{
					if(cb)
					{
						cb(await cached);
						return;
					}
					else
					{
						return cached;
					}
				}
			}
			
			if(cb)
			{
				cb(await (cache[filename] = fs.promises.readFile(filename)));
				return;
			}
			else
			{
				return cache[filename] = fs.promises.readFile(filename);
			}
		}
	};
})();

console.log('info: Running router-server on ' + listen_host + ':' + listen_port + ' ' + (config.tls || config.ssl ? 'with SSL' : 'without SSL'));

// main app
const app = connect();

// use vhost for every catch
config.vhosts.forEach(function(v)
{
	// sub app
	const p = connect();
	
	// grab host value for this vhost
	var host = v.host || '*';
	if(typeof host === 'object')
	{
		if(host.type === 'RegExp')
		{
			host = v.hostRegExp = new RegExp(host.pattern, host.flags);
		}
	}
	else if(typeof host === 'string')
	{
		host = v.hostRegExp = new RegExp(host.replace(/./gi, function(c){return c === '*' ? '.*' : c === '\\' ? '\\\\' : '[' + c + ']';}), 'gi');
	}
	
	// possibly add {address,redirect} routes (path = source, address = destination)
	// array may be specified, or directly address/redirect route (path is always / in this case, since it is the only route for the given host)
	var routes = v.routes || [];
	if(v.address)
	{
		routes.push({path: '/', address: v.address});
	}
	if(v.redirect)
	{
		routes.push({path: '/', redirect: v.redirect});
	}
	
	// for each route
	routes.forEach(function(subroute)
	{
		const subroutePath = subroute.path || '/';
		
		// handle redirect
		if(subroute.redirect)
		{
			// construct Location value
			const targetURL = typeof v.redirect === 'object' ? v.redirect : url.parse(v.redirect);
			targetURL.protocol = ((targetURL.protocol || '') + ':').replace(/:.*$/gi, '://').replace(/^:\/\/$/gi, '');
			targetURL.hostname = targetURL.hostname || targetURL.host || '';
			targetURL.port = (':' + (targetURL.port || '')).replace(/^:$/gi, '');
			targetURL.path = targetURL.path || '';
			targetURL.basePath = targetURL.basePath || '';
			
			console.log('info: ' + listen_host + ':' + listen_port + ' will redirect: ' + host + '' + subroutePath + ' -> ' + targetURL.protocol + '' + targetURL.hostname + targetURL.port + targetURL.basePath + targetURL.path);
			
			p.use(subroutePath, function(req, res, next)
			{
				if(req.secure)
				{
					return next();
				}
				res.writeHead(302, {'Location': targetURL.protocol + (targetURL.hostname || req.headers.host) + targetURL.port + targetURL.basePath + (targetURL.path || req.url)});
				res.end();
			});
		}
		// handle address
		else
		{
			console.log('info: ' + listen_host + ':' + listen_port + ' will reroute: ' + host + '' + subroutePath + ' -> ' + subroute.address);
			
			p.use(proxy(subroutePath, {
				target: subroute.address,
				pathRewrite: function(path, req)
				{
					return path.substring(subroutePath.length);
				},
				onProxyReq: function(proxyReq, req, res, options)
				{
					// problem: http://localhost:8082 gets parsed by the proxy (using require('url').parse) with trailing slash
					// solved by letting proxy send the original path in a header
					proxyReq.setHeader('X-Forwarded-Original-Path', req.originalUrl);
					proxyReq.setHeader('X-Forwarded-Original-Proto', req.headers['x-forwarded-proto'] || req.protocol || '');
				}
			}));
		}
	});
	
	if(host === '*')
	{
		app.use(p);
	}
	else
	{
		app.use(vhost(host, p));
	}
});

// final virtual host catch-all:
app.use(function(req, res, next)
{
	console.log('warning: No virtual host matched for request (' + listen_host + ':' + listen_port + '): ' + req.url + ', headers: ' + JSON.stringify(req.headers));
	res.writeHead(404);
	res.end('[nodejs-router] Warning: No virtual host matched for request (' + listen_host + ':' + listen_port + '): ' + req.url + ', headers: ' + JSON.stringify(req.headers));
});


if(config.tls || config.ssl)
{
	var tls_default = {
			key: filecache.getSync((config.tls || config.ssl).key),
			cert: filecache.getSync((config.tls || config.ssl).cert)
	};
	var tls_lookup = {
		'*': tls.createSecureContext(tls_default)
	};
	
	// use SNICallback to handle multiple TLS/SSL certificates, one for each domain name
	var options = {
		SNICallback: function(domain, cb)
		{
			try
			{
				var secureContext = tls_lookup[domain];
				if(!secureContext)
				{
					for(var i=0;i<config.vhosts.length;++i)
					{
						var v = config.vhosts[i];
						
						var host_match = false;
						var host = v.hostRegExp || ((v.host || '') +'');
						if(typeof host === 'string')
						{
							if(host === domain)
							{
								host_match = true;
							}
						}
						else
						{
							host.lastIndex = 0;
							host_match = host.test(domain);
						}
						
						if(host_match)
						{
							var host_tls = v.tls || v.ssl;
							if(host_tls)
							{
								console.log('info: Dynamically loading custom TLS/SSL for domain (' + domain + ') which matched: ' + JSON.stringify(v.host) + '.');
								
								if(!cb)
								{
									console.log('info: Reading configured files in sync (' + JSON.stringify(host_tls) + ').');
									
									var tls_opts = {};
									tls_opts.key = filecache.getSync(host_tls.key);
									tls_opts.cert = filecache.getSync(host_tls.cert);
									if(host_tls.ca)
									{
										tls_opts.ca = filecache.getSync(host_tls.ca);
									}
									secureContext = tls_lookup[domain] = tls.createSecureContext(tls_opts);
								}
								else
								{
									// mark for this function (and any other parallel requests!) we are working on it
									secureContext = tls_lookup[domain] = new Promise(async function(resolve, reject)
									{
										console.log('info: Reading configured files in async (' + JSON.stringify(host_tls) + ').');
										
										var tls_opts = {};
										tls_opts.key = await filecache.get(host_tls.key);
										tls_opts.cert = await filecache.get(host_tls.cert);
										if(host_tls.ca)
										{
											tls_opts.ca = await filecache.get(host_tls.ca);
										}
										cb(null, tls_lookup[domain] = tls.createSecureContext(tls_opts));
									});
								}
								break;
							}
						}
					}
				}
				else if(typeof secureContext.then === 'function') // secureContext is a Promise
				{
					// if(cb) -> cb must be a function, otherwise we cannot have a Promise
					(async function()
					{
						// await the secureContext which is loaded in a parallel request
						cb(null, await secureContext);
					})();
				}
			}
			catch(err)
			{
				console.error('file error: Failed to load TLS Certificate/Key files for request domain (' + domain + '):');
				console.error(err);
			}
			
			if(!secureContext)
			{
				// no key/cert available for this domain
				console.log('warning: No TLS Certificate/Key files available for request domain (' + domain + '). Fallback to default global TLS/SSL files.');
				secureContext = tls_lookup['*'];
			}
			
			if(cb)
			{
				if(!secureContext || typeof secureContext.then !== 'function') // secureContext is not a Promise
				{
					cb(null, secureContext);
				}
			}
			else
			{
				return secureContext;
			}
		},
		key: tls_default.key,
		cert: tls_default.cert
	};
	
	https.createServer(options, app).listen(listen_port, listen_host);
}
else
{
	http.createServer(app).listen(listen_port, listen_host);
}

