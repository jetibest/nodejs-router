const fs = require('fs');
const http = require('http');
const https = require('https');
const connect = require('connect');
const vhost = require('vhost');
const proxy = require('http-proxy-middleware');

const config = JSON.parse(fs.readFileSync('config.json'));

// TODO: SNICallback implementation in https-server options, and provide SSL context for each vhost if ssl arg provided for that host

const globalOptions = {};
if(config.ssl)
{
	globalOptions.ssl = {
		key: fs.readFileSync(config.ssl.key),
		cert: fs.readFileSync(config.ssl.cert)
	};
}
console.log('running router with global options:');
console.log(globalOptions);

const routers = config.routers || {};
Object.keys(routers).forEach(function(port)
{
	console.log('handling router: ' + port);
	console.log(routers[port]);
	const router = routers[port];
	if(!router)
	{
		return;
	}
	
	const listenPort = parseInt(port);
	if(Number.isNaN(listenPort))
	{
		return;
	}
	
	var ssl = false;
	if(router.ssl)
	{
		if(typeof router.ssl === 'object')
		{
			ssl = router.ssl;
		}
		else
		{
			ssl = globalOptions.ssl;
		}
	}
	
	console.log('Running router-server on port: ' + listenPort + ' ' + (ssl ? 'with SSL' : 'without SSL'));
	
	const app = connect();
		
	router.vhosts.forEach(function(v)
	{
		const p = connect();
		
		var host = v.host || '*';
		if(typeof host === 'object')
		{
			if(host.type === 'RegExp')
			{
				host = new RegExp(host.pattern, host.flags);
			}
		}
		
		var routes = v.routes || [];
		if(v.address)
		{
			routes.push({path: '/', address: v.address});
		}
		if(v.redirect)
		{
			routes.push({path: '/', redirect: v.redirect});
		}
		
		(v.routes || []).forEach(function(subroute)
		{
			if(subroute.redirect)
			{
				const targetURL = typeof v.redirect === 'object' ? v.redirect : url.parse(v.redirect);
				targetURL.protocol = ((targetURL.protocol || '') + ':').replace(/:.*$/gi, '://').replace(/^:\/\/$/gi, '');
				targetURL.hostname = targetURL.hostname || targetURL.host || '';
				targetURL.port = (':' + (targetURL.port || '')).replace(/^:$/gi, '');
				targetURL.path = targetURL.path || '';
				targetURL.basePath = targetURL.basePath || '';
				console.log(':' + listenPort + ' Redirecting virtual host: ' + host + '' + subroute.path + ' to ' + targetURL.protocol + '' + targetURL.hostname + targetURL.port + targetURL.basePath + targetURL.path);
				p.use(subroute.path, function(req, res, next)
				{
					if(req.secure)
					{
						return next();
					}
					res.writeHead(302, {'Location': targetURL.protocol + (targetURL.hostname || req.headers.host) + targetURL.port + targetURL.basePath + (targetURL.path || req.url)});
					res.end();
				});
			}
			else
			{
				console.log(':' + listenPort + ' Routing virtual host: ' + host + '' + subroute.path + ' -> ' + subroute.address);
				p.use(proxy(subroute.path, {
					target: subroute.address,
					pathRewrite: function(path, req)
					{
						return path.substring(subroute.path.length);
					},
					onProxyReq: function(proxyReq, req, res, options)
					{
						// problem: http://localhost:8082 gets parsed by the proxy (using require('url').parse) with trailing slash
						// solved by letting proxy send the original path in a header
						proxyReq.setHeader('X-Forwarded-Original-Path', req.originalUrl);
					}
				}));
			}
		});
		
		app.use(vhost(host, p));
	});
	
	// Final virtual host catch-all:
	app.use(function(req, res, next)
	{
		console.log('[nodejs-router] Warning: No virtual host matched for request (:' + listenPort + '): ' + req.url + ', headers: ' + JSON.stringify(req.headers));
		res.writeHead(404);
		res.end('[nodejs-router] Warning: No virtual host matched for request (:' + listenPort + '): ' + req.url + ', headers: ' + JSON.stringify(req.headers));
	});
	
	if(ssl)
	{
		https.createServer(ssl, app).listen(listenPort);
	}
	else
	{
		http.createServer(app).listen(listenPort);
	}
});
