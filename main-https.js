// Modules
const fs = require('fs');
const https = require('https');
const connect = require('connect');
const vhost = require('vhost');
const proxy = require('http-proxy-middleware');

const config = JSON.parse(fs.readFileSync('config.json'));

// Config
const options = {
	key: fs.readFileSync(config.ssl.key),
	cert: fs.readFileSync(config.ssl.cert)
};
// problem: http://localhost:8082 gets parsed by the proxy (using require('url').parse) with trailing slash
// solved by letting proxy send the original path in a header

// Connect code
const app = connect();

(config.routes || []).forEach(function(route)
{
	var p = connect();
	
	if(typeof route.host === 'object')
	{
		if(route.host.type === 'RegExp')
		{
			route.host = new RegExp(route.host.pattern, route.host.flags);
		}
	}
	
	route.routes.forEach(function(subroute)
	{
		console.log('Routing virtual host: https://' + route.host + '' + subroute.path + ' -> ' + subroute.address);
		p.use(proxy(subroute.path, {
			target: subroute.address,
			pathRewrite: function(path, req)
			{
				return path.substring(subroute.path.length);
			},
			onProxyReq: function(proxyReq, req, res, options)
			{
				proxyReq.setHeader('X-Forwarded-Original-Path', req.originalUrl);
			}
		}));
	});
	
	app.use(vhost(route.host, p));
});

app.use(function(req, res, next)
{
	console.log('Warning: No virtual host matched for request: ' + req.url + ', headers: ' + JSON.stringify(req.headers));
	res.writeHead(404);
	res.end('Warning: No virtual host matched for request: ' + req.url + ', headers: ' + JSON.stringify(req.headers));
});

https.createServer(options, app).listen(parseInt(process.argv[2]) || 8080);

