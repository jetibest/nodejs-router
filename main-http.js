const http = require('http');
const connect = require('connect');

const app = connect();

// Redirect automatically HTTP to HTTPS

app.use(function(req, res, next)
{
	if(req.secure)
	{
		return next();
	}
	res.writeHead(302, {'Location': 'https://' + req.headers.host + req.url});
	res.end();
});

http.createServer(app).listen(parseInt(process.argv[2]) || 80);
