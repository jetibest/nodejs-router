// acme_challenge is a simple webserver for the purpose of serving webroot
// and has some convenience functions around certbot for use in NodeJS

const path = require('path');
const fs = require('fs');
const http = require('http');
const child_process = require('child_process');

function log()
{
	console.log.apply(console, ['[acme_challenge]'].concat(Array.from(arguments)));
}

async function exec_certbot(certbot_bin, certbot_args)
{
	return new Promise((resolve, reject) =>
	{
		const report = [];
		
		const certbot = child_process.spawn(certbot_bin, certbot_args, {stdio: ['ignore', 'pipe', 'pipe']});
		certbot.on('error', err =>
		{
			log('Debug: certbot output => ' + Buffer.concat(report).toString('utf8'));
			log('Error: Failed to run certbot (' + certbot_bin + ') with args: ' + certbot_args.join(' '));
			reject(err);
		});
		certbot.on('exit', exitCode =>
		{
			if(exitCode !== 0)
			{
				log('Debug: certbot output => ' + Buffer.concat(report).toString('utf8'));
				return reject(new Error('Non-zero exit-code (' + exitCode + ') from certbot (' + certbot_bin + ') with args: ' + certbot_args.join(' ')));
			}
			
			resolve(Buffer.concat(report).toString('utf8'));
		});
		certbot.stdout.on('error', err => log(err));
		certbot.stderr.on('error', err => log(err));
		certbot.stdout.on('data', chunk => report.push(chunk));
		certbot.stderr.on('data', chunk => report.push(chunk));
	});
}

module.exports = {
	WEBROOT_PATH: '/tmp/acme-challenge',
	ACME_CHALLENGE_PATH: '/.well-known/acme-challenge/',
	CERT_FILE: '/etc/letsencrypt/live/<domain>/fullchain.pem',
	KEY_FILE: '/etc/letsencrypt/live/<domain>/privkey.pem',
	renewCertificates: async function(options)
	{
		options = options || {};
		
		const certbot_bin = 'certbot';
		const certbot_args = [
			'renew'
		];
		
		return exec_certbot(certbot_bin, certbot_args);
	},
	createCertificate: async function(options)
	{
		options = options || {};

		const opts_domain = options.domain;
		const opts_email = options.email;
		
		const opts_webroot_path = options._webroot_path || this.WEBROOT_PATH;
		
		const certbot_bin = 'certbot';
		const certbot_args = [
			'--non-interactive',
			'certonly',
			'--webroot',
			'--agree-tos',
			'--webroot-path', opts_webroot_path,
			'--domain', opts_domain
		];
		
		if(opts_email)
		{
			certbot_args.push('--email', opts_email);
		}
		else
		{
			certbot_args.push('--register-unsafely-without-email');
		}
		
		return exec_certbot(certbot_bin, certbot_args);
	},
	getCertificate: function(options)
	{
		options = options || {};

		if(typeof options === 'string') options = {domain: options};
		
		const opts_domain = options.domain;
		
		return {
			key: this.KEY_FILE.replace(/<(domain|domainname|host|hostname)>/gi, opts_domain),
			cert: this.CERT_FILE.replace(/<(domain|domainname|host|hostname)>/gi, opts_domain)
		};
	},
	readCertificate: async function(options)
	{
		const tls = getCertificate(options);

		if(tls)
		{
			if(typeof tls.key === 'string') tls.key = await fs.promises.readFile(tls.key);
			if(typeof tls.cert === 'string') tls.cert = await fs.promises.readFile(tls.cert);
		}
		
		return tls;
	},
	createServer: async function(options, host_arg)
	{
		options = options || {};
		
		if(typeof options === 'number') options = {listen_port: options};
		
		const opts_listen_host = options.listen_host || '::';
		const opts_listen_port = options.listen_port || 0;
		
		const opts_public_html = options._public_html || this.WEBROOT_PATH;
		const opts_listen_path = options._listen_path || this.ACME_CHALLENGE_PATH;
		
		const ac_jail_path = path.resolve(opts_public_html);
		try
		{
			await fs.promises.mkdir(ac_jail_path, {recursive: true});
		}
		catch(err)
		{
			if(err.code !== 'EEXIST')
			{
				log('Error (' + err.code + '). Unable to create directory (' + ac_jail_path + ')');
				throw err;
			}
		}
		
		return new Promise((resolve, reject) =>
		{
			var fulfilled = false;

			const ac_server = http.createServer();
			ac_server.on('error', err =>
			{
				log('Server unexpectedly stopped (' + (err ? err.code : 'undefined') + ').');
				log(err);
				
				if(fulfilled) return;
				fulfilled = true;
				reject(ac_server);
			});
			ac_server.on('listening', () =>
			{
				log('Server listening now, waiting for acme challenge requests at ' + opts_listen_path);
				
				if(fulfilled) return;
				fulfilled = true;
				resolve(ac_server);
			});
			ac_server.on('request', async (req, res) =>
			{
				const req_path = path.resolve(path.join(ac_jail_path, opts_listen_path, req.url.replace(/[?].*$/gi, '')));
				
				if(req_path.startsWith(ac_jail_path))
				{
					try
					{
						const data = await fs.promises.readFile(req_path);
						
						res.writeHead(200, {'Content-Type': 'text/plain'});
						res.end(data);
						
						log('Request ok: ' + data.length + ' bytes for ' + req.url + ' at path: ' + req_path);
						
						return;
					}
					catch(err)
					{
						if(err.code !== 'ENOENT' && err.code !== 'EISDIR')
						{
							log('Filesystem error: ' + err.code + ' for ' + req.url + ' at path: ' + req_path);
						}
						else
						{
							log('Request error: ' + err.code + ' for ' + req.url + ' at path: ' + req_path);
						}
					}
				}
				else
				{
					log('Request error: jailbreak for ' + req.url + ' at path: ' + req_path);
				}
				
				res.writeHead(404, {'Content-Type': 'text/plain'});
				res.end('404 Not Found: ' + req.url + '\n');
			});
			ac_server.on('clientError', (err, socket) =>
			{
					if(err.code === 'ECONNRESET' || socket.writable) return;
				
				socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
			});
			ac_server.on('close', () =>
			{
				log('Server stopped.');

				if(fulfilled) return;
				fulfilled = true;
				reject(new Error('Server closed before it could start listening.'));
			});
			
			log('Starting server at ' + (opts_listen_host === '::' ? '' : (opts_listen_host || '')) + ':' + opts_listen_port);
			
			ac_server.listen(opts_listen_port, opts_listen_host);
		});
	}
};
