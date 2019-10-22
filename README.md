# nodejs-router
Simple NodeJS router for local HTTP/HTTPS webapplications

# Recommended installation
```bash
cd /srv && git clone https://github.com/jetibest/nodejs-router.git
```

**`/root/nodejs-router.service`**:
```
[Unit]
Description=HTTP/HTTPS router using NodeJS

[Service]
Type=simple
WorkingDirectory=/srv/nodejs-router
ExecStart=/bin/bash -c 'cd /srv/nodejs-router/ && node main.js'
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable /root/nodejs-router.service
systemctl start nodejs-router
```

# TODO
 - Implement SNICallback for different certificates per vhost on the same port
 - Implement `--check-syntax` to ensure syntax will work
 - Update Readme with documentation for `config.json`
