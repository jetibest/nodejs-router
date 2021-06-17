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
ExecStart=/bin/bash -c 'cd /srv/nodejs-router/ && node main.js -c config.json localhost:80'
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
 - Implement `--check-syntax` to ensure syntax will work
 - Implement regex backreference to include regex group in resulting address or redirect value
 - Update Readme with documentation for `config.json`
