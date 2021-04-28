# Dynamic DNS handler for Caddy #

A caddy v2 plugin for dealing with dynamic DNS setups.
See the documentation for [DynDnsHandler] for more details.

[DynDnsHandler]: https://pkg.go.dev/github.com/nelsonxb/caddy-dyndns#DynDnsHandler

## Installing ##

Build a custom Caddy:

```bash
$ go install github.com/caddyserver/xcaddy@latest
$ xcaddy build \
    --with github.com/nelsonxb/caddy-dyndns \
    --with github.com/caddy-dns/...
```

## Setting up ##

This plugin was mainly developed to use with a FRITZ!Box.
You might find a setup like the following useful:

```jsonc
{
    "apps": {
        "http": {
            "servers": {
                "default": {
                    "routes": [{
                        "match": [{
                            "remote_ip": { "ranges": ["192.168.178.1"] },
                            "path": ["/.ddns"]
                        }],
                        "handle": [
                            {
                                "handler": "authentication",
                                "providers": {
                                    "http_basic": {/*...*/}
                                }
                            },
                            {
                                "handler": "dyndns",
                                "domain": "my.domain.com",
                                "provider": {/* dns.providers.* */}
                            }
                        ]
                    }]
                }
            }
        }
    }
}
```

Then, in the FRITZ!Box, configure DynDNS using the _User-defined_ provider:

| Setting | Value |
| ------- | ----- |
| Update URL | `http://192.168.178.x/.ddns?4=<ipaddr> http://192.168.178.x/.ddns?6=<ip6addr>` (or `<ip6addr>` could be `<ip6lanprefix>`, also note the two space-separated URLs) |
| Domain name | `my.domain.com` |
| User name | As configured in Caddy |
| Password | As configured in Caddy |
