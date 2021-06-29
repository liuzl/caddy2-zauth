# Caddy2-zauth

## Overview

`zauth` is a ak/sk authentication  middleware for [Caddy](https://github.com/caddyserver/caddy) v2.

## Installation

Rebuild caddy as follows:

```sh
xcaddy build --with github.com/liuzl/caddy2-zauth
```

## Caddyfile syntax

```
127.0.0.1:2021 {
    zauth {
        auth_db_dir ./authdb
        auth_admin_addr 127.0.0.1:1983
    }
}
```
