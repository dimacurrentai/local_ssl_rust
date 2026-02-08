# `local_ssl_rust`

The example below is using `dima.ai` as the FQDN.

## Get a Cert

Install certbot, then, from a temporary dir, run, without root:

```
certbot certonly --manual \
    --preferred-challenges dns -d dima.ai \
    --config-dir ./letsencrypt \
    --work-dir \
    ./letsencrypt/work --logs-dir \
    ./letsencrypt/logs
```

This will produce two files, `fullchain.pem` and `privkey.pem`. Look for them under `letsencrypt/live/dima.ai/`.

Store them safely under some directory where the last path component is `dima.ai`, ex. `~/.ssl/dima.ai/`.

## Local Routing

In `/etc/hosts`, add these two lines:

```
127.0.0.1 dima.ai
::1 dima.ai
```

## Run

Here's the simplest invocation command:

```bash
cargo build && sudo ./target/debug/local_ssl_rust --letsencrypt ~/.ssl/dima.ai
```

You can also `cargo build --release` and replace `/debug/` by `/release/`.
```
