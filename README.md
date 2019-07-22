<p align="center">
  <img src="https://suyashkumar.com/assets/img/lock.png" width="64">
  <h3 align="center">ssl-proxy</h3>
  <p align="center">Simple single-command SSL reverse proxy with autogenerated certificates (LetsEncrypt, self-signed)<p>
  <p align="center"> <a href="https://goreportcard.com/report/github.com/suyashkumar/ssl-proxy"><img src="https://goreportcard.com/badge/github.com/suyashkumar/ssl-proxy" alt=""></a> <a href="https://travis-ci.com/suyashkumar/ssl-proxy"><img src="https://travis-ci.com/suyashkumar/ssl-proxy.svg?branch=master" /></a> <a href="https://godoc.org/github.com/suyashkumar/ssl-proxy"><img src="https://godoc.org/github.com/suyashkumar/ssl-proxy?status.svg" alt=""></a> 
  </p>
</p>

A handy and simple way to add SSL to your thing running on a VM--be it your personal jupyter notebook or your team jenkins instance. `ssl-proxy` autogenerates SSL certs and proxies HTTPS traffic to an existing HTTP server in a single command. 

## Usage
### With auto self-signed certificates
```sh
ssl-proxy -from 0.0.0.0:4430 -to 127.0.0.1:8000
```
This will immediately generate self-signed certificates and begin proxying HTTPS traffic from https://0.0.0.0:4430 to http://127.0.0.1:8000. No need to ever call openssl. It will print the SHA256 fingerprint of the cert being used for you to perform manual certificate verification in the browser if you would like (before you "trust" the cert).

I know `nginx` is often used for stuff like this, but I got tired of dealing with the boilerplate and wanted to explore something fun. So I ended up throwing this together. 

### With auto LetsEncrypt SSL certificates
```sh
ssl-proxy -from 0.0.0.0:443 -to 127.0.0.1:8000 -domain=mydomain.com
```
This will immediately generate, fetch, and serve real LetsEncrypt certificates for `mydomain.com` and begin proxying HTTPS traffic from https://0.0.0.0:443 to http://127.0.0.1:8000. For now, you need to ensure that `ssl-proxy` can bind port `:443` and that `mydomain.com` routes to the server running `ssl-proxy` (as you may have expected, this is not the tool you should be using if you have load-balancing over multiple servers or other deployment configurations).

### Provide your own certs
```sh
ssl-proxy -cert cert.pem -key myKey.pem -from 0.0.0.0:4430 -to 127.0.0.1:8000
```
You can provide your own existing certs, of course. Jenkins still has issues serving the fullchain certs from letsencrypt properly, so this tool has come in handy for me there. 

### Redirect HTTP -> HTTPS
Simply include the `-redirectHTTP` flag when running the program.

## Installation
Simply download and uncompress the proper prebuilt binary for your system from the [releases tab](https://github.com/suyashkumar/ssl-proxy/releases/). Then, add the binary to your path or start using it locally (`./ssl-proxy`).

If you're using `wget`, you can fetch and uncompress the right binary for your OS using [`getbin.io`](https://github.com/suyashkumar/getbin) as follows:
```sh
wget -qO- "https://getbin.io/suyashkumar/ssl-proxy" | tar xvz 
```
or with `curl` (note you need to provide your os if using curl as one of `(darwin, windows, linux)` below):
```sh
curl -LJ "https://getbin.io/suyashkumar/ssl-proxy?os=linux" | tar xvz 
```

Shameless plug: [`suyashkumar/getbin (https://getbin.io)`](https://github.com/suyashkumar/getbin) is a general tool that can fetch the latest binaries from GitHub releases for your OS. Check it out :).  

### Build from source 
#### Build from source using Docker
You can build `ssl-proxy` for all platforms quickly using the included Docker configurations.

If you have `docker-compose` installed:
```sh
docker-compose -f docker-compose.build.yml up
```
will build linux, osx, and darwin binaries (x86) and place them in a `build/` folder in your current working directory.
#### Build from source locally
You must have Golang installed on your system along with `make` and [`dep`](https://github.com/golang/dep). Then simply clone the repository and run `make`. 

## Attribution
Icons made by <a href="https://www.flaticon.com/authors/those-icons" title="Those Icons">Those Icons</a> from <a href="https://www.flaticon.com/" title="Flaticon">www.flaticon.com</a> is licensed by <a href="http://creativecommons.org/licenses/by/3.0/" title="Creative Commons BY 3.0" target="_blank">CC 3.0 BY</a>
