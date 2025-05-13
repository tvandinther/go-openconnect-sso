# go-openconnect-sso

A tool for getting login details through Two Factor Authentication for the openconnect clients. This tool only generates a config file with the `cookie`, `servercert` and `host` details which can be used to connect to the OpenConnect VPN server.

### Usage

```shell
go-openconnect-sso --server='https://vpn.server.myorg.com' --config ~/my-vpn-cookie/cookie.txt
```

The generate opneconnect config file:
```
$ cat ~/my-vpn-cookie/cookie.txt
cookie=1234567890ABCDEF123
servercert=4567890DEFABC321
# host=https://vpn-cluster-2.server.myorg.com/
```

After the file is successfully generated, you can run the following to connect to the VPN server:
```
openconnect <any-additional-params> --verbose --config ~/my-vpn-cookie/cookie.txt https://vpn-cluster-2.server.myorg.com
```
