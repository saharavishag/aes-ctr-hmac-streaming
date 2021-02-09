# aes-ctr-hmac-streaming 🔐
Implementing encryption/decryption with authentication for large files using CTR mode and HMAC

## Overview
In this project you can find implementaion for large files encryption and decryption using **AES-CTR** mode.
In addition, there's also **HMAC** authentication using to authenticate the encrypted data along decrypting it.
This code is based on golang crypto packages

### Implementation
The implementation can be found in `encryption.go`

### Usage
Example of how to use the function can be found in `encryption_test.go`

Run it
```
go test
```

### GO version
```
$ go version
go version go1.14.6 darwin/amd64
```