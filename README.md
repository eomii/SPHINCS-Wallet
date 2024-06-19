# A mini-wallet with SPHINCS+ signatures

This is a highly experimental external signer with quantum-safe signatures.
It is built on liboqs-go. It uses the NIST round 3 standardisation level for SPHINCS+.

> :warning: **Do not use this in production**

Setting up liboqs-go can be difficult. You can build a container with 

```bash
docker build -t oqs-go .
```

Mount your current directory into the container and use it as an environment:

```bash
 docker run --rm -it --workdir=/app -v ${PWD}:/app oqs-go /bin/bash
```

After that you can run the code with:

```bash
 go run main.go
```
