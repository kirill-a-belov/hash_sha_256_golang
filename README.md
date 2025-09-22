# SHA-256 Implementation in Go

**hash_sha_256_golang** is a Go implementation of the SHA-256 cryptographic hash function.  
This project is intended for research, education, and experimentation with cryptographic algorithms.

---

## Project Overview

SHA-256 is a widely used cryptographic hash function, forming the backbone of Bitcoin and other blockchain technologies.  
This repository contains a **custom implementation** of SHA-256 from scratch in Go, alongside a comparison with Go's standard library implementation.

### Features

- Complete SHA-256 implementation in pure Go
- Demonstrates cryptographic padding, message chunking, and compression functions
- Includes bitwise operations (rotate, shift) used in SHA-256
- Example usage for hashing arbitrary input strings

### Educational Value

This project can be used to:
- Learn and understand the internal workings of SHA-256
- Experiment with cryptographic algorithms and optimizations
- Serve as a base for research in blockchain and distributed systems

---

## Getting Started

Clone the repository:

```bash
git clone https://github.com/kirill-a-belov/hash_sha_256_golang.git
cd hash_sha_256_golang
```
## Run the example:

go run sha_256.go

Example Output:

Hash input string: Bitcoin is the most popular cryptocurrency
- Standard library SHA-256 hex output
- Custom implementation SHA-256 hex output

## Status

Open-source and research-oriented

Contributions, improvements, and educational forks are welcome

#Tags

#GO #sha_256 #crypto_algorithm"
