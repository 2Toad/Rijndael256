# Rijndael256

[![NuGet](https://img.shields.io/nuget/v/Rijndael256.svg?maxAge=86400)](https://www.nuget.org/packages/Rijndael256/)
[![Build Status](https://travis-ci.org/2Toad/Rijndael256.svg?branch=master)](https://travis-ci.org/2Toad/Rijndael256)

AES cryptographic library for .NET Framework and .NET Core

---

## About
Rijndael256 makes encrypting data and files a breeze with the AES symmetric-key cipher Rijndael.

### Features

* Advanced Encryption Standard (AES)
* Rijndael symmetric-key cipher:
	* Encrypt data or files
	* AES key sizes:
		* 128-bit
		* 192-bit
		* 256-bit
	* CBC Mode
* [Authenticated Encryption (AE)](#authenticated-encryption-ae)
	* Encrypt-then-MAC (EtM)
* Cryptographic hashes:
	* SHA-512
	* PBKDF2

## Quick Start

### Encrypt a string using Rijndael AES 256-bit

```C#
string password = "sKzvYk#1Pn33!YN";  // The password to encrypt the data with
string plaintext = "Top secret data"; // The string to encrypt

// Encrypt the string
string ciphertext = Rijndael.Encrypt(plaintext, password, KeySize.Aes256);

// Decrypt the string
plaintext = Rijndael.Decrypt(ciphertext, password, KeySize.Aes256);
```

### Encrypt a string using [Authenticated Encryption (AE)](#authenticated-encryption-ae)

```C#
string password = "KQpc@HuQ66b$z37";  // The password to encrypt the data with
string plaintext = "Top secret data"; // The string to encrypt

// Encrypt the string
string aeCiphertext = RijndaelEtM.Encrypt(plaintext, password, KeySize.Aes256);

// Decrypt the string
plaintext = RijndaelEtM.Decrypt(aeCiphertext, password, KeySize.Aes256);
```

### Encrypt a file using Rijndael AES 256-bit

```C#
string password = "2zj9cV!50BwJ$A1";            // The password to encrypt the file with
string plaintextFile = @"C:\TopSecretFile.png"; // The file to encrypt
string ciphertextFile = @"C:\SecureFile";       // The encrypted file (extension unnecessary)

// Encrypt the file
Rijndael.Encrypt(plaintextFile, ciphertextFile, password, KeySize.Aes256);

// Decrypt the file
Rijndael.Decrypt(ciphertextFile, plaintextFile, password, KeySize.Aes256);
```

----------

## Settings

The *Settings* object is a collection of mutable defaults used throughout the library. Modification of these defaults is not necessary, but is made available for developers who want finer control of Rijndael256.

| Setting        | Description                                    | Default |
|----------------|------------------------------------------------|---------|
| HashIterations | The number of iterations used to derive hashes | 10000   |

### Example

```C#
// The HashIterations setting is used in several places throughout the lib,
// with Rijndael.Encrypt being just one of them. After making this change,
// any future calls to Rijndael.Encrypt will make use of this new value
Settings.HashIterations = 25000;
```

## Appendix

### Authenticated Encryption (AE)

AE adds an integrity check to the resulting ciphertext, so we can authenticate the ciphertext before decrypting it. Whereas encryption provides confidentiality, AE adds authenticity.

#### Encrypt-then-MAC (EtM)

Rijndael256 offers AE via the EtM encryption mode, which was standardized in ISO/IEC 19772:2009.

##### EtM Workflow

 1. **Encryption**:
	 1. The plaintext is encrypted.
	 2. A MAC is calculated from the resulting ciphertext.
	 3. The MAC is appended to the ciphertext.
 2. **Decryption**:
	 1. The MAC is extracted from the ciphertext (M<sub>o</sub>).
	 2. A MAC is calculated from the ciphertext (M<sub>n</sub>).
	 3. The MACs are compared for equality (M<sub>o</sub> == M<sub>n</sub>)
		 1. Equal: The ciphertext is decrypted.
		 2. Not Equal:  Authentication has failed -- the decryption process is aborted, with no attempt being made to decrypt the unauthentic ciphertext.
