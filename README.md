# Rijndael256

[![NuGet](https://img.shields.io/nuget/v/Rijndael256.svg?maxAge=2592000)](https://www.nuget.org/packages/Rijndael256/)

AES cryptographic library for .NET

---

## About
Rijndael256 makes encrypting data and files a breeze with the AES symmetric-key cipher Rijndael.

### Features

* Advanced Encryption Standard
* Rijndael symmetric-key cipher:
	* Encrypt data or files
	* AES key sizes:
		* 128-bit
		* 192-bit
		* 256-bit
	* CBC Mode
	* Authenticated AES: Encrypt then MAC (EtM)
* Cryptographic hashes:
	* SHA-512
	* PBKDF2
* 100% Managed C#

## Examples

### Encrypt a string using Rijndael AES 256-bit

```C#
string password = "sKzvYk#1Pn33!YN";  // The password to encrypt the data with
string clearText = "Top secret data"; // The string to encrypt

// Encrypt the string
string cipherText = Rijndael.Encrypt(clearText, password, KeySize.Aes256);

// Decrypt the string
clearText = Rijndael.Decrypt(cipherText, password, KeySize.Aes256);
```

### Encrypt a string using authenticated Rijndael AES 256-bit (Encrypt then MAC)

```C#
string password = "Znk7drQ8a8AS3PeHl42b";   // The password to encrypt the data with
string clearText = "Super top secret data"; // The string to encrypt

// Encrypt the string
string authenticatedCipherText = RijndaelEtM.Encrypt(clearText, password, KeySize.Aes256);

// Decrypt the string
clearText = RijndaelEtM.Decrypt(authenticatedCipherText, password, KeySize.Aes256);
```

### Encrypt a file using Rijndael AES 256-bit

```C#
string password = "2zj9cV!50BwJ$A1";        // The password to encrypt the file with
string clearFile = @"C:\TopSecretFile.png"; // The file to encrypt
string cipherFile = @"C:\SecureFile";       // The encrypted file (extension is optional)

// Encrypt the file
Rijndael.Encrypt(clearFile, cipherFile, password, KeySize.Aes256);

// Decrypt the file
Rijndael.Decrypt(cipherFile, clearFile, password, KeySize.Aes256);
```