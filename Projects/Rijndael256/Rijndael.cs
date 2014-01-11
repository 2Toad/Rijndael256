/*
 * Rijndael256
 * Copyright (C)2013 2Toad, LLC.
 * licensing@2toad.com
 * 
 * http://2toad.com/Project/Rijndael256/License
 */

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Rijndael256
{
    /// <summary>
    /// AES implementation of the Rijndael symmetric-key cipher.
    /// </summary>
    public static class Rijndael
    {
        #region Properties

        const int InitializationVectorSize = 16;
        const CipherMode BlockCipherMode = CipherMode.CBC;
        
        /// <summary>
        /// A cryptographically strong random number generator.
        /// </summary>
        public static RNGCryptoServiceProvider RandomNumberGenerator
        {
            get { return _randomNumberGenerator ?? (_randomNumberGenerator = new RNGCryptoServiceProvider()); }
        }
        private static RNGCryptoServiceProvider _randomNumberGenerator;

        #endregion

        /// <summary>
        /// Encrypts data using the Rijndael cipher in CBC mode with a password derived HMAC SHA1 salt.
        /// A random 128-bit Initialization Vector is generated for the cipher, and inserted at the
        /// beginning of the resulting Base64 encoded string.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="password">The password to encrypt the data with.</param>
        /// <param name="keySize">The cipher key size. 256-bit is stronger, but slower.</param>
        /// <returns>The encrypted data.</returns>
        public static string Encrypt(string data, string password, KeySize keySize)
        {
            return Encrypt(Encoding.UTF8.GetBytes(data), password, keySize);
        }

        /// <summary>
        /// Encrypts data using the Rijndael cipher in CBC mode with a password derived HMAC SHA1 salt.
        /// A random 128-bit Initialization Vector is generated for the cipher, and inserted at the
        /// beginning of the resulting Base64 encoded string.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="password">The password to encrypt the data with.</param>
        /// <param name="keySize">The cipher key size. 256-bit is stronger, but slower.</param>
        /// <returns>The encrypted data.</returns>
        public static string Encrypt(byte[] data, string password, KeySize keySize)
        {
            // Generate a random IV
            var iv = GenerateRandomBytes(InitializationVectorSize);

            // Encrypt the data
            var cipher = Encrypt(data, password, iv, keySize);

            // Store the IV at the beginning of the output
            var output = new byte[iv.Length + cipher.Length];
            iv.CopyTo(output, 0);
            cipher.CopyTo(output, iv.Length);

            // Base64 encode the output
            return Convert.ToBase64String(output);
        }

        /// <summary>
        /// Encrypts data using the Rijndael cipher in CBC mode with a password derived HMAC SHA1 salt.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="password">The password to encrypt the data with.</param>
        /// <param name="iv">The initialization vector. Must be 128-bits.</param>
        /// <param name="keySize">The cipher key size. 256-bit is stronger, but slower.</param>
        /// <returns>The encrypted data.</returns>
        public static byte[] Encrypt(byte[] data, string password, byte[] iv, KeySize keySize)
        {
            if (iv.Length != InitializationVectorSize) throw new ArgumentOutOfRangeException("iv", "AES requires an Initialization Vector of 128-bits.");

            using (var ms = new MemoryStream())
            {
                // Create a CryptoStream to process the data
                using (var cs = new CryptoStream(ms, CreateEncryptor(password, iv, keySize), CryptoStreamMode.Write))
                {
                    // Encrypt the data
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();
                }
                return ms.ToArray();
            }            
        }

        /// <summary>
        /// Encrypts a file using the Rijndael cipher in CBC mode with a password derived HMAC SHA1 salt.
        /// A random 128-bit Initialization Vector is generated for the cipher, and inserted at the
        /// beginning of the resulting file.
        /// </summary>
        /// <param name="inFile">The file to encrypt.</param>
        /// <param name="outFile">The new encrypted file.</param>
        /// <param name="password">The password to encrypt the file with.</param>
        /// <param name="keySize">The cipher key size. 256-bit is stronger, but slower.</param>
        public static void Encrypt(string inFile, string outFile, string password, KeySize keySize)
        {
            // Create a new output file to write the encrypted data to
            using (var fso = new FileStream(outFile, FileMode.Create, FileAccess.Write))
            {
                // Store the IV at the beginning of the encrypted file
                var iv = GenerateRandomBytes(InitializationVectorSize);
                fso.Write(iv, 0, iv.Length);

                // Create a CryptoStream to process the data
                using (var cs = new CryptoStream(fso, CreateEncryptor(password, iv, keySize), CryptoStreamMode.Write))
                {
                    // Open the file we want to encrypt
                    using (var fsi = new FileStream(inFile, FileMode.Open, FileAccess.Read))
                    {
                        // Create a buffer to process the input file in chunks vs reading
                        // the whole file into memory
                        var buffer = new byte[4096];

                        // Read a chunk of data from the input file 
                        int bytesRead;
                        while ((bytesRead = fsi.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            // Encrypt the data and write it to the output file
                            cs.Write(buffer, 0, bytesRead);
                        }

                        // Finalize encryption
                        cs.FlushFinalBlock();
                    }
                }
            }
        }

        /// <summary>
        /// Decrypts data using the Rijndael cipher in CBC mode with a password derived HMAC SHA1 salt.
        /// This method expects a Base64 encoded string, with a 128-bit Initiliazation Vector embedded 
        /// at the beginning of the data.
        /// </summary>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="password">The password to decrypt the data with.</param>
        /// <param name="keySize">The size of the cipher key used to encrypt the data.</param>
        /// <returns>The decrypted data.</returns>
        public static string Decrypt(string data, string password, KeySize keySize)
        {
            return Decrypt(Convert.FromBase64String(data), password, keySize);
        }

        /// <summary>
        /// Decrypts data using the Rijndael cipher in CBC mode with a password derived HMAC SHA1 salt.
        /// This method expects a 128-bit Initiliazation Vector embedded at the beginning of the data.
        /// </summary>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="password">The password to decrypt the data with.</param>
        /// <param name="keySize">The size of the cipher key used to encrypt the data.</param>
        /// <returns>The decrypted data.</returns>
        public static string Decrypt(byte[] data, string password, KeySize keySize)
        {
            using (var ms = new MemoryStream(data))
            {
                // Read the IV from the beginning of the encrypted string
                var iv = new byte[InitializationVectorSize];
                ms.Read(iv, 0, iv.Length);

                // Create a CryptoStream to process the data
                using (var cs = new CryptoStream(ms, CreateDecryptor(password, iv, keySize), CryptoStreamMode.Read))
                {
                    // Decrypt data and convert it to a string
                    using (var sr = new StreamReader(cs, Encoding.UTF8)) return sr.ReadToEnd();
                }
            }
        }

        /// <summary>
        /// Decrypts data using the Rijndael cipher in CBC mode with a password derived HMAC SHA1 salt.
        /// </summary>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="password">The password to decrypt the data with.</param>
        /// <param name="iv">The initialization vector. Must be 128-bits.</param>
        /// <param name="keySize">The size of the cipher key used to encrypt the data.</param>
        /// <returns>The decrypted data.</returns>
        public static byte[] Decrypt(byte[] data, string password, byte[] iv, KeySize keySize)
        {
            if (iv.Length != InitializationVectorSize) throw new ArgumentOutOfRangeException("iv", "AES requires an Initialization Vector of 128-bits.");

            using (var ms = new MemoryStream(data))
            {
                // Create a CryptoStream to process the data
                using (var cs = new CryptoStream(ms, CreateDecryptor(password, iv, keySize), CryptoStreamMode.Read))
                {
                    // We don't know what the size of decrypted data will be, so allocate the buffer using
                    // the encrypted size (encrypted data is always larger then decrypted data)
                    var buffer = new byte[data.Length];

                    // Decrypt the data
                    var length = cs.Read(buffer, 0, buffer.Length);
                    // Remove unused space
                    Array.Resize(ref buffer, length);

                    return buffer;
                }
            }
        }

        /// <summary>
        /// Decrypts a file using the Rijndael cipher in CBC mode with a password derived HMAC SHA1 salt.
        /// This method expects a 128-bit Initiliazation Vector embedded at the beginning of the file.
        /// </summary>
        /// <param name="inFile">The file to decrypt.</param>
        /// <param name="outFile">The new decrypted file.</param>
        /// <param name="password">The password to decrypt the file with.</param>
        /// <param name="keySize">The size of the cipher key used to encrypt the data.</param>
        public static void Decrypt(string inFile, string outFile, string password, KeySize keySize)
        {
            // Open the file we want to decrypt
            using (var fsi = new FileStream(inFile, FileMode.Open, FileAccess.Read))
            {
                // Read the IV from the beginning of the encrypted file
                var iv = new byte[InitializationVectorSize];
                fsi.Read(iv, 0, iv.Length);

                // Create a new output file to write the decrypted data to
                using (var fso = new FileStream(outFile, FileMode.Create, FileAccess.Write))
                {
                    // Create a CryptoStream to process the data
                    using (var cs = new CryptoStream(fso, CreateDecryptor(password, iv, keySize), CryptoStreamMode.Write))
                    {
                        // Create a buffer to process the input file in chunks vs reading
                        // the whole file into memory
                        var buffer = new byte[4096];

                        // Read a chunk of data from the input file 
                        int bytesRead;
                        while ((bytesRead = fsi.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            // Decrypt the data and write it to the output file
                            cs.Write(buffer, 0, bytesRead);
                        }
                    }
                }
            }
        }

        #region Private Methods

        /// <summary>
        /// Generates an array of bytes using a cryptographically strong sequence
        /// of random values.
        /// </summary>
        /// <param name="size">The size of the array.</param>
        /// <returns>The array of bytes.</returns>
        private static byte[] GenerateRandomBytes(int size)
        {
            var bytes = new byte[size];
            RandomNumberGenerator.GetBytes(bytes);
            return bytes;
        }

        /// <summary>
        /// Generates a cryptographic key from the specified password.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="keySize">The cipher key size. 256-bit is stronger, but slower.</param>
        /// <returns>The cryptographic key.</returns>
        private static byte[] GenerateKey(string password, KeySize keySize)
        {
            // Create a salt to help prevent rainbow table attacks
            var salt = Hash.Pbkdf2(password, Hash.Sha512(password + password.Length), 500);

            // Generate a key from the password and salt
            return Hash.Pbkdf2(password, salt, 500, (int)keySize / 8);
        }

        /// <summary>
        /// Creates a symmetric Rijndael encryptor.
        /// </summary>
        /// <param name="password">The password to encrypt the data with.</param>
        /// <param name="iv">The initialization vector. Must be 128-bits.</param>
        /// <param name="keySize">The cipher key size. 256-bit is stronger, but slower.</param>
        /// <returns>The symmetric encryptor.</returns>
        private static ICryptoTransform CreateEncryptor(string password, byte[] iv, KeySize keySize)
        {
            var rijndael = new RijndaelManaged { Mode = BlockCipherMode };
            return rijndael.CreateEncryptor(GenerateKey(password, keySize), iv);
        }
        
        /// <summary>
        /// Creates a symmetric Rijndael decryptor.
        /// </summary>
        /// <param name="password">The password to decrypt the data with.</param>
        /// <param name="iv">The initialization vector. Must be 128-bits.</param>
        /// <param name="keySize">The cipher key size.</param>
        /// <returns>The symmetric decryptor.</returns>
        private static ICryptoTransform CreateDecryptor(string password, byte[] iv, KeySize keySize)
        {
            var rijndael = new RijndaelManaged { Mode = BlockCipherMode };
            return rijndael.CreateDecryptor(GenerateKey(password, keySize), iv);
        }

        #endregion
    }

    /// <summary>
    /// AES approved cipher key sizes.
    /// </summary>
    public enum KeySize
    {
        /// <summary>
        /// 128-bit
        /// </summary>
        Aes128 = 128,
        /// <summary>
        /// 192-bit
        /// </summary>
        Aes192 = 192,
        /// <summary>
        /// 256-bit
        /// </summary>
        Aes256 = 256
    }
}
