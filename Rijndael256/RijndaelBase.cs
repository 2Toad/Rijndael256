/*
 * Rijndael256
 * Copyright (C)2013 2Toad, LLC.
 * licensing@2toad.com
 * 
 * https://github.com/2Toad/Rijndael256
 */

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Rijndael256
{
    public abstract class RijndaelBase
    {
        internal const int InitializationVectorSize = 16;
        internal const CipherMode BlockCipherMode = CipherMode.CBC;

        /// <summary>
        /// Encrypts data using the Rijndael cipher in CBC mode with a password derived HMAC SHA-512 salt.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="password">The password to encrypt the data with.</param>
        /// <param name="iv">The initialization vector. Must be 128-bits.</param>
        /// <param name="keySize">The cipher key size. 256-bit is stronger, but slower.</param>
        /// <returns>The encrypted data.</returns>
        public static byte[] Encrypt(byte[] data, string password, byte[] iv, KeySize keySize)
        {
            if (iv.Length != InitializationVectorSize) throw new ArgumentOutOfRangeException(nameof(iv), "AES requires an Initialization Vector of 128-bits.");

            byte[] cipher;

            using (var ms = new MemoryStream())
            {
                // Create a CryptoStream to process the data
                using (var cs = new CryptoStream(ms, CreateEncryptor(password, iv, keySize), CryptoStreamMode.Write))
                {
                    // Encrypt the data
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();
                }

                cipher = ms.ToArray();
            }

            // Concatenate IV + Cipher
            var output = new byte[iv.Length + cipher.Length];
            iv.CopyTo(output, 0);
            cipher.CopyTo(output, iv.Length);

            return output;
        }

        /// <summary>
        /// Decrypts data using the Rijndael cipher in CBC mode with a password derived HMAC SHA-512 salt.
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
        /// Generates a cryptographic key from the specified password.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="keySize">The cipher key size. 256-bit is stronger, but slower.</param>
        /// <returns>The cryptographic key.</returns>
        internal static byte[] GenerateKey(string password, KeySize keySize)
        {
            // Create a salt to help prevent rainbow table attacks
            var salt = Hash.Pbkdf2(password, Hash.Sha512(password + password.Length), 10000);

            // Generate a key from the password and salt
            return Hash.Pbkdf2(password, salt, 10000, (int)keySize / 8);
        }

        /// <summary>
        /// Creates a symmetric Rijndael encryptor.
        /// </summary>
        /// <param name="password">The password to encrypt the data with.</param>
        /// <param name="iv">The initialization vector. Must be 128-bits.</param>
        /// <param name="keySize">The cipher key size. 256-bit is stronger, but slower.</param>
        /// <returns>The symmetric encryptor.</returns>
        internal static ICryptoTransform CreateEncryptor(string password, byte[] iv, KeySize keySize)
        {
#if NET452
            var rijndael = new RijndaelManaged { Mode = BlockCipherMode };
#else
            var rijndael = Aes.Create();
            rijndael.Mode = BlockCipherMode;
#endif
            return rijndael.CreateEncryptor(GenerateKey(password, keySize), iv);
        }

        /// <summary>
        /// Creates a symmetric Rijndael decryptor.
        /// </summary>
        /// <param name="password">The password to decrypt the data with.</param>
        /// <param name="iv">The initialization vector. Must be 128-bits.</param>
        /// <param name="keySize">The cipher key size.</param>
        /// <returns>The symmetric decryptor.</returns>
        internal static ICryptoTransform CreateDecryptor(string password, byte[] iv, KeySize keySize)
        {
#if NET452
            var rijndael = new RijndaelManaged { Mode = BlockCipherMode };
#else
            var rijndael = Aes.Create();
            rijndael.Mode = BlockCipherMode;
#endif
            return rijndael.CreateDecryptor(GenerateKey(password, keySize), iv);
        }
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
