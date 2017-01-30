/*
 * Rijndael256
 * Copyright (C)2013 2Toad, LLC.
 * licensing@2toad.com
 * 
 * https://github.com/2Toad/Rijndael256
 */

using System;
using System.IO;
using System.Linq;
using System.Text;

namespace Rijndael256
{
    /// <summary>
    /// Authenticated implementation of the Rijndael symmetric-key cipher using
    /// the Encrypt then MAC (EtM) strategy.
    /// </summary>
    public class RijndaelEtM : Rijndael
    {
        /// <summary>
        /// Encrypts data using the "Encrypt then MAC" (EtM) strategy via the Rijndael cipher in CBC 
        /// mode with a password derived HMAC SHA-512 salt. A random 128-bit Initialization Vector 
        /// is generated for the cipher.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="password">The password to encrypt the data with.</param>
        /// <param name="keySize">The cipher key size. 256-bit is stronger, but slower.</param>
        /// <returns>The encrypted data.</returns>
        public static new string Encrypt(string data, string password, KeySize keySize)
        {
            return Encrypt(Encoding.UTF8.GetBytes(data), password, keySize);
        }

        /// <summary>
        /// Encrypts data using the "Encrypt then MAC" (EtM) strategy via the Rijndael cipher in CBC 
        /// mode with a password derived HMAC SHA-512 salt. A random 128-bit Initialization Vector 
        /// is generated for the cipher.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="password">The password to encrypt the data with.</param>
        /// <param name="keySize">The cipher key size. 256-bit is stronger, but slower.</param>
        /// <returns>The encrypted data.</returns>
        public static new string Encrypt(byte[] data, string password, KeySize keySize)
        {
            // Generate a random IV
            var iv = Rng.GenerateRandomBytes(InitializationVectorSize);

            // Encrypt the data
            var cipher = Encrypt(data, password, iv, keySize);

            // Base64 encode the cipher
            return Convert.ToBase64String(cipher);
        }

        /// <summary>
        /// Encrypts data using the "Encrypt then MAC" (EtM) strategy via the Rijndael cipher in CBC 
        /// mode with a password derived HMAC SHA-512 salt.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="password">The password to encrypt the data with.</param>
        /// <param name="iv">The initialization vector. Must be 128-bits.</param>
        /// <param name="keySize">The cipher key size. 256-bit is stronger, but slower.</param>
        /// <returns>The encrypted data.</returns>
        public static new byte[] Encrypt(byte[] data, string password, byte[] iv, KeySize keySize)
        {
            // Generate keys
            var keys = AuthKeys.Generate(password);

            // Encrypt the data (returns IV + Cipher)
            var cipher = Rijndael.Encrypt(data, keys.CipherKey, iv, keySize);

            // Calculate MAC from cipher
            var mac = CalculateMac(cipher, keys.MacKey);

            // Append MAC
            var output = new byte[cipher.Length + mac.Length];
            Buffer.BlockCopy(cipher, 0, output, 0, cipher.Length);
            Buffer.BlockCopy(mac, 0, output, cipher.Length, mac.Length);

            // IV + Cipher + MAC
            return output;
        }

        /// <summary>
        /// Decrypts authenticated ciphers using Rijndael in CBC mode with a password derived HMAC SHA-512 salt.
        /// </summary>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="password">The password to decrypt the data with.</param>
        /// <param name="keySize">The size of the cipher key used to encrypt the data.</param>
        /// <returns>The decrypted data.</returns>
        public static new string Decrypt(string data, string password, KeySize keySize)
        {
            return Decrypt(Convert.FromBase64String(data), password, keySize);
        }

        /// <summary>
        /// Decrypts authenticated ciphers using Rijndael in CBC mode with a password derived HMAC SHA-512 salt.
        /// </summary>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="password">The password to decrypt the data with.</param>
        /// <param name="keySize">The size of the cipher key used to encrypt the data.</param>
        /// <returns>The decrypted data.</returns>
        public static new string Decrypt(byte[] data, string password, KeySize keySize)
        {
            // Generate keys
            var keys = AuthKeys.Generate(password);

            // Split (IV + Cipher) + MAC
            var mac = new byte[keys.MacKey.Length];
            var cipher = new byte[data.Length - mac.Length];
            using (var ms = new MemoryStream(data))
            {
                // Read the IV + Cipher from the beginning of the encrypted string
                ms.Read(cipher, 0, cipher.Length);

                // Read the MAC from the end of the encrypted string
                ms.Read(mac, 0, mac.Length);
            }

            // Calculate MAC from cipher
            var cipherMac = CalculateMac(cipher, keys.MacKey);

            // Validate MAC
            if (!mac.SequenceEqual(cipherMac)) throw new Exception("Authorization failed!");

            // Decrypt cipher
            return Rijndael.Decrypt(cipher, keys.CipherKey, keySize);
        }

        private static byte[] CalculateMac(byte[] cipher, byte[] key)
        {
            return Hash.Pbkdf2(cipher, key, 10000);
        }
    }
}
