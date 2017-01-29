/*
 * Rijndael256
 * Copyright (C)2013 2Toad, LLC.
 * licensing@2toad.com
 * 
 * https://github.com/2Toad/Rijndael256
 */

using System.Text;

namespace Rijndael256
{
    public class AuthKeys
    {
        // The generated hash is 512-bit (128 chars)
        // We split that into two 256-bit keys (64 chars each)
        private const int KeyLength = 64;

        public string CipherKey { get; set; }
        public byte[] MacKey { get; set; }

        public static AuthKeys Generate(string password)
        {
            // Generate 512-bit hash from password
            var hash = Hash.Sha512(password);

            // Split hash into two 256-bit keys
            return new AuthKeys {
                CipherKey = hash.Substring(0, KeyLength),
                MacKey = Encoding.UTF8.GetBytes(hash.Substring(KeyLength, KeyLength))
            };
        }
    }
}
