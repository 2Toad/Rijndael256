/*
 * Rijndael256
 * Copyright (C)2013 2Toad, LLC.
 * licensing@2toad.com
 * 
 * https://github.com/2Toad/Rijndael256
 */

using System;
using System.Text;
using Xunit;

namespace Rijndael256.Tests
{
    public class RijndaelTests
    {
        const string Password = "Crackle Turbine Zebra Austin";
        static readonly byte[] Iv = Encoding.UTF8.GetBytes("C3BF491FD6BB4C14");
        const string Plaintext = "A secret phrase to test AES.";
        const string Proof128 = "QzNCRjQ5MUZENkJCNEMxNPkl8wqqwa6lLiX3guZBl60qeV+YdqVvML5nRTV5gVck";
        const string Proof192 = "QzNCRjQ5MUZENkJCNEMxNPNTaKDpLH/CyFRjhTZmm9eENOLqZQhbg4bK/WkNLIsS";
        const string Proof256 = "QzNCRjQ5MUZENkJCNEMxNFTqmc7V05vvZ0X/1Fhke9PrXOfS6vT3wIByDyYslUsZ";

        [Fact]
        public void Encrypt128()
        {
            var plaintext = Encoding.UTF8.GetBytes(Plaintext);
            var ciphertext = Rijndael.Encrypt(plaintext, Password, Iv, KeySize.Aes128);
            Assert.Equal(Convert.ToBase64String(ciphertext), Proof128);
        }

        [Fact]
        public void Encrypt192()
        {
            var plaintext = Encoding.UTF8.GetBytes(Plaintext);
            var ciphertext = Rijndael.Encrypt(plaintext, Password, Iv, KeySize.Aes192);
            Assert.Equal(Convert.ToBase64String(ciphertext), Proof192);
        }

        [Fact]
        public void Encrypt256()
        {
            var plaintext = Encoding.UTF8.GetBytes(Plaintext);
            var ciphertext = Rijndael.Encrypt(plaintext, Password, Iv, KeySize.Aes256);
            Assert.Equal(Convert.ToBase64String(ciphertext), Proof256);
        }

        [Fact]
        public void Decrypt128()
        {
            var plaintext = Rijndael.Decrypt(Proof128, Password, KeySize.Aes128);
            Assert.Equal(plaintext, Plaintext);
        }

        [Fact]
        public void Decrypt192()
        {
            var plaintext = Rijndael.Decrypt(Proof192, Password, KeySize.Aes192);
            Assert.Equal(plaintext, Plaintext);
        }

        [Fact]
        public void Decrypt256()
        {
            var plaintext = Rijndael.Decrypt(Proof256, Password, KeySize.Aes256);
            Assert.Equal(plaintext, Plaintext);
        }

        [Fact]
        public void RandomIv128()
        {
            var ciphertext1 = Rijndael.Encrypt(Plaintext, Password, KeySize.Aes128);
            var ciphertext2 = Rijndael.Encrypt(Plaintext, Password, KeySize.Aes128);
            var plaintext = Rijndael.Decrypt(ciphertext1, Password, KeySize.Aes128);

            Assert.Equal(plaintext, Plaintext);
            Assert.NotEqual(ciphertext1, ciphertext2);
        }

        [Fact]
        public void RandomIv192()
        {
            var ciphertext1 = Rijndael.Encrypt(Plaintext, Password, KeySize.Aes192);
            var ciphertext2 = Rijndael.Encrypt(Plaintext, Password, KeySize.Aes192);
            var plaintext = Rijndael.Decrypt(ciphertext1, Password, KeySize.Aes192);

            Assert.Equal(plaintext, Plaintext);
            Assert.NotEqual(ciphertext1, ciphertext2);
        }

        [Fact]
        public void RandomIv256()
        {
            var ciphertext1 = Rijndael.Encrypt(Plaintext, Password, KeySize.Aes256);
            var ciphertext2 = Rijndael.Encrypt(Plaintext, Password, KeySize.Aes256);
            var plaintext = Rijndael.Decrypt(ciphertext1, Password, KeySize.Aes256);

            Assert.Equal(plaintext, Plaintext);
            Assert.NotEqual(ciphertext1, ciphertext2);
        }
    }
}
