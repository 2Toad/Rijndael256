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
        const string Password = "Cracker Turbine Zebra Austin";
        static readonly byte[] InitializationVector = Encoding.UTF8.GetBytes("C3BF491FD6BB4C14");
        const string Data = "This is my AES secret phrase.";
        const string Cipher128 = "QzNCRjQ5MUZENkJCNEMxNE8f2ohrMW7y1rrLjKBxBU4C+W/n2zR8s6DdAy9GJB2j";
        const string Cipher192 = "QzNCRjQ5MUZENkJCNEMxNJk6tXT/RLReed064fp29r5OLA6axJVVk7Ux7OYmUAH+";
        const string Cipher256 = "QzNCRjQ5MUZENkJCNEMxNJ10aYjkvU+/Kkn0iiCK0JLqw4dNqhCNrsU9bo/03vMI";

        [Fact]
        public void Encrypt128()
        {
            var data = Encoding.UTF8.GetBytes(Data);
            var cipher = Rijndael.Encrypt(data, Password, InitializationVector, KeySize.Aes128);
            Assert.Equal(Convert.ToBase64String(cipher), Cipher128);
        }

        [Fact]
        public void Encrypt192()
        {
            var data = Encoding.UTF8.GetBytes(Data);
            var cipher = Rijndael.Encrypt(data, Password, InitializationVector, KeySize.Aes192);
            Assert.Equal(Convert.ToBase64String(cipher), Cipher192);
        }

        [Fact]
        public void Encrypt256()
        {
            var data = Encoding.UTF8.GetBytes(Data);
            var cipher = Rijndael.Encrypt(data, Password, InitializationVector, KeySize.Aes256);
            Assert.Equal(Convert.ToBase64String(cipher), Cipher256);
        }

        [Fact]
        public void Decrypt128()
        {
            var data = Rijndael.Decrypt(Cipher128, Password, KeySize.Aes128);
            Assert.Equal(data, Data);
        }

        [Fact]
        public void Decrypt192()
        {
            var data = Rijndael.Decrypt(Cipher192, Password, KeySize.Aes192);
            Assert.Equal(data, Data);
        }

        [Fact]
        public void Decrypt256()
        {
            var data = Rijndael.Decrypt(Cipher256, Password, KeySize.Aes256);
            Assert.Equal(data, Data);
        }

        [Fact]
        public void RandomIv128()
        {
            var cipher1 = Rijndael.Encrypt(Data, Password, KeySize.Aes128);
            var cipher2 = Rijndael.Encrypt(Data, Password, KeySize.Aes128);
            var data = Rijndael.Decrypt(cipher1, Password, KeySize.Aes128);

            Assert.Equal(data, Data);
            Assert.NotEqual(cipher1, cipher2);
        }

        [Fact]
        public void RandomIv192()
        {
            var cipher1 = Rijndael.Encrypt(Data, Password, KeySize.Aes192);
            var cipher2 = Rijndael.Encrypt(Data, Password, KeySize.Aes192);
            var data = Rijndael.Decrypt(cipher1, Password, KeySize.Aes192);

            Assert.Equal(data, Data);
            Assert.NotEqual(cipher1, cipher2);
        }

        [Fact]
        public void RandomIv256()
        {
            var cipher1 = Rijndael.Encrypt(Data, Password, KeySize.Aes256);
            var cipher2 = Rijndael.Encrypt(Data, Password, KeySize.Aes256);
            var data = Rijndael.Decrypt(cipher1, Password, KeySize.Aes256);

            Assert.Equal(data, Data);
            Assert.NotEqual(cipher1, cipher2);
        }
    }
}
