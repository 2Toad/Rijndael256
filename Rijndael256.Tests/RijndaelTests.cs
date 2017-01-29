/*
 * Rijndael256
 * Copyright (C)2013 2Toad, LLC.
 * licensing@2toad.com
 * 
 * http://2toad.com/Project/Rijndael256/License
 */

using System;
using System.Text;
using Xunit;

namespace Rijndael256.Tests
{
    public class RijndaelTests
    {
        #region Properties

        const string Password = "A95D46AC30D44CFE-A403553D1D0F5D46";
        static readonly byte[] InitializationVector = Encoding.UTF8.GetBytes("D6BB4C14C3BF491F");
        const string Data = "8D17099FE0D44173BA0F66653DA7D48B";

        const string Cipher128 = "jpbR3MrsIVIjXeBLF3+3vNyZ/xyBeJAH3JzX1FOYaXDxQcf96YOyEy1imKqXgc9w";
        const string Cipher192 = "87hQWJoPGdMrwz1qBcQi6cn6xw6xWWz+rjDlTkRzQYatKW7xR91OExJKSR+yA2+c";
        const string Cipher256 = "5s+yLHArUeal29ZZ/QZ6+7Z7qxoibIp6nzrLaE6T5MYYCPlFyGThsh+41beL1p+j";

        #endregion

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
            var cipher = Convert.FromBase64String(Cipher128);
            var data = Rijndael.Decrypt(cipher, Password, InitializationVector, KeySize.Aes128);
            Assert.Equal(Encoding.UTF8.GetString(data), Data);
        }

        [Fact]
        public void Decrypt192()
        {
            var cipher = Convert.FromBase64String(Cipher192);
            var data = Rijndael.Decrypt(cipher, Password, InitializationVector, KeySize.Aes192);
            Assert.Equal(Encoding.UTF8.GetString(data), Data);
        }

        [Fact]
        public void Decrypt256()
        {
            var cipher = Convert.FromBase64String(Cipher256);
            var data = Rijndael.Decrypt(cipher, Password, InitializationVector, KeySize.Aes256);
            Assert.Equal(Encoding.UTF8.GetString(data), Data);
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
