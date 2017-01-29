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
    public class RijndaelAuthTests
    {
        const string Password = "Tomatoe Belize Gestalt Sierra";
        static readonly byte[] InitializationVector = Encoding.UTF8.GetBytes("D6BB4C14C3BF491F");
        const string Data = "This is my AES Authenticated secret phrase.";
        const string Cipher128 = "RDZCQjRDMTRDM0JGNDkxRkArkEm90ErIS0WCUfikunHgIwlfdPFqw9nfupUeC9TMqY6H2dOSs5jwmbNzGGCQV2Ve/RF24XigznkUwCTYQTNYAJpArITlx8G5grSmJAlWYZ3zSZH1DKrPGOfGxm5WmyfcUyYaMyZ3XBWTJAejzpE=";
        const string Cipher192 = "RDZCQjRDMTRDM0JGNDkxRn2W9qZjyZWePUzBqARLO+qv7djOGOiItxZDvRa2kOJ9jco+aECaA+Lh9Ak+0/1pscunkkBMK8GdYEZu7sRr6iHsUo8LITJ32nZPk/fbHKnATwVLe/iD+73Q68obCoI8ojRrC5VBLh3VtPh4WF8UF8Q=";
        const string Cipher256 = "RDZCQjRDMTRDM0JGNDkxRq5TioN0HlvFkhBmFF86p6oV8RVmjM0HZIb463VmMXzBx8AY2Or8YvPZs/vpyG3U2lg8tDJxc3cFqzhMrcv97dTAMrdrV93vSV4K9jLeA/OQzKOwmo6XIubGDYxDlzT9YYd7eEzdqWx3O/rwTSZpELA=";

        [Fact]
        public void Encrypt128()
        {
            var data = Encoding.UTF8.GetBytes(Data);
            var cipher = RijndaelAuth.Encrypt(data, Password, InitializationVector, KeySize.Aes128);
            Assert.Equal(Convert.ToBase64String(cipher), Cipher128);
        }

        [Fact]
        public void Encrypt192()
        {
            var data = Encoding.UTF8.GetBytes(Data);
            var cipher = RijndaelAuth.Encrypt(data, Password, InitializationVector, KeySize.Aes192);
            Assert.Equal(Convert.ToBase64String(cipher), Cipher192);
        }

        [Fact]
        public void Encrypt256()
        {
            var data = Encoding.UTF8.GetBytes(Data);
            var cipher = RijndaelAuth.Encrypt(data, Password, InitializationVector, KeySize.Aes256);
            Assert.Equal(Convert.ToBase64String(cipher), Cipher256);
        }

        [Fact]
        public void Decrypt128()
        {
            var data = RijndaelAuth.Decrypt(Cipher128, Password, KeySize.Aes128);
            Assert.Equal(data, Data);
        }

        [Fact]
        public void Decrypt192()
        {
            var data = RijndaelAuth.Decrypt(Cipher192, Password, KeySize.Aes192);
            Assert.Equal(data, Data);
        }

        [Fact]
        public void Decrypt256()
        {
            var data = RijndaelAuth.Decrypt(Cipher256, Password, KeySize.Aes256);
            Assert.Equal(data, Data);
        }

        [Fact]
        public void RandomIv128()
        {
            var cipher1 = RijndaelAuth.Encrypt(Data, Password, KeySize.Aes128);
            var cipher2 = RijndaelAuth.Encrypt(Data, Password, KeySize.Aes128);
            var data = RijndaelAuth.Decrypt(cipher1, Password, KeySize.Aes128);

            Assert.Equal(data, Data);
            Assert.NotEqual(cipher1, cipher2);
        }

        [Fact]
        public void RandomIv192()
        {
            var cipher1 = RijndaelAuth.Encrypt(Data, Password, KeySize.Aes192);
            var cipher2 = RijndaelAuth.Encrypt(Data, Password, KeySize.Aes192);
            var data = RijndaelAuth.Decrypt(cipher1, Password, KeySize.Aes192);

            Assert.Equal(data, Data);
            Assert.NotEqual(cipher1, cipher2);
        }

        [Fact]
        public void RandomIv256()
        {
            var cipher1 = RijndaelAuth.Encrypt(Data, Password, KeySize.Aes256);
            var cipher2 = RijndaelAuth.Encrypt(Data, Password, KeySize.Aes256);
            var data = RijndaelAuth.Decrypt(cipher1, Password, KeySize.Aes256);

            Assert.Equal(data, Data);
            Assert.NotEqual(cipher1, cipher2);
        }
    }
}
