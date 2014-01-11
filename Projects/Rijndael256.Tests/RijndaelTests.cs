using System;
using System.Text;
using NUnit.Framework;

namespace Rijndael256.Tests
{
    public class RijndaelTests
    {
        #region Properties

        const string Password = "A95D46AC30D44CFE-A403553D1D0F5D46";
        static readonly byte[] InitializationVector = Encoding.UTF8.GetBytes("D6BB4C14C3BF491F");
        const string Data = "8D17099FE0D44173BA0F66653DA7D48B";

        const string Cipher128 = "laxV572ARLFKlHHHCoW3KQM/gkildCBh7MGWncyAyfnOeFOqgnzLNysQWnDzGD6g";
        const string Cipher192 = "st8+AbnWhPRvlD+InbRmd0JZhcN7+LJMOciMi78eytvCcKk3PS8BiVhd2exK4QuM";
        const string Cipher256 = "NaiGDMg4vdWt7xOcCVGcoBGsX2HcbSOqnypn51xmYj8XqZduvJ++bD6bwwVuN6ih";

        #endregion

        [Test]
        public void Encrypt128()
        {
            var data = Encoding.UTF8.GetBytes(Data);
            var cipher = Rijndael.Encrypt(data, Password, InitializationVector, KeySize.Aes128);
            Assert.AreEqual(Convert.ToBase64String(cipher), Cipher128);
        }

        [Test]
        public void Encrypt192()
        {
            var data = Encoding.UTF8.GetBytes(Data);
            var cipher = Rijndael.Encrypt(data, Password, InitializationVector, KeySize.Aes192);
            Assert.AreEqual(Convert.ToBase64String(cipher), Cipher192);
        }

        [Test]
        public void Encrypt256()
        {
            var data = Encoding.UTF8.GetBytes(Data);
            var cipher = Rijndael.Encrypt(data, Password, InitializationVector, KeySize.Aes256);
            Assert.AreEqual(Convert.ToBase64String(cipher), Cipher256);
        }

        [Test]
        public void Decrypt128()
        {
            var cipher = Convert.FromBase64String(Cipher128);
            var data = Rijndael.Decrypt(cipher, Password, InitializationVector, KeySize.Aes128);
            Assert.AreEqual(Encoding.UTF8.GetString(data), Data);
        }

        [Test]
        public void Decrypt192()
        {
            var cipher = Convert.FromBase64String(Cipher192);
            var data = Rijndael.Decrypt(cipher, Password, InitializationVector, KeySize.Aes192);
            Assert.AreEqual(Encoding.UTF8.GetString(data), Data);
        }

        [Test]
        public void Decrypt256()
        {
            var cipher = Convert.FromBase64String(Cipher256);
            var data = Rijndael.Decrypt(cipher, Password, InitializationVector, KeySize.Aes256);
            Assert.AreEqual(Encoding.UTF8.GetString(data), Data);
        }

        [Test]
        public void RandomIv128()
        {
            var cipher1 = Rijndael.Encrypt(Data, Password, KeySize.Aes128);
            var cipher2 = Rijndael.Encrypt(Data, Password, KeySize.Aes128);
            var data = Rijndael.Decrypt(cipher1, Password, KeySize.Aes128);

            Assert.AreEqual(data, Data);
            Assert.AreNotEqual(cipher1, cipher2);
        }

        [Test]
        public void RandomIv192()
        {
            var cipher1 = Rijndael.Encrypt(Data, Password, KeySize.Aes192);
            var cipher2 = Rijndael.Encrypt(Data, Password, KeySize.Aes192);
            var data = Rijndael.Decrypt(cipher1, Password, KeySize.Aes192);

            Assert.AreEqual(data, Data);
            Assert.AreNotEqual(cipher1, cipher2);
        }

        [Test]
        public void RandomIv256()
        {
            var cipher1 = Rijndael.Encrypt(Data, Password, KeySize.Aes256);
            var cipher2 = Rijndael.Encrypt(Data, Password, KeySize.Aes256);
            var data = Rijndael.Decrypt(cipher1, Password, KeySize.Aes256);

            Assert.AreEqual(data, Data);
            Assert.AreNotEqual(cipher1, cipher2);
        }
    }
}
