/*
 * Rijndael256
 * Copyright (C)2013 2Toad, LLC.
 * licensing@2toad.com
 * 
 * https://github.com/2Toad/Rijndael256
 */

using System;
using System.Linq;
using System.Text;
using Xunit;

namespace Rijndael256.Tests
{
    public class RijndaelEtMTests
    {
        const string Password = "Tomatoe Belize Gestalt Sierra";
        static readonly byte[] Iv = Encoding.UTF8.GetBytes("D6BB4C14C3BF491F");
        const string Plaintext = "A secret phrase to test AES using AE Encrypt-then-MAC mode.";

        const string EtmProof128 = "RDZCQjRDMTRDM0JGNDkxRtS+RAdwVMS6M5pj72jp1pV0aVj4QvZ5EBWQgwzSvF3i5K9PiI8BoV4X0jg9+kBcJu1YJCStyy+GhUfCIpeFoIakL43pla1AmYtw4s5ZK2Vst+eWsrcRgz/087FjfNtWwAqd1OtH8CgNkpOK+7WD9uP2hBK3fYnameaK/egB4Xdc";
        const string EtmProof192 = "RDZCQjRDMTRDM0JGNDkxRnUSZIKdb+0yFIiQdG2z9DHcqEWBv6TLuJGo4iQdRPcWjcIh+xjU3MxAel+1V6rIT2QsqyEHgDj/UmJinEwEn0JzV9tor4K0mS/ELRL1ziIs8DeNOXmDJdL2N5ivz6Fx1vahgiXDCG4jbZfwzLexG/yOIsFdN5EDSIGmyVEbRV0g";
        const string EtmProof256 = "RDZCQjRDMTRDM0JGNDkxRtwcUOKuBaOOpLPY2hUdMZC9flT2NF9oOVCGTb0kGugKZ7XYd/AlHG1JbBwcfmfGffkcP8tsrc02aBUNwSXzMP4ssvTFAdeOFgahnomVwL1W2Gbhd7bqTKIrptYzBPlKDOWOvAPWBvd4KLctZMJ2bkKZMwenqCXNq3FfNXxvggag";

        static readonly byte[] MacProof128 = Convert.FromBase64String("Mj88Yf3cfDOY+pnjcpVKwbaITgF25hPORX2H+lETXuz5AoIaEyZ0f9a1Enf1WK2VMHlb75DW5STs9z8NaT96bA==");
        static readonly byte[] MacProof192 = Convert.FromBase64String("20SB6UTQZmIcrHROvR7UIrIWlQ6VEDYmJy0ZI/iO6fJh6JOyPPEADsGvHPVfWlSbB/dlwu8NKD5xf3uF61mswA==");
        static readonly byte[] MacProof256 = Convert.FromBase64String("BHpBmrYfKRN/Xg1ZULOWMD7naD/dgydjKXPhQIauOtgnDXI6HPY+N1C6IrjKP0JbFfMbGVuoADA3eC2q/ZcX2g==");

        static readonly AeKeyRing AeKeyRingProof = new AeKeyRing {
            CipherKey = "238FB434AE3ADCFFB6C02CD7275EB3847A957E1726AC55204C6CF8DF1F0EA2D8",
            MacKey = Convert.FromBase64String("MkQ0NTM2MzYyOUExM0I2MDVCQjUyNjNFNkY0N0U4OEVBOTk5NEI1RDA0NkZCQTA5NUI1QjQzQTkwODY0RDA2Mg==")
        };

        [Fact]
        public void Encrypt128()
        {
            var plaintext = Encoding.UTF8.GetBytes(Plaintext);
            var etmCiphertext = RijndaelEtM.Encrypt(plaintext, Password, Iv, KeySize.Aes128);
            Assert.Equal(Convert.ToBase64String(etmCiphertext), EtmProof128);
        }

        [Fact]
        public void Encrypt192()
        {
            var plaintext = Encoding.UTF8.GetBytes(Plaintext);
            var etmCiphertext = RijndaelEtM.Encrypt(plaintext, Password, Iv, KeySize.Aes192);
            Assert.Equal(Convert.ToBase64String(etmCiphertext), EtmProof192);
        }

        [Fact]
        public void Encrypt256()
        {
            var plaintext = Encoding.UTF8.GetBytes(Plaintext);
            var etmCiphertext = RijndaelEtM.Encrypt(plaintext, Password, Iv, KeySize.Aes256);
            Assert.Equal(Convert.ToBase64String(etmCiphertext), EtmProof256);
        }

        [Fact]
        public void Decrypt128()
        {
            var plaintext = RijndaelEtM.Decrypt(EtmProof128, Password, KeySize.Aes128);
            Assert.Equal(plaintext, Plaintext);
        }

        [Fact]
        public void Decrypt192()
        {
            var plaintext = RijndaelEtM.Decrypt(EtmProof192, Password, KeySize.Aes192);
            Assert.Equal(plaintext, Plaintext);
        }

        [Fact]
        public void Decrypt256()
        {
            var plaintext = RijndaelEtM.Decrypt(EtmProof256, Password, KeySize.Aes256);
            Assert.Equal(plaintext, Plaintext);
        }

        [Fact]
        public void RandomIv128()
        {
            var etmCiphertext1 = RijndaelEtM.Encrypt(Plaintext, Password, KeySize.Aes128);
            var etmCiphertext2 = RijndaelEtM.Encrypt(Plaintext, Password, KeySize.Aes128);
            var plaintext = RijndaelEtM.Decrypt(etmCiphertext1, Password, KeySize.Aes128);

            Assert.Equal(plaintext, Plaintext);
            Assert.NotEqual(etmCiphertext1, etmCiphertext2);
        }

        [Fact]
        public void RandomIv192()
        {
            var etmCiphertext1 = RijndaelEtM.Encrypt(Plaintext, Password, KeySize.Aes192);
            var etmCiphertext2 = RijndaelEtM.Encrypt(Plaintext, Password, KeySize.Aes192);
            var plaintext = RijndaelEtM.Decrypt(etmCiphertext1, Password, KeySize.Aes192);

            Assert.Equal(plaintext, Plaintext);
            Assert.NotEqual(etmCiphertext1, etmCiphertext2);
        }

        [Fact]
        public void RandomIv256()
        {
            var etmCiphertext1 = RijndaelEtM.Encrypt(Plaintext, Password, KeySize.Aes256);
            var etmCiphertext2 = RijndaelEtM.Encrypt(Plaintext, Password, KeySize.Aes256);
            var plaintext = RijndaelEtM.Decrypt(etmCiphertext1, Password, KeySize.Aes256);

            Assert.Equal(plaintext, Plaintext);
            Assert.NotEqual(etmCiphertext1, etmCiphertext2);
        }

        [Fact]
        public void CalculateMac128()
        {
            var proof128 = Convert.FromBase64String(EtmProof128);
            var mac = RijndaelEtM.CalculateMac(proof128, Iv);
            Assert.True(mac.SequenceEqual(MacProof128));
        }

        [Fact]
        public void CalculateMac192()
        {
            var proof192 = Convert.FromBase64String(EtmProof192);
            var mac = RijndaelEtM.CalculateMac(proof192, Iv);
            Assert.True(mac.SequenceEqual(MacProof192));
        }

        [Fact]
        public void CalculateMac256()
        {
            var proof256 = Convert.FromBase64String(EtmProof256);
            var mac = RijndaelEtM.CalculateMac(proof256, Iv);
            Assert.True(mac.SequenceEqual(MacProof256));
        }

        [Fact]
        public void GenerateAeKeyRing()
        {
            var keyRing = AeKeyRing.Generate(Password);

            Assert.Equal(keyRing.CipherKey, AeKeyRingProof.CipherKey);
            Assert.True(keyRing.MacKey.SequenceEqual(AeKeyRingProof.MacKey));
        }
    }
}
