/*
 * Rijndael256
 * Copyright (C)2013 2Toad, LLC.
 * licensing@2toad.com
 * 
 * https://github.com/2Toad/Rijndael256
 */

using System;
using Xunit;

namespace Rijndael256.Tests
{
    public class HashTests
    {
        const string Plaintext = "A secret phrase to test hashing.";

        [Fact]
        public void Sha512()
        {
            const string proof = "1BF40EE7C7D63646BECD264677DB01089C139BC96CC75373999A3FD7EFFB193FA57C7A7CA7949F1F488D05401EFA" +
                "C156334EB4C120727D8FDEC9F6975809D248";

            var hash = Hash.Sha512(Plaintext);
            Assert.Equal(hash, proof);
        }

        [Fact]
        public void Pbkdf2()
        {
            const string salt = "0A9FDB669FA44FF1BEC484A1BE6B6E2A";
            const string proof100 = "M7j/OS8d2EPXGHKw3Is+R+A4xsDUlfDkW0sl7hfFLZkH7VG2kb0EYezSZNW/Diqto5Q1dRvb/FP5uzLJZgCvIQ==";
            const string proof1000 = "rYCf8xf1sJpnPhK0P1tjRlI6iZVH1gbPUHRCMXgkiw8mK/Z1YsSK6r6lS9RNO3PidRlwQQobTX8DySvxezfuEA==";
            const string proof10000 = "pGnGDWwZAVvIlmDgGZ1gkvqEqm2DvkYdPRygUjZGIW/Ts+q2R+ZdMlRzfV1Dlz4udcHwS+A/1TjP+6jBDUTBMQ==";

            var hash100 = Hash.Pbkdf2(Plaintext, salt, 100);
            var hash1000 = Hash.Pbkdf2(Plaintext, salt, 1000);
            var hash10000 = Hash.Pbkdf2(Plaintext, salt, 10000);

            Assert.Equal(Convert.ToBase64String(hash100), proof100);
            Assert.Equal(Convert.ToBase64String(hash1000), proof1000);
            Assert.Equal(Convert.ToBase64String(hash10000), proof10000);
        }
    }
}
