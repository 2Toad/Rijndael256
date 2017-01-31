/*
 * Rijndael256
 * Copyright (C)2013 2Toad, LLC.
 * licensing@2toad.com
 * 
 * https://github.com/2Toad/Rijndael256
 */

using System;
using System.Linq;
using Xunit;

namespace Rijndael256.Tests
{
    public class SettingsTests
    {
        const string Plaintext = "A secret phrase to test hashing.";
        const string Salt = "0A9FDB669FA44FF1BEC484A1BE6B6E2A";

        [Fact]
        public void HashIterations()
        {
            var proofDefault = Convert.FromBase64String("pGnGDWwZAVvIlmDgGZ1gkvqEqm2DvkYdPRygUjZGIW/Ts+q2R+ZdMlRzfV1Dlz4udcHwS+A/1TjP+6jBDUTBMQ==");

            var hashDefault = Hash.Pbkdf2(Plaintext, Salt, Settings.HashIterations);
            Assert.True(hashDefault.SequenceEqual(proofDefault));

            Settings.HashIterations = 500;

            var hashChanged = Hash.Pbkdf2(Plaintext, Salt, Settings.HashIterations);
            Assert.False(hashChanged.SequenceEqual(proofDefault));

            RestoreDefaults();
        }

        /// <summary>
        /// Settings is global, so we need to restore defaults before the other
        /// unit tests, which depend on said defaults, are run.
        /// </summary>
        private void RestoreDefaults()
        {
            Settings.HashIterations = 10000;
        }
    }
}
