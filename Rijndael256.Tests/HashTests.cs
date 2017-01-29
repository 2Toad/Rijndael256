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
        #region Properties

        const string Data = "8D17099FE0D44173BA0F66653DA7D48B";

        #endregion

        [Fact]
        public void Sha512()
        {
            const string proof = "5670CA06284E9328D363CD7F6986374D22806F21A106DE5EDFE5D5667B577B33D69024A1E13E468B44A9C4EE5542AB9" +
                "BC4D19BCF083BE1270D2E66A989105429";

            var hash = Hash.Sha512(Data);
            Assert.Equal(hash, proof);
        }

        [Fact]
        public void Pbkdf2()
        {
            const string salt = "0A9FDB669FA44FF1BEC484A1BE6B6E2A";
            const string proof100 = "Ae46Q6u3I7Z7MPuX5HbkahHII9jahV4o3NCug6Zt2yYVKWnCAwsokOGlyuIqwiqPqNIeiXxU8yBEO+6QnsobAw==";
            const string proof1000 = "/HpGVn9ti223R5H2c6Rj5EAaU3dEjH37Y9GRjFuOp3OlOAN5V1zI06CDLQqEgFuxjM8jesNM0G/3aQQpR72n7Q==";

            var hash100 = Hash.Pbkdf2(Data, salt, 100);
            var hash1000 = Hash.Pbkdf2(Data, salt, 1000);

            Assert.Equal(Convert.ToBase64String(hash100), proof100);
            Assert.Equal(Convert.ToBase64String(hash1000), proof1000);
            Assert.NotEqual(Convert.ToBase64String(hash100), Convert.ToBase64String(hash1000));
        }
    }
}
