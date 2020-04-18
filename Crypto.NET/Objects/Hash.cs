using System.Collections.Generic;
using Crypto.NET.Helpers;

namespace Crypto.NET.Objects{
    /// <summary>
    /// Main datatype of Crypto Library.
    /// </summary>
    public class Hash{
        /// <summary>
        /// Less accurate Token it does not has all information about difficulty.
        /// </summary>
        public string Token;

        /// <summary>
        /// Result of all hashing methods it is called CrossHash. In Hash object it is called HashToken.
        /// </summary>
        public string HashToken;

        /// <summary>
        /// hashes List
        /// </summary>
        public List<string> Hashes;

        /// <summary>
        /// difficulties List of hashes
        /// </summary>
        public List<int> DifficultiesList;

        /// <summary>
        ///  Length of objects
        /// </summary>
        public int HashesObjectsLength;

        /// <summary>
        ///  Length List of hashes
        /// </summary>
        public List<int> HashesLengthList;

        /// <summary>
        /// Verification parameter - check if CrossHash (HashToken) is valid
        /// </summary>
        public bool Verified;

        /// <summary>
        /// Salt for hashing messages
        /// </summary>
        public string Salt;

        /// <summary>
        /// Key for hashing messages
        /// </summary>
        public string Key;

        /// <summary>
        /// Message that is going to be hashed with crossHash
        /// </summary>
        public string HashingMessage;

        /// <summary>
        /// Change to Base64
        /// </summary>
        /// <returns>Base64 Hash</returns>
        public string GetAsBase64(){
            return !Token.IsBase64() ? Token.Base64Encode() : Token;
        }

        /// <summary>
        /// Change from Base64
        /// </summary>
        /// <returns>Decrypted Base64 Hash</returns>
        public string GetFromBase64(){
            return Token.IsBase64() ? Token.Base64Decode() : Token;
        }
    }
}