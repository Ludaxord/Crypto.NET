using System.Collections.Generic;
using Crypto.NET.Helpers;

namespace Crypto.NET.Objects{
    /// <summary>
    /// 
    /// </summary>
    public class Hash{
        /// <summary>
        /// 
        /// </summary>
        public string Token;

        /// <summary>
        /// 
        /// </summary>
        public string HashToken;

        /// <summary>
        /// 
        /// </summary>
        public List<string> Hashes;

        /// <summary>
        /// 
        /// </summary>
        public List<int> DifficultiesList;

        /// <summary>
        /// 
        /// </summary>
        public int HashesObjectsLength;

        /// <summary>
        /// 
        /// </summary>
        public List<int> HashesLengthList;

        /// <summary>
        /// 
        /// </summary>
        public bool Verified;

        /// <summary>
        /// 
        /// </summary>
        public string Salt;

        /// <summary>
        /// 
        /// </summary>
        public string Key;

        /// <summary>
        /// 
        /// </summary>
        public string HashingMessage;

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public string GetAsBase64(){
            return !Token.IsBase64() ? Token.Base64Encode() : Token;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public string GetFromBase64(){
            return Token.IsBase64() ? Token.Base64Decode() : Token;
        }
    }
}