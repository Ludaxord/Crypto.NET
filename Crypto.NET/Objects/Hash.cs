using System.Collections.Generic;
using Crypto.NET.Helpers;

namespace Crypto.NET.Objects{
    public class Hash{
        public string Token;
        public string HashToken;
        public List<string> Hashes;
        public List<int> DifficultiesList;
        public int HashesObjectsLength;
        public List<int> HashesLengthList;
        public bool Verified;
        public string Salt;
        public string Key;
        public string HashingMessage;

        public string GetAsBase64(){
            return !Token.IsBase64() ? Token.Base64Encode() : Token;
        }

        public string GetFromBase64(){
            return Token.IsBase64() ? Token.Base64Decode() : Token;
        }
    }
}