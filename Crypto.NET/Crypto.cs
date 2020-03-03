using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Crypto.NET.Helpers;
using Crypto.NET.Objects;
using Sodium;

namespace Crypto.NET{
    public interface ICrypto{
        string GenerateCryptoHash(string message, int type);
        string GenerateGenericHash(string message, string key, int bytes);

        string GenerateGenericHashWithSalt(string message, string key, string salt, byte[] saltBytes, string personal,
            int bytes = 64);

        string GenerateGenericKey(int bytes = 64);
        string GenerateSalt(Crypto.SaltLength length);
    }

    public sealed class Crypto : ICrypto{
        public enum SaltLength{
            SaltShort = 16,
            SaltLong = 32
        }

        private enum CodeType{
            Difficulty = 62,
            Length = 1
        }

        private readonly Random _random = new Random();

        public string GenerateAuthToken(string message = null, int difficulty = 0, bool asBase64 = true){
            var hash = GenerateEncodedAuthHash(message, difficulty, asBase64);
            return hash.Token;
        }

        public Hash GenerateEncodedAuthHash(string message = null, int difficulty = 0, bool asBase64 = true){
            if (message == null){
                message = GenerateRandomMessage(20);
            }

            var (key, salt, tag) = GenerateAuthCredentials(message);
            var hashSha = GenerateCryptoHash(message, 0);
            var hashSha256 = GenerateCryptoHash(message, 256);
            var hashSha512 = GenerateCryptoHash(message, 512);
            var additionalData = new Dictionary<string, string>(){
                {"key", key},
                {"salt", salt},
                {"hashing_message", message}
            };
            var hash = EncodeCrossHash(new[]{tag, hashSha, hashSha256, hashSha512}, additionalData, difficulty,
                asBase64);

            return hash;
        }

        public Hash GenerateDecodedAuthHash(string crossHash){
            var hash = DecodeCrossHash(crossHash);
            return hash;
        }

        public void TestCrypto(int iterations = 100){
            var fails = 0;
            var success = 0;
            var observations = 0;
            var failedLists = new List<Dictionary<string, Hash>>();
            for (var i = 0; i < iterations; i++){
                var encodedHash = GenerateEncodedAuthHash(difficulty: 10);
                var decodedHash = GenerateDecodedAuthHash(encodedHash.Token);

                var test1 = encodedHash.Hashes;
                var test2 = decodedHash.Hashes;
                foreach (var hash1 in test1){
                    var hash2 = test2.Find(x => x == hash1);
                    var equal = hash1 == hash2;
                    if (equal){
                        test2.Remove(hash2);
                        success++;
                    }
                    else{
                        fails++;
                        failedLists.Add(new Dictionary<string, Hash>
                            {{"encoded_hash", encodedHash},{"decoded_hash", decodedHash}}
                        );
                    }

                    observations++;
                }
            }

            ConsoleExtended.WriteColorLine("results:");
            ConsoleExtended.WriteColorLine($"successful results {success} of {observations} observations");
            ConsoleExtended.WriteColorLine($"failed results {fails} of {observations} observations");
            if (fails <= 0) return;
            ConsoleExtended.WriteColorLine("failed at observations:");
            foreach (var failedList in failedLists){
                var enc = failedList["encoded_hash"];
                var dec = failedList["decoded_hash"];
                ConsoleExtended.WriteColorLine("failed observation encoded:");
                foreach (var eh in enc.Hashes){
                    ConsoleExtended.WriteColorLine(eh);
                }

                ConsoleExtended.WriteColorLine("failed observation decoded:");
                foreach (var dh in dec.Hashes){
                    ConsoleExtended.WriteColorLine(dh);
                }

                Console.WriteLine("---------------------------------------------------");
            }
        }

        private string GenerateRandomMessage(int length){
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[_random.Next(s.Length)]).ToArray());
        }

        private Hash EncodeCrossHash(IEnumerable<string> hashes, Dictionary<string, string> additionalData,
            int difficulty = 0, bool asBase64 = true){
            var crossHash = "";
            var difficultySum = "";
            var index = 0;
            var h = hashes.ToList();
            foreach (var tag in h){
                var hashChar = tag.ToCharArray();
                if (difficulty <= 0){
                    crossHash = hashChar.Aggregate(crossHash, (current, c) => current + c);
                    crossHash += difficulty;
                }
                else if (difficulty > 0 && difficulty < 5){
                    if (index == 0){
                        crossHash = hashChar.Aggregate(crossHash, (current, c) => current + c);
                    }
                    else{
                        crossHash = hashChar.Aggregate(crossHash,
                            (current, hashElement) => current.Insert(difficulty, hashElement.ToString()));
                    }

                    difficultySum += $"lo{difficulty * 62}ol";
                }
                else{
                    if (index == 0){
                        crossHash = hashChar.Aggregate(crossHash, (current, c) => current + c);
                    }
                    else{
                        var randomDifficulty = Utils.GenerateRandom(difficulty > crossHash.Length - 1 ? 0 : difficulty,
                            crossHash.Length - 1);
                        crossHash = hashChar.Aggregate(crossHash,
                            (current, c) => current.Insert(randomDifficulty, c.ToString()));

                        difficultySum += $"lo{randomDifficulty * 62}ol";
                    }
                }

                index++;
            }


            var crossRemoved = crossHash;

            crossHash += GenerateTrollCode(difficultySum, h);

            if (asBase64){
                crossHash = crossHash.Base64Encode();
            }

            var hash = new Hash{
                Token = crossHash,
                HashToken = crossRemoved,
                Hashes = h,
                Salt = additionalData["salt"],
                Key = additionalData["key"],
                HashingMessage = additionalData["hashing_message"]
            };

            return hash;
        }

        private Hash DecodeCrossHash(string crossHash){
            var hashes = new List<string>();
            if (crossHash.IsBase64()){
                crossHash = crossHash.Base64Decode();
            }

            var hash = GetHashesFromDecodedToken(crossHash);
            var hashToken = hash.HashToken;
            hash.HashesLengthList.Reverse();
            hash.DifficultiesList.Reverse();

            var ch = hashToken.ToCharArray().ToList();
            for (var i = 0; i < hash.HashesLengthList.Count; i++){
                var hashLength = i == 0 ? hash.HashesLengthList.First() : hash.HashesLengthList[i];
                try{
                    var difficulty = i == 0 ? hash.DifficultiesList.First() : hash.DifficultiesList[i];
                    try{
                        var temp = hashToken.Substring(difficulty, hashLength);
                        hashToken = hashToken.Remove(difficulty, hashLength);
                        var t = temp.ReverseString();
                        hashes.Add(t);
                    }
                    catch (Exception e){
                        ConsoleExtended.WriteColorLine(
                            $"EXCEPTION: {e.Message} \nlengths: {difficulty}, {hashLength}, {hashToken.Length}");
                    }
                }
                catch (Exception){
                    hashes.Add(hashToken);
                }
            }

            hash.Hashes = hashes;

            return hash;
        }

        private byte[] GenerateSaltBytes(SaltLength length = SaltLength.SaltLong){
            var salt = length == SaltLength.SaltLong
                ? PasswordHash.ScryptGenerateSalt()
                : PasswordHash.ArgonGenerateSalt();
            return salt;
        }

        private Hash GetHashesFromDecodedToken(string crossHash){
            var (hashLengthInt, removedFromLen) = GetHashesLength(crossHash, true);
            var crossRemoved = removedFromLen;
            var (difficultiesList, removedFromDifficulties) =
                GetCodes(crossRemoved, new[]{"lo", "ol"}, true, CodeType.Difficulty);
            crossRemoved = removedFromDifficulties;
            var (lengthList, removedFromHashLength) = GetCodes(crossRemoved, new[]{"lm", "ao"}, true, CodeType.Length);
            crossRemoved = removedFromHashLength;
            var hash = new Hash{
                Token = crossHash,
                HashToken = crossRemoved,
                DifficultiesList = difficultiesList,
                HashesObjectsLength = hashLengthInt,
                HashesLengthList = lengthList
            };
            return hash;
        }

        private (List<int>, string) GetCodes(string crossHash, IReadOnlyList<string> codes, bool removeFromOriginal,
            CodeType type){
            var codesList = new List<int>();
            var removed = crossHash;
            var regex = new Regex($@"(?<={codes[0]})\d+(?={codes[1]}?)");
            var matches = regex.Matches(crossHash);
            for (var count = 0; count < matches.Count; count++){
                var match = matches[count].Value;
                var code = Utils.StringToInt(match);
                if (removeFromOriginal){
                    removed = removed.Replace($"{codes[0]}{match}{codes[1]}", "");
                }

                if (code != null){
                    switch (type){
                        case CodeType.Difficulty:
                            codesList.Add((int) (code / 62));
                            break;
                        case CodeType.Length:
                            codesList.Add((int) code);
                            break;
                        default:
                            throw new ArgumentOutOfRangeException(nameof(type), type, null);
                    }
                }
            }

            return (codesList, removed);
        }

        private (int, string) GetHashesLength(string crossHash, bool removeFromOriginal){
            var removed = crossHash;
            var lastIndexOfTrollCode = crossHash.LastIndexOf("xd", StringComparison.Ordinal);
            if (lastIndexOfTrollCode <= 0) return (0, removed);
            var len = crossHash.Substring(lastIndexOfTrollCode + 2);
            if (removeFromOriginal){
                removed = crossHash.Remove(lastIndexOfTrollCode, len.Length + 2);
            }

            var hashesLength = Utils.StringToInt(len);
            return hashesLength != null ? ((int) (hashesLength / 43), removed) : (0, removed);
        }

        private string GenerateTrollCode(string difficultySum, ICollection h){
            var lmao = h.Cast<object>().Aggregate("", (current, hash) => current + $"lm{((string) hash).Length}ao");
            var trollCode = lmao + difficultySum + "xd" + (h.Count * 43);
            return trollCode;
        }

        private (string, string, string) GenerateAuthCredentials(string message){
            var key = GenerateGenericKey(32);
            var salt = GenerateSaltBytes(SaltLength.SaltShort);
            var hash = GenerateGenericHashWithSalt(message, key, saltBytes: salt);
            return (key, salt.EncodeByteArray(), hash);
        }

        public string GenerateGenericKey(int bytes = 64){
            if (bytes == 64){
                var key = GenericHash.GenerateKey();
                return key.EncodeByteArray();
            }
            else{
                var key = SodiumCore.GetRandomBytes(bytes);
                return key.EncodeByteArray();
            }
        }

        public string GenerateGenericHash(string message, string key, int bytes = 64){
            var hash = GenericHash.Hash(message, key, bytes);
            return hash.EncodeByteArray();
        }

        public string GenerateGenericHashWithSalt(string message, string key, string salt = null,
            byte[] saltBytes = null,
            string personal = "crypto_lib_user_",
            int bytes = 64){
            if (salt == null && saltBytes == null){
                saltBytes = GenerateSaltBytes(SaltLength.SaltShort);
            }

            if (salt != null){
                saltBytes = salt.EncodeToByteArray();
            }

            var hash = GenericHash.HashSaltPersonal(message.EncodeToByteArray(), key.EncodeToByteArray(), saltBytes,
                personal.EncodeToByteArray(), bytes);
            return hash.EncodeByteArray();
        }

        public string GenerateSalt(SaltLength length = SaltLength.SaltLong){
            var salt = length == SaltLength.SaltLong
                ? PasswordHash.ScryptGenerateSalt()
                : PasswordHash.ArgonGenerateSalt();
            return salt.EncodeByteArray();
        }

        public string GenerateCryptoHash(string message, int type = 0){
            switch (type){
                case 256:
                    var sha256 = CryptoHash.Sha256(message);
                    return sha256.EncodeByteArray();
                case 512:
                    var sha512 = CryptoHash.Sha512(message);
                    return sha512.EncodeByteArray();
                case 0:
                    var shaHash = CryptoHash.Hash(message);
                    return shaHash.EncodeByteArray();
                default:
                    var shaDefault = CryptoHash.Hash(message);
                    return shaDefault.EncodeByteArray();
            }
        }
    }
}