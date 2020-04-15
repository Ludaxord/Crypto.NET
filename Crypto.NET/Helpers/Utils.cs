using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Crypto.NET.Helpers{
    public static class Utils{
        private const int CharSize = sizeof(char);

        //Main encode functions
        public static string EncodeByteArray(this byte[] buffer){
            return buffer.GetStringSafe();
        }

        public static byte[] ToByteArray(this string value){
            return value.GetBytesSafe();
        }

        //Main safe and unsafe encode functions
        public static string GetStringSafe(this byte[] buffer){
            return buffer.GetStringAggregate("x2");
        }

        public static byte[] GetBytesSafe(this string value){
            return value.HexToBytes();
        }

        public static byte[] CharArrayToByte(this string value){
            return value.ToCharArray().Select(Convert.ToByte).ToArray();
        }

        public static byte[] HexMatch(this string value){
            var bytes = new List<byte>();
            // const string reg = @"^(.*?)000000([a-zA-Z0-9]{2})";
            const string reg = @"(000000[a-zA-Z0-9]{2})";
            var matchList = Regex.Matches(value, reg);
            var list = matchList.Select(match => match.Value).ToList();
            foreach (var l in list){
                ConsoleExtended.WriteColorLine($"value => {l}");
                bytes.AddRange(HexToByteArray(l));
            }

            return bytes.ToArray();
        }

        public static string ToHex(this byte[] bytes){
            char[] c = new char[bytes.Length * 2];

            byte b;

            for (int bx = 0, cx = 0; bx < bytes.Length; ++bx, ++cx){
                b = ((byte) (bytes[bx] >> 4));
                c[cx] = (char) (b > 9 ? b + 0x37 + 0x20 : b + 0x30);

                b = ((byte) (bytes[bx] & 0x0F));
                c[++cx] = (char) (b > 9 ? b + 0x37 + 0x20 : b + 0x30);
            }

            return new string(c);
        }

        public static byte[] HexToBytes(this string str){
            if (str.Length == 0 || str.Length % 2 != 0)
                return new byte[0];

            byte[] buffer = new byte[str.Length / 2];
            char c;
            for (int bx = 0, sx = 0; bx < buffer.Length; ++bx, ++sx){
                // Convert first half of byte
                c = str[sx];
                buffer[bx] = (byte) ((c > '9' ? (c > 'Z' ? (c - 'a' + 10) : (c - 'A' + 10)) : (c - '0')) << 4);

                // Convert second half of byte
                c = str[++sx];
                buffer[bx] |= (byte) (c > '9' ? (c > 'Z' ? (c - 'a' + 10) : (c - 'A' + 10)) : (c - '0'));
            }

            return buffer;
        }


        //Types of encodings functions
        public static string GetStringFromChar(this byte[] buffer){
            return buffer.Aggregate("", (current, b) => current + Convert.ToChar(b));
        }

        public static string GetStringAggregate(this byte[] buffer, string format = "x2"){
            return buffer.Aggregate("", (current, b) => current + b.ToString(format));
        }

        public static byte[] HexToByteArray(string hex){
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }

        public static int GenerateRandom(int start, int stop){
            var rnd = new Random();
            var random = rnd.Next(start, stop);
            return random;
        }

        public static byte[] EncodeToByteArray(this string encodeString){
            return Encoding.UTF8.GetBytes(encodeString);
        }


        public static int? StringToInt(string obj){
            int? result = null;
            if (int.TryParse(obj, out var outInt)){
                result = outInt;
            }

            return result;
        }

        public static string ReverseString(this string s){
            var charArray = s.ToCharArray();
            Array.Reverse(charArray);
            return new string(charArray);
        }

        public static bool IsBase64(this string base64String){
            // Credit: oybek https://stackoverflow.com/users/794764/oybek
            if (string.IsNullOrEmpty(base64String) || base64String.Length % 4 != 0
                                                   || base64String.Contains(" ") || base64String.Contains("\t") ||
                                                   base64String.Contains("\r") || base64String.Contains("\n"))
                return false;

            try{
                Convert.FromBase64String(base64String);
                return true;
            }
            catch (Exception exception){
                // Handle the exception
            }

            return false;
        }

        public static string Base64Encode(this string plainText){
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }

        public static string Base64Decode(this string base64EncodedData){
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }

        private static readonly Random Random = new Random();

        public static ConsoleColor GetRandomConsoleColor(){
            var consoleColors = Enum.GetValues(typeof(ConsoleColor));
            var color = (ConsoleColor) consoleColors.GetValue(Random.Next(consoleColors.Length));
            if (color != ConsoleColor.Black){
                return color;
            }

            return (ConsoleColor) consoleColors.GetValue(Random.Next(consoleColors.Length));
        }
    }
}