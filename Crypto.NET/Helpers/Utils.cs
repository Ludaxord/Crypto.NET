using System;
using System.Linq;
using System.Text;

namespace Crypto.NET.Helpers{
    public static class Utils{
        public static string EncodeByteArray(this byte[] buffer){
            return buffer.Aggregate("", (current, theByte) => current + theByte.ToString("x2"));
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