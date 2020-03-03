using System;

namespace Crypto.NET.Helpers{
    public static class ConsoleExtended{
        public static void WriteColorLine(string message){
            var oldColor = Console.ForegroundColor;
            Console.ForegroundColor = Utils.GetRandomConsoleColor();
            Console.WriteLine(message);
            Console.ForegroundColor = oldColor;
        }

        public static void WriteLine(string message){
            Console.WriteLine(message);
        }
    }
}