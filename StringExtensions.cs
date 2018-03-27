using System;
using System.Text.RegularExpressions;

using JetBrains.Annotations;

namespace NTRightsNet
{

    /// <summary>
    /// Extension methods for <see cref="string"/>.
    /// </summary>
    internal static class StringExtensions
    {

        //--------------------------------------------------
        [NotNull] public static string EscapeForColourOutput([CanBeNull] this string value)
        {
            return (string.IsNullOrEmpty(value)
                ? string.Empty
                : value.Replace("&", "&amp;"));
        }


        //--------------------------------------------------
        public static void WriteToConsoleWithColour([CanBeNull] this string value)
        {
            if (string.IsNullOrEmpty(value)) { return; }

            var currentIndex = 0;
            var currentColour = default(ConsoleColor?);
            var match = StringExtensions.ColourSpecRegex.Match(value);
            while (match.Success)
            {
                if (match.Index > currentIndex)
                {
                    Console.Write(value.Substring(currentIndex, match.Index - currentIndex));
                }

                var spec = match.Value.Substring(1, match.Value.Length - 2);
                switch (spec)
                {
                    case string s when StringComparer.OrdinalIgnoreCase.Equals("amp", s):
                        Console.Write('&');
                        break;

                    case string s when StringComparer.OrdinalIgnoreCase.Equals("reset", s):
                        currentColour = default;
                        Console.ResetColor();
                        break;

                    default:
                        if (Enum.TryParse<ConsoleColor>(spec, ignoreCase: true, result: out var parsedColour) && parsedColour != currentColour)
                        {
                            Console.ForegroundColor = parsedColour;
                            currentColour = parsedColour;
                        }
                        break;
                }

                currentIndex = match.Index + match.Length;
                match = match.NextMatch();
            }

            if (currentIndex < value.Length)
            {
                Console.Write(currentIndex > 0 ? value.Substring(currentIndex) : value);
            }

            if (currentColour.HasValue)
            {
                Console.ResetColor();
            }
        }



        //**************************************************
        //* Private
        //**************************************************

        [NotNull] private static readonly Regex ColourSpecRegex = new Regex("&[a-zA-Z]+;", RegexOptions.CultureInvariant);

    }

}
