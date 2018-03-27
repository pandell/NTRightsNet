using System.ComponentModel;

using JetBrains.Annotations;

// "ROP": Railway Oriented Programming. For more info see:
// https://fsharpforfunandprofit.com/rop/
// https://fsharpforfunandprofit.com/posts/recipe-part2/

namespace NTRightsNet
{

    //--------------------------------------------------
    /// <summary>
    /// Simple railway-oriented programming general result.
    /// </summary>
    // ReSharper disable once UnusedTypeParameter - type is used to document what type is being returned (when successful)
    internal abstract class Result<T> {}


    //--------------------------------------------------
    /// <summary>
    /// Simple railway-oriented programming failure result.
    /// </summary>
    /// <inheritdoc />
    internal sealed class Failure<T> : Result<T>
    {
        public Failure([NotNull] string message, int win32Error = 0)
        {
            this.Message = (win32Error == 0
                ? message
                : $"{message} (0x{win32Error:X8}: {new Win32Exception(win32Error).Message})");
        }
        [NotNull] public string Message { get; }
    }


    //--------------------------------------------------
    /// <summary>
    /// Simple railway-oriented programming successful result.
    /// </summary>
    /// <inheritdoc />
    internal sealed class Success<T> : Result<T>
    {
        public Success([NotNull] T value)
        {
            this.Value = value;
        }
        [NotNull] public T Value { get; }
    }

}
