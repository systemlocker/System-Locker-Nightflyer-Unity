// init-only setters and records need this marker type on profiles older than
// .NET 5 (like Unity's netstandard2.1 target). Unity 2021.2+ provides its own
// definition, so the guard prevents a duplicate type in supported players.
#if !UNITY_2019_1_OR_NEWER
namespace System.Runtime.CompilerServices
{
    internal static class IsExternalInit
    {
    }
}
#endif
