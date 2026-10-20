using Haukcode.SigNet.Keys;
using Xunit;

namespace Haukcode.SigNet.UnitTest;

public class PassphraseValidatorTests
{
    [Theory]
    [InlineData("SigNetT3stVector1!")]
    [InlineData("Ge2p$E$4*A")]
    [InlineData("abcABC123x")]
    [InlineData("aa1BB2cc3D")]
    // Exactly 3 sequential is allowed, only 4 is rejected
    [InlineData("abcXyz135!")]
    public void Valid(string passphrase)
    {
        Assert.Equal(PassphraseValidationResult.Valid, PassphraseValidator.Validate(passphrase));
    }

    [Theory]
    [InlineData("", PassphraseValidationResult.TooShort)]
    [InlineData("Ab1!xyZ9", PassphraseValidationResult.TooShort)]
    [InlineData("Ab1!Ab1!Ab1!Ab1!Ab1!Ab1!Ab1!Ab1!Ab1!Ab1!Ab1!Ab1!Ab1!Ab1!Ab1!Ab1!X", PassphraseValidationResult.TooLong)]
    [InlineData("abcdefghXY", PassphraseValidationResult.ConsecutiveSequential)]
    [InlineData("Zyx1234abQ", PassphraseValidationResult.ConsecutiveSequential)]
    [InlineData("Pass4321wd", PassphraseValidationResult.ConsecutiveSequential)]
    // The reference compares code points, so symbol runs count too
    [InlineData("Ab9!\"#$xyQ", PassphraseValidationResult.ConsecutiveSequential)]
    [InlineData("aaaBBB111!", PassphraseValidationResult.ConsecutiveIdentical)]
    [InlineData("lowercaseonly", PassphraseValidationResult.InsufficientClasses)]
    [InlineData("lowerUPPERx", PassphraseValidationResult.InsufficientClasses)]
    // '~' is not in the spec's symbol class, so it adds no class
    [InlineData("lower~UPPER", PassphraseValidationResult.InsufficientClasses)]
    [InlineData("Ab1!Ab1!Ab1é", PassphraseValidationResult.InvalidCharacter)]
    public void Invalid(string passphrase, PassphraseValidationResult expected)
    {
        Assert.Equal(expected, PassphraseValidator.Validate(passphrase));
    }

    [Fact]
    public void FailureOrder_MatchesReference_IdenticalBeforeSequentialBeforeClassesBeforeLength()
    {
        // Short, one class, a sequence and a triple: the reference reports the triple first
        Assert.Equal(PassphraseValidationResult.ConsecutiveIdentical, PassphraseValidator.Validate("aaabcd"));
        // Short, one class, a sequence
        Assert.Equal(PassphraseValidationResult.ConsecutiveSequential, PassphraseValidator.Validate("abcd"));
        // Short and one class
        Assert.Equal(PassphraseValidationResult.InsufficientClasses, PassphraseValidator.Validate("abab"));
    }

    [Fact]
    public void Analyse_ReportsEveryCheck()
    {
        PassphraseValidator.Analyse("abc", out var checks);

        Assert.Equal(3, checks.Length);
        Assert.False(checks.LengthOk);
        Assert.True(checks.HasLower);
        Assert.False(checks.HasUpper);
        Assert.Equal(1, checks.ClassCount);
        Assert.True(checks.NoIdenticalRun);
        Assert.True(checks.NoSequentialRun);
    }

    [Fact]
    public void EveryResult_HasASpecificMessage()
    {
        foreach (var result in System.Enum.GetValues<PassphraseValidationResult>())
            Assert.DoesNotContain("not ready", PassphraseValidator.GetMessage(result));
    }
}
