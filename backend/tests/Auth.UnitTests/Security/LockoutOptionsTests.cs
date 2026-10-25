using Auth.Services.Security;

namespace Auth.UnitTests.Security;

/// <summary>T17 (T11 audit LOW-4): the failure window and level decay cannot be configured away.</summary>
public class LockoutOptionsTests
{
    [Theory]
    [InlineData(59, 24)]
    [InlineData(60, 0)]
    public void Windows_that_would_disable_the_protection_are_refused(int windowMinutes, int decayHours)
    {
        LockoutOptions options = new() { FailureWindow = TimeSpan.FromMinutes(windowMinutes), LevelDecayAfter = TimeSpan.FromHours(decayHours) };

        Assert.Throws<ArgumentOutOfRangeException>(() => options.Validated());
    }

    [Fact]
    public void The_defaults_are_valid()
    {
        LockoutOptions options = new LockoutOptions().Validated();

        Assert.Equal((TimeSpan.FromHours(1), TimeSpan.FromHours(24)), (options.FailureWindow, options.LevelDecayAfter));
    }
}
