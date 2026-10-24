using Auth.Services.Passwords;

namespace Auth.UnitTests.Passwords;

public class PasswordPolicyTests
{
    private static readonly CommonPasswordList CommonPasswords = new();

    private readonly PasswordPolicy policy = new(CommonPasswords);

    [Theory]
    [InlineData("violet-canyon-7319")]
    [InlineData("twelve-chars")]
    [InlineData("correct horse battery staple")]
    public void Long_uncommon_password_is_accepted(string password)
    {
        Assert.Empty(policy.Validate(password, "someone@example.test"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("a")]
    [InlineData("eleven-char")]
    public void Password_shorter_than_12_is_rejected(string password)
    {
        Assert.Contains(PasswordPolicyViolation.TooShort, policy.Validate(password, null));
    }

    [Fact]
    public void Length_counts_code_points_not_UTF16_units()
    {
        string twelveEmoji = string.Concat(Enumerable.Repeat("\U0001F510", 12));
        string sixEmoji = string.Concat(Enumerable.Repeat("\U0001F510", 6));

        Assert.DoesNotContain(PasswordPolicyViolation.TooShort, policy.Validate(twelveEmoji, null));
        Assert.Contains(PasswordPolicyViolation.TooShort, policy.Validate(sixEmoji, null));
    }

    [Fact]
    public void Password_longer_than_128_is_rejected()
    {
        Assert.Contains(PasswordPolicyViolation.TooLong, policy.Validate(new string('x', 129), null));
        Assert.DoesNotContain(PasswordPolicyViolation.TooLong, policy.Validate("violet-canyon-" + new string('x', 114), null));
    }

    [Theory]
    [InlineData("qwerty123456")]
    [InlineData("QWERTY123456")]
    [InlineData("Qwerty123456")]
    [InlineData("1qaz2wsx3edc")]
    [InlineData("1QAZ2WSX3EDC")]
    [InlineData("123qweasdzxc")]
    [InlineData("q1w2e3r4t5y6")]
    public void Password_on_the_common_list_is_rejected_in_any_case(string password)
    {
        Assert.Equal([PasswordPolicyViolation.Common], policy.Validate(password, null));
    }

    [Fact]
    public void Short_common_password_reports_both_rules()
    {
        IReadOnlyList<PasswordPolicyViolation> violations = policy.Validate("Password", null);

        Assert.Contains(PasswordPolicyViolation.TooShort, violations);
        Assert.Contains(PasswordPolicyViolation.Common, violations);
    }

    [Theory]
    [InlineData("long.username.example@example.test", "long.username.example")]
    [InlineData("long.username.example@example.test", "LONG.USERNAME.EXAMPLE")]
    [InlineData("first+tag.lastname@example.test", "First+Tag.Lastname")]
    public void Password_equal_to_the_email_local_part_is_rejected(string email, string password)
    {
        Assert.Contains(PasswordPolicyViolation.MatchesEmail, policy.Validate(password, email));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("other.person.name@example.test")]
    public void Password_not_equal_to_the_local_part_is_not_flagged(string? email)
    {
        Assert.DoesNotContain(PasswordPolicyViolation.MatchesEmail, policy.Validate("long.username.example", email));
    }

    [Fact]
    public void Bundled_list_is_loaded_with_about_100k_entries()
    {
        Assert.InRange(CommonPasswords.Count, 90_000, 100_000);
        Assert.True(CommonPasswords.Contains("PASSWORD"));
    }
}
