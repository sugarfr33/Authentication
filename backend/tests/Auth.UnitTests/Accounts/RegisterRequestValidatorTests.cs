using Auth.Contracts.Requests;
using Auth.Services.Accounts;
using Auth.Services.Passwords;

namespace Auth.UnitTests.Accounts;

/// <summary>T12: hand-written sign-up validation; errors are keyed by JSON field name.</summary>
public class RegisterRequestValidatorTests
{
    private const string GoodPassword = "violet-canyon-7319";

    private static readonly RegisterRequestValidator Validator = new(new PasswordPolicy(new CommonPasswordList()));

    [Theory]
    [InlineData("ada@example.test")]
    [InlineData("  Ada.Lovelace+tag@Example.TEST  ")]
    [InlineData("o'brien@sub.example.co.uk")]
    public void Valid_request_has_no_errors(string email)
    {
        Assert.Empty(Validator.Validate(new RegisterRequest(email, GoodPassword, "Ada Lovelace")));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("plainaddress")]
    [InlineData("@example.test")]
    [InlineData("ada@")]
    [InlineData("ada@@example.test")]
    [InlineData("ada@example")]
    [InlineData("ada@.example.test")]
    [InlineData("ada@example..test")]
    [InlineData("ada lovelace@example.test")]
    [InlineData("Ada <ada@example.test>")]
    [InlineData("ada\u0001@example.test")]
    public void Bad_email_is_rejected(string email)
    {
        Assert.True(Validator.Validate(new RegisterRequest(email, GoodPassword, "Ada")).ContainsKey(AuthRequestFields.Email));
    }

    [Fact]
    public void Email_or_local_part_too_long_is_rejected()
    {
        string longLocal = new string('a', 65) + "@example.test";
        string longTotal = new string('a', 60) + "@" + new string('b', 200) + ".example.test";

        Assert.True(Validator.Validate(new RegisterRequest(longLocal, GoodPassword, "Ada")).ContainsKey(AuthRequestFields.Email));
        Assert.True(Validator.Validate(new RegisterRequest(longTotal, GoodPassword, "Ada")).ContainsKey(AuthRequestFields.Email));
    }

    [Theory]
    [InlineData("short", "Password must be at least 12 characters.")]
    [InlineData("password1234", "Password is too common; choose a less predictable one.")]
    [InlineData("ada.lovelace.x", "Password must not be the same as the email address.")]
    public void Password_policy_violations_are_reported(string password, string message)
    {
        IReadOnlyDictionary<string, string[]> errors = Validator.Validate(new RegisterRequest("ada.lovelace.x@example.test", password, "Ada"));

        Assert.Contains(message, errors["password"]);
    }

    [Fact]
    public void Huge_password_is_refused_before_the_policy_normalizes_it()
    {
        IReadOnlyDictionary<string, string[]> errors = Validator.Validate(new RegisterRequest("ada@example.test", new string('x', 2_000_000), "Ada"));

        Assert.Equal(["Password must be at most 128 characters."], errors["password"]);
    }

    [Fact]
    public void Missing_fields_are_required_errors_not_exceptions()
    {
        IReadOnlyDictionary<string, string[]> errors = Validator.Validate(new RegisterRequest(null!, null!, null!));

        Assert.Equal(["displayName", "email", "password"], errors.Keys.Order(StringComparer.Ordinal));
    }

    [Theory]
    [InlineData("   ")]
    [InlineData("bad\u0000name")]
    public void Blank_or_control_character_display_name_is_rejected(string displayName)
    {
        Assert.True(Validator.Validate(new RegisterRequest("ada@example.test", GoodPassword, displayName)).ContainsKey("displayName"));
    }

    [Fact]
    public void Display_name_over_128_characters_is_rejected()
    {
        Assert.True(Validator.Validate(new RegisterRequest("ada@example.test", GoodPassword, new string('n', 129))).ContainsKey("displayName"));
        Assert.Empty(Validator.Validate(new RegisterRequest("ada@example.test", GoodPassword, new string('n', 128))));
    }

    [Fact]
    public void Verification_link_puts_the_token_in_the_fragment_and_options_are_checked()
    {
        AccountEmailOptions options = new() { VerifyEmailUrl = new Uri("https://app.example.test/verify-email") };

        Assert.Equal("https://app.example.test/verify-email#token=abc", options.Validated().VerificationLink("abc"));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AccountEmailOptions { VerificationTokenLifetime = TimeSpan.FromDays(8) }.Validated());
        Assert.Throws<ArgumentOutOfRangeException>(() => new AccountEmailOptions { VerifyEmailUrl = new Uri("https://app.example.test/v#x") }.Validated());
        Assert.Throws<ArgumentOutOfRangeException>(() => new AccountEmailOptions { VerifyEmailUrl = new Uri("ftp://app.example.test/v") }.Validated());
    }
}
