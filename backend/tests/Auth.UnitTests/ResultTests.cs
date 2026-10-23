using Auth.Contracts;

namespace Auth.UnitTests;

public class ResultTests
{
    [Fact]
    public void Success_has_no_error()
    {
        Result result = Result.Success();

        Assert.True(result.IsSuccess);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Failure_carries_the_error()
    {
        Result result = Result.Failure(AuthError.LockedOut);

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthError.LockedOut, result.Error);
    }

    [Fact]
    public void Generic_success_carries_the_value()
    {
        Result<int> result = Result.Success(42);

        Assert.True(result.IsSuccess);
        Assert.Equal(42, result.Value);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Generic_failure_carries_the_error_and_no_value()
    {
        Result<string> result = Result.Failure<string>(AuthError.GenericInvalidCredentials);

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthError.GenericInvalidCredentials, result.Error);
        Assert.Null(result.Value);
    }

    [Fact]
    public void AuthError_has_no_default_member_so_an_unset_error_is_never_mistaken_for_a_real_one()
    {
        Assert.False(Enum.IsDefined(default(AuthError)));
    }
}
