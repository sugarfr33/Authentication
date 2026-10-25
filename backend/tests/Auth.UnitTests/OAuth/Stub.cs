using System.Reflection;

namespace Auth.UnitTests.OAuth;

/// <summary>
/// A test double for any interface (no mocking package): members with a handler run it, every other member returns
/// the default (a completed Task, Task.FromResult(default), null, 0, false). Calls are recorded by member name.
/// </summary>
public class Stub<T> : DispatchProxy
    where T : class
{
    public Dictionary<string, Func<object?[], object?>> Handlers { get; } = new(StringComparer.Ordinal);

    public List<string> Calls { get; } = [];

    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
    {
        ArgumentNullException.ThrowIfNull(targetMethod);
        Calls.Add(targetMethod.Name);
        return Handlers.TryGetValue(targetMethod.Name, out Func<object?[], object?>? handler)
            ? handler(args ?? [])
            : DefaultFor(targetMethod.ReturnType);
    }

    private static object? DefaultFor(Type type)
    {
        if (type == typeof(void))
        {
            return null;
        }

        if (type == typeof(Task))
        {
            return Task.CompletedTask;
        }

        if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Task<>))
        {
            Type result = type.GetGenericArguments()[0];
            return typeof(Task).GetMethod(nameof(Task.FromResult))!.MakeGenericMethod(result).Invoke(null, [DefaultValue(result)]);
        }

        return DefaultValue(type);
    }

    private static object? DefaultValue(Type type) => type.IsValueType ? Activator.CreateInstance(type) : null;
}

/// <summary>Creates <see cref="Stub{T}"/> doubles.</summary>
public static class Stubs
{
    public static (T Instance, Stub<T> Stub) Create<T>()
        where T : class
    {
        T instance = DispatchProxy.Create<T, Stub<T>>();
        return (instance, (Stub<T>)(object)instance);
    }
}
