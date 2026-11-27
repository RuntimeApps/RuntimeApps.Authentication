using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Features.TwoFactor.Models;

/// <summary>Outcome of starting a second-factor login after the first factor succeeded.</summary>
public sealed record TwoFactorLoginStart {
    private TwoFactorLoginStart() { }

    /// <summary>
    /// True only when the user has no enrolled method and <see cref="TwoFactorOptions.NoEnrolledMethodBehavior"/> is
    /// <see cref="TwoFactorNoMethodBehavior.AllowSignIn"/>. The caller may then issue a session.
    /// </summary>
    public bool SignInAllowed { get; private init; }

    /// <summary>Opaque challenge handle for the client. Null when <see cref="SignInAllowed"/> is true.</summary>
    public string Challenge { get; private init; }

    public DateTimeOffset? ExpiresAt { get; private init; }

    /// <summary>Methods the user can answer with. Empty when none is enrolled.</summary>
    public IReadOnlyList<TwoFactorMethodInfo> Methods { get; private init; } = [];

    public static TwoFactorLoginStart SignIn() => new() { SignInAllowed = true };

    public static TwoFactorLoginStart Required(string challenge, DateTimeOffset expiresAt, IReadOnlyList<TwoFactorMethodInfo> methods) {
        ArgumentException.ThrowIfNullOrWhiteSpace(challenge);
        ArgumentNullException.ThrowIfNull(methods);
        return new() { Challenge = challenge, ExpiresAt = expiresAt, Methods = methods };
    }
}
