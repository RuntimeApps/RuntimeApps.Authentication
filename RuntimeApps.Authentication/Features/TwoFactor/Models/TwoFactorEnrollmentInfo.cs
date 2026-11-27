namespace RuntimeApps.Authentication.Features.TwoFactor.Models;

/// <summary>
/// Method-specific data returned when enrollment starts. Properties may contain secrets
/// (for example an authenticator key), so responses carrying it must not be cached or logged.
/// </summary>
/// <param name="Method">The <see cref="Contracts.ITwoFactorMethod{TUser}.Name"/> that produced this data.</param>
/// <param name="Properties">Method-defined values, keyed by name. Empty for methods that need none.</param>
public sealed record TwoFactorEnrollmentInfo(string Method, IReadOnlyDictionary<string, string> Properties);
