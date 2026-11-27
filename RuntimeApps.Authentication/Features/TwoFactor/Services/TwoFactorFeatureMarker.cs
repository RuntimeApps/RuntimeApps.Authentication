namespace RuntimeApps.Authentication.Features.TwoFactor.Services;

/// <summary>
/// Registered by <c>AddTwoFactor</c>. Its presence tells the sign-in manager that API-based two-factor login is
/// available, so a user with two-factor enabled must complete a second step (fail-closed). Without it the
/// legacy gate applies and behavior is unchanged.
/// </summary>
internal sealed class TwoFactorFeatureMarker;
