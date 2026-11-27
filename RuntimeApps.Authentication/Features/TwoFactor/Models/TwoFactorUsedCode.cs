namespace RuntimeApps.Authentication.Features.TwoFactor.Models;

/// <summary>
/// Replay ledger entry: an accepted second-factor code for a user and method. Only a hash of the code is
/// stored (see <c>TwoFactorCodeHash</c>). A 6-digit code is easy to brute-force from its hash, so rows are
/// short-lived and must be removed by cleanup once they expire.
/// </summary>
public class TwoFactorUsedCode<TKey> where TKey : IEquatable<TKey> {
    public long Id { get; set; }
    public TKey UserId { get; set; }
    public string Method { get; set; }
    public string CodeHash { get; set; }
    public DateTimeOffset UsedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
}
