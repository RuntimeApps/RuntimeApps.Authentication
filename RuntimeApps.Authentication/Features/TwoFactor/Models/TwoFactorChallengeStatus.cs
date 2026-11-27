namespace RuntimeApps.Authentication.Features.TwoFactor.Models;

public enum TwoFactorChallengeStatus {
    /// <summary>Can still be answered, until it expires or its attempts are used up.</summary>
    Pending,
    /// <summary>Answered successfully. A challenge can be consumed only once.</summary>
    Completed,
    /// <summary>Replaced by a newer challenge for the same user (pending-challenge cap).</summary>
    Superseded
}
