namespace RuntimeApps.Authentication.Features.Account.Models {
    /// <summary>Indicates that the first login step succeeded and another authentication step is required.</summary>
    public sealed record AuthenticationContinuationResponse(bool RequiresTwoFactor = true);
}
