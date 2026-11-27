namespace RuntimeApps.Authentication.Shared.Models {
    /// <summary>A second-factor method the user can answer a login challenge with.</summary>
    /// <param name="Name">Method name to send back when completing the challenge, for example "authenticator".</param>
    /// <param name="RequiresSend">True when the code is delivered (email, SMS) and the client must request it first.</param>
    public sealed record TwoFactorMethodInfo(string Name, bool RequiresSend);
}
