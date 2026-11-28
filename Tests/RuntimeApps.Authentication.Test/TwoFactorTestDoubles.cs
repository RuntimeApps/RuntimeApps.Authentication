using Microsoft.AspNetCore.Identity;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Models;

namespace RuntimeApps.Authentication.Test;

/// <summary>Configurable second-factor method for service tests.</summary>
public sealed class FakeTwoFactorMethod(string name, bool deliveryBased = false) : ITwoFactorMethod<IdentityUser<int>> {
    public string Name => name;
    public bool IsDeliveryBased => deliveryBased;
    public bool Enrolled { get; set; } = true;
    public string ValidCode { get; set; } = "111111";
    public int VerifyCalls { get; private set; }
    public Exception VerifyException { get; set; }
    public Exception BeginException { get; set; }
    public int BeginCalls { get; private set; }
    public int ClearCalls { get; private set; }

    public Task<bool> IsEnrolledAsync(IdentityUser<int> user, CancellationToken cancellationToken) => Task.FromResult(Enrolled);

    public Task<TwoFactorEnrollmentInfo> BeginEnrollmentAsync(IdentityUser<int> user, CancellationToken cancellationToken) {
        if(BeginException != null) throw BeginException;
        BeginCalls++;
        return Task.FromResult(new TwoFactorEnrollmentInfo(name, new Dictionary<string, string> { ["sharedKey"] = "SECRET-KEY" }));
    }

    public Task ClearEnrollmentAsync(IdentityUser<int> user, CancellationToken cancellationToken) {
        ClearCalls++;
        return Task.CompletedTask;
    }

    public Task<bool> ConfirmEnrollmentAsync(IdentityUser<int> user, string code, CancellationToken cancellationToken) =>
        Task.FromResult(code == ValidCode);

    public Task SendChallengeAsync(IdentityUser<int> user, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task<bool> VerifyAsync(IdentityUser<int> user, string code, CancellationToken cancellationToken) {
        VerifyCalls++;
        if(VerifyException != null) throw VerifyException;
        return Task.FromResult(code == ValidCode);
    }
}

/// <summary>Time provider whose clock the test controls.</summary>
public sealed class TestClock(DateTimeOffset now) : TimeProvider {
    public DateTimeOffset Now { get; set; } = now;
    public void Advance(TimeSpan by) => Now += by;
    public override DateTimeOffset GetUtcNow() => Now;
}
