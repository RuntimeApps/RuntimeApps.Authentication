using RuntimeApps.Authentication.Shared.Models;
namespace RuntimeApps.Authentication.Identity.Contracts {
    public interface IJwtProvider<TUser>
        where TUser : class {
        /// <summary>Generates a JWT. Cancellation is observed around claim creation; Identity's principal factory has no cancellation overload.</summary>
        Task<Token> GenerateTokenAsync(TUser user, CancellationToken cancellationToken = default);
    }
}
