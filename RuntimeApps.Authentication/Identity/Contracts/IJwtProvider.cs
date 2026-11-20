using RuntimeApps.Authentication.Shared.Models;
namespace RuntimeApps.Authentication.Identity.Contracts {
    public interface IJwtProvider<TUser>
        where TUser : class {
        Task<Token> GenerateTokenAsync(TUser user);
    }
}
