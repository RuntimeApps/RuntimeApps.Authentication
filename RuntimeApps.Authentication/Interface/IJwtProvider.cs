using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Interface {
    public interface IJwtProvider<TUser>
        where TUser : class {
        Task<Token> GenerateTokenAsync(TUser user);
    }
}
