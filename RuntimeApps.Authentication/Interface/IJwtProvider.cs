using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Interface {
    public interface IJwtProvider<TUser>
        where TUser : class {
        public Token GenerateToken(TUser user);
    }
}
