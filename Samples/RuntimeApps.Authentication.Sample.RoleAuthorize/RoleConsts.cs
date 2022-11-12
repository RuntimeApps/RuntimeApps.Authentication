namespace RuntimeApps.Authentication.Sample.RoleAuthorize {
    public class RoleConsts {
        public const string UserManagerRole = "UserManager";
        public const string UserViewRole = "UserViewer";
        public const string OtherRole = "OtherRole";

        public static IEnumerable<string> AllRoles() => new string[] {
            UserManagerRole,
            UserViewRole,
            OtherRole
        };
    }
}
