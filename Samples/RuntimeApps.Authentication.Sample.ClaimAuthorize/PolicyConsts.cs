namespace RuntimeApps.Authentication.Sample.ClaimAuthorize {
    public class PolicyConsts {
        public const string ViewUserPolicy = "ViewUser";
        public const string ManageUserPolicy = "ManageUser";
        public const string ManageUserRolePolicy = "ManageUser";
        public const string ManageRolePolicy = "ManageRole";
        public const string ManageRoleClaimPolicy = "ManageRoleClaim";

        public static IEnumerable<PolicyData> GetAllPolicies() => new List<PolicyData>() {
            new PolicyData(ViewUserPolicy, ClaimConsts.UserManagerClaim.ClaimType, null),
            new PolicyData(ManageUserPolicy, ClaimConsts.UserManagerClaim.ClaimType, ClaimConsts.UserManagerClaim.ClaimValueDescription.Keys.Order().Skip(1).ToArray()),
            new PolicyData(ManageUserRolePolicy, ClaimConsts.UserManagerClaim.ClaimType, ClaimConsts.UserManagerClaim.ClaimValueDescription.Keys.Order().Skip(2).ToArray()),
            new PolicyData(ManageRolePolicy, ClaimConsts.UserManagerClaim.ClaimType, ClaimConsts.UserManagerClaim.ClaimValueDescription.Keys.Order().Skip(3).ToArray()),
            new PolicyData(ManageRoleClaimPolicy, ClaimConsts.UserManagerClaim.ClaimType, ClaimConsts.UserManagerClaim.ClaimValueDescription.Keys.Order().Skip(4).ToArray()),
        };
    }

    public record PolicyData(string PolicyName, string ClaimType, IEnumerable<string> ClaimValues);
}
