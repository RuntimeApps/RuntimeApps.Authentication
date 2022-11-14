namespace RuntimeApps.Authentication.Sample.ClaimAuthorize {
    public static class ClaimConsts {
        public static ClaimData UserManagerClaim { get; } = new ClaimData("UserManager", "Claims of users access to managing users", new Dictionary<string, string>() {
                { "1", "View users info" },
                { "2", "Manage users data" },
                { "3", "Manage users roles" },
                { "4", "Manage role infos" },
                { "5", "Manage role claims" },
            });

        public static IEnumerable<ClaimData> GetAllClaimData() => new List<ClaimData>() {
            UserManagerClaim
        };

    }

    public record ClaimData(string ClaimType, string ClaimDescription, IDictionary<string, string> ClaimValueDescription);

}
