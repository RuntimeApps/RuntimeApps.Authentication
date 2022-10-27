namespace RuntimeApps.Authentication.Model.Facebook {
    internal class FacebookUserAccessTokenData {
        public long? App_id { get; set; }
        public string Type { get; set; }
        public string Application { get; set; }
        public long? Expires_at { get; set; }
        public bool Is_valid { get; set; }
        public long? User_Id { get; set; }
    }
}
