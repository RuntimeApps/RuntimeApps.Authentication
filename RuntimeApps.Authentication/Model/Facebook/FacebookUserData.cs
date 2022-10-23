namespace RuntimeApps.Authentication.Model.Facebook {
    public class FacebookUserData {
        public long? Id { get; set; }
        public string? Email { get; set; }
        public string? Name { get; set; }
        public string? First_name { get; set; }
        public string? Last_name { get; set; }
        public string? Gender { get; set; }
        public string? Locale { get; set; }
        public FacebookPictureData? Picture { get; set; }
    }
}
