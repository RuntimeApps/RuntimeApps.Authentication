namespace RuntimeApps.Authentication.Model {
    public enum ResultCode {
        Success = 200,
        Accepted = 202,
        BadRequest = 401,
        Forbidden = 403,
        Conflict = 409,
        Locked = 423,
    }
}
