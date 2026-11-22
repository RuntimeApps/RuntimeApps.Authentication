namespace RuntimeApps.Authentication.Shared.Models {
    public enum ResultCode {
        Success = 200,
        Accepted = 202,
        // Historical wire value retained for compatibility. Map to HTTP 400 explicitly;
        // do not use this enum's underlying value as an HTTP status.
        BadRequest = 401,
        Forbidden = 403,
        Conflict = 409,
        Locked = 423,
    }
}
