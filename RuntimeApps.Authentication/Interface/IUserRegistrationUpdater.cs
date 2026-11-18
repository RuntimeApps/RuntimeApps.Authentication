namespace RuntimeApps.Authentication.Interface {
    /// <summary>Copies only explicitly permitted, non-credential fields to an existing pending account.</summary>
    public interface IUserRegistrationUpdater<TUser> {
        Task UpdatePendingUserAsync(TUser existingUser, TUser requestedUser, CancellationToken cancellationToken = default);
    }
}