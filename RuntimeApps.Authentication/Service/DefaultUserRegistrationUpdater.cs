using Microsoft.AspNetCore.Identity;
using RuntimeApps.Authentication.Interface;

namespace RuntimeApps.Authentication.Service {
    /// <summary>
    /// Updates only username and phone number on an existing pending Identity account.
    /// Passwords, email ownership, roles, claims, security stamps, and external logins are not copied.
    /// </summary>
    public sealed class DefaultUserRegistrationUpdater<TUser, TKey> : IUserRegistrationUpdater<TUser>
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey> {
        public Task UpdatePendingUserAsync(
            TUser existingUser,
            TUser requestedUser,
            CancellationToken cancellationToken = default) {
            ArgumentNullException.ThrowIfNull(existingUser);
            ArgumentNullException.ThrowIfNull(requestedUser);

            if(!string.IsNullOrWhiteSpace(requestedUser.UserName))
                existingUser.UserName = requestedUser.UserName;

            if(existingUser.PhoneNumber != requestedUser.PhoneNumber) {
                existingUser.PhoneNumber = requestedUser.PhoneNumber;
                existingUser.PhoneNumberConfirmed = false;
            }

            return Task.CompletedTask;
        }
    }
}