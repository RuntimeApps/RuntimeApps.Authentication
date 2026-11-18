using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Service {
    public sealed class RegistrationService<TUser, TKey> : IRegistrationService<TUser, TKey>
        where TUser : IdentityUser<TKey>, new()
        where TKey : IEquatable<TKey> {
        private readonly IUserManager<TUser> _userManager;
        private readonly IUserRegistrationUpdater<TUser> _userUpdater;
        private readonly IVerificationWorkflowService<TUser, TKey> _verification;
        private readonly IUserAccountService<TUser> _accountService;
        private readonly VerificationOptions _options;
        private readonly TimeProvider _timeProvider;

        public RegistrationService(
            IUserManager<TUser> userManager,
            IUserRegistrationUpdater<TUser> userUpdater,
            IVerificationWorkflowService<TUser, TKey> verification,
            IUserAccountService<TUser> accountService,
            IOptions<VerificationOptions> options,
            TimeProvider timeProvider = null) {
            _userManager = userManager;
            _userUpdater = userUpdater;
            _verification = verification;
            _accountService = accountService;
            _options = options.Value;
            _timeProvider = timeProvider ?? TimeProvider.System;
        }

        public async Task<Result<RegistrationVerificationResponse>> RegisterAsync(
            TUser user, string password, CancellationToken cancellationToken = default) {
            ArgumentNullException.ThrowIfNull(user);
            if(string.IsNullOrWhiteSpace(user.Email) || string.IsNullOrEmpty(password))
                return Failure("InvalidRegistration", "Email and password are required.");

            if(string.IsNullOrWhiteSpace(user.UserName))
                user.UserName = user.Email;

            var existingUser = await _userManager.FindByEmailAsync(user.Email);
            if(existingUser?.EmailConfirmed == true)
                return GenericResponse();

            if(existingUser != null) {
                await _userUpdater.UpdatePendingUserAsync(existingUser, user, cancellationToken);
                var updateResult = await _userManager.UpdateAsync(existingUser);
                if(!updateResult.Succeeded)
                    return new Result<RegistrationVerificationResponse>(ResultCode.BadRequest, updateResult.Errors);
                user = existingUser;
            } else {
                user.EmailConfirmed = false;
                var createResult = await _userManager.CreateAsync(user, password);
                if(!createResult.Succeeded) {
                    // A concurrent registration may have created the account after our initial lookup.
                    var racedUser = await _userManager.FindByEmailAsync(user.Email);
                    if(racedUser?.EmailConfirmed == true)
                        return GenericResponse();
                    if(racedUser == null)
                        return new Result<RegistrationVerificationResponse>(ResultCode.BadRequest, createResult.Errors);

                    await _userUpdater.UpdatePendingUserAsync(racedUser, user, cancellationToken);
                    var updateResult = await _userManager.UpdateAsync(racedUser);
                    if(!updateResult.Succeeded)
                        return new Result<RegistrationVerificationResponse>(ResultCode.BadRequest, updateResult.Errors);
                    user = racedUser;
                }
            }

            user.EmailConfirmed = false;
            var verificationResult = await _verification.StartAsync(
                user, VerificationPurpose.Registration, VerificationChannel.Email, user.Email,
                cancellationToken: cancellationToken);

            if(!verificationResult.Succeeded)
                return Failure(verificationResult.ErrorCode, verificationResult.ErrorDescription);

            return new Result<RegistrationVerificationResponse>(new RegistrationVerificationResponse {
                VerificationHandle = verificationResult.VerificationHandle,
                ExpiresAt = verificationResult.ExpiresAt!.Value
            });
        }

        public async Task<Result<TUser, Token>> VerifyAsync(
            string verificationHandle, string code, CancellationToken cancellationToken = default) {
            var verificationResult = await _verification.VerifyAsync(
                verificationHandle, code, VerificationPurpose.Registration, VerificationChannel.Email, cancellationToken);
            if(!verificationResult.Succeeded)
                return new Result<TUser, Token>(verificationResult.Code, verificationResult.Errors);

            return await _accountService.CompleteRegistrationAsync(verificationResult.Data);
        }

        public async Task<Result<RegistrationVerificationResponse>> ResendAsync(
            string verificationHandle, CancellationToken cancellationToken = default) {
            var result = await _verification.ResendAsync(
                verificationHandle, VerificationPurpose.Registration, VerificationChannel.Email, cancellationToken);
            if(!result.Succeeded)
                return Failure(result.ErrorCode, result.ErrorDescription);

            return new Result<RegistrationVerificationResponse>(new RegistrationVerificationResponse {
                VerificationHandle = result.VerificationHandle,
                ExpiresAt = result.ExpiresAt!.Value
            });
        }

        private Result<RegistrationVerificationResponse> GenericResponse() =>
            new(new RegistrationVerificationResponse {
                VerificationHandle = VerificationHandle.Create(),
                ExpiresAt = _timeProvider.GetUtcNow().Add(_options.CodeLifetime)
            });

        private static Result<RegistrationVerificationResponse> Failure(string code, string description) =>
            new(ResultCode.BadRequest, Result.CreateErrors(code, description));
    }
}