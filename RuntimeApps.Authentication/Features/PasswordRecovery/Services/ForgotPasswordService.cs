using Microsoft.AspNetCore.Identity;
using RuntimeApps.Authentication.Features.Verification.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Features.PasswordRecovery.Contracts;
using RuntimeApps.Authentication.Features.RefreshTokens.Contracts;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Features.PasswordRecovery.Models;
using RuntimeApps.Authentication.Features.Verification.Models;
using RuntimeApps.Authentication.Shared.Models;
namespace RuntimeApps.Authentication.Features.PasswordRecovery.Services {
    public sealed class ForgotPasswordService<TUser, TKey> : IForgotPasswordService<TUser, TKey>
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey> {
        private readonly IUserManager<TUser> _userManager;
        private readonly UserManager<TUser> _identityUserManager;
        private readonly IForgotPasswordVerificationWorkflow<TUser, TKey> _verification;
        private readonly IRefreshTokenService<TKey> _refreshTokens;
        private readonly IEnumerable<IPasswordValidator<TUser>> _passwordValidators;
        private readonly ILogger<ForgotPasswordService<TUser, TKey>> _logger;
        private readonly ForgotPasswordOptions _options;

        public ForgotPasswordService(
            IUserManager<TUser> userManager,
            UserManager<TUser> identityUserManager,
            IForgotPasswordVerificationWorkflow<TUser, TKey> verification,
            IEnumerable<IPasswordValidator<TUser>> passwordValidators,
            IServiceProvider services,
            ILogger<ForgotPasswordService<TUser, TKey>> logger,
            IOptions<ForgotPasswordOptions> options) {
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            _identityUserManager = identityUserManager ?? throw new ArgumentNullException(nameof(identityUserManager));
            _verification = verification ?? throw new ArgumentNullException(nameof(verification));
            _passwordValidators = passwordValidators ?? throw new ArgumentNullException(nameof(passwordValidators));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
            _options.Validate();
            _refreshTokens = services.GetService(typeof(IRefreshTokenService<TKey>)) as IRefreshTokenService<TKey>;
        }

        public async Task<ForgotPasswordResponse> RequestAsync(string email, CancellationToken cancellationToken = default) {
            if(string.IsNullOrWhiteSpace(email) || email.Length > 256)
                return CreateGenericResponse();

            var user = await _userManager.FindByEmailAsync(email.Trim());
            // Only a confirmed email address can be used to recover an account.
            if(user == null || !user.EmailConfirmed)
                return CreateGenericResponse();

            try {
                var operation = await _verification.StartAsync(
                    user, VerificationPurpose.PasswordReset, VerificationChannel.Email, user.Email,
                    cancellationToken: cancellationToken);
                if(operation.Succeeded && _options.Method == ForgotPasswordMethod.VerificationCode)
                    return new ForgotPasswordResponse {
                        VerificationHandle = operation.VerificationHandle
                    };
            } catch(OperationCanceledException) when(cancellationToken.IsCancellationRequested) {
                throw;
            } catch(Exception exception) {
                // Do not expose delivery failures or account state to the caller.
                _logger.LogError(exception, "Password recovery delivery failed.");
            }

            return CreateGenericResponse();
        }

        public async Task<Result> ResetAsync(
            string verificationHandle, string credential, string newPassword,
            CancellationToken cancellationToken = default) {
            if(string.IsNullOrWhiteSpace(verificationHandle) || verificationHandle.Length > 128 ||
               string.IsNullOrWhiteSpace(credential) || credential.Length > 4096 ||
               string.IsNullOrEmpty(newPassword) || newPassword.Length > 1024)
                return Failure("InvalidPasswordReset", "The password reset request is invalid.");

            // First validate possession of the recovery credential without consuming it. This
            // prevents password-policy errors from becoming a way to probe whether a handle exists.
            var check = await _verification.CheckAsync(
                verificationHandle, credential, VerificationPurpose.PasswordReset,
                VerificationChannel.Email, cancellationToken);
            if(!check.Succeeded)
                return Failure("InvalidPasswordReset", "The password reset request is invalid.");

            var user = check.Data;
            if(_options.Method == ForgotPasswordMethod.Link &&
               !await _identityUserManager.VerifyUserTokenAsync(
                   user,
                   _identityUserManager.Options.Tokens.PasswordResetTokenProvider,
                   "ResetPassword",
                   credential))
                return Failure("InvalidPasswordReset", "The password reset request is invalid.");

            // Validate the proposed password before consuming the recovery request. Identity's
            // ResetPasswordAsync validates it again when persisting the new password.
            foreach(var validator in _passwordValidators) {
                var passwordValidation = await validator.ValidateAsync(_identityUserManager, user, newPassword);
                if(!passwordValidation.Succeeded)
                    return new Result(ResultCode.BadRequest, passwordValidation.Errors);
            }

            // Link mode sends an Identity reset token at request time, binding it to the
            // user's security stamp. Code mode creates the Identity token after code validation.
            var resetToken = _options.Method == ForgotPasswordMethod.Link
                ? credential
                : await _userManager.GeneratePasswordResetTokenAsync(user);
            var verification = await _verification.VerifyAsync(
                verificationHandle, credential, VerificationPurpose.PasswordReset,
                VerificationChannel.Email, cancellationToken);
            if(!verification.Succeeded)
                return Failure("InvalidPasswordReset", "The password reset request is invalid.");

            var resetResult = await _userManager.ResetPasswordAsync(verification.Data, resetToken, newPassword);
            if(!resetResult.Succeeded)
                return new Result(ResultCode.BadRequest, resetResult.Errors);

            if(_refreshTokens != null)
                await _refreshTokens.RevokeAllAsync(verification.Data.Id, cancellationToken);

            return new Result();
        }

        private ForgotPasswordResponse CreateGenericResponse() => new() {
            VerificationHandle = _options.Method == ForgotPasswordMethod.VerificationCode
                ? VerificationHandle.Create()
                : null
        };

        private static Result Failure(string code, string description) =>
            new(ResultCode.BadRequest, Result.CreateErrors(code, description));
    }
}
