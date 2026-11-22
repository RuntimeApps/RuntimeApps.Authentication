using System.Globalization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Features.PasswordRecovery.Contracts;
using RuntimeApps.Authentication.Features.Verification.Contracts;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Features.PasswordRecovery.Models;
using RuntimeApps.Authentication.Features.Verification.Models;
using RuntimeApps.Authentication.Shared.Models;
namespace RuntimeApps.Authentication.Features.Verification.Services {
    public sealed class VerificationWorkflowService<TUser, TKey> : IForgotPasswordVerificationWorkflow<TUser, TKey>
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey> {
        private readonly IVerificationRequestStore<TKey> _store;
        private readonly IVerificationCodeGenerator<TUser, TKey> _generator;
        private readonly IVerificationCodeVerifier<TKey> _verifier;
        private readonly IVerificationSender<TUser, TKey> _sender;
        private readonly IUserManager<TUser> _userManager;
        private readonly IUserPasswordManager<TUser> _passwordManager;
        private readonly ILookupNormalizer _normalizer;
        private readonly VerificationOptions _options;
        private readonly ForgotPasswordOptions _forgotOptions;
        private readonly TimeProvider _timeProvider;

        // Keep the original constructor available for applications that instantiate this service directly.
        public VerificationWorkflowService(
            IVerificationRequestStore<TKey> store,
            IVerificationCodeGenerator<TUser, TKey> generator,
            IVerificationCodeVerifier<TKey> verifier,
            IVerificationSender<TUser, TKey> sender,
            IUserManager<TUser> userManager,
            IUserPasswordManager<TUser> passwordManager,
            ILookupNormalizer normalizer,
            IOptions<VerificationOptions> options,
            TimeProvider timeProvider = null)
            : this(store, generator, verifier, sender, userManager, passwordManager, normalizer, options,
                Options.Create(new ForgotPasswordOptions()), timeProvider) {
        }

        public VerificationWorkflowService(
            IVerificationRequestStore<TKey> store,
            IVerificationCodeGenerator<TUser, TKey> generator,
            IVerificationCodeVerifier<TKey> verifier,
            IVerificationSender<TUser, TKey> sender,
            IUserManager<TUser> userManager,
            IUserPasswordManager<TUser> passwordManager,
            ILookupNormalizer normalizer,
            IOptions<VerificationOptions> options,
            IOptions<ForgotPasswordOptions> forgotOptions,
            TimeProvider timeProvider = null) {
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _generator = generator ?? throw new ArgumentNullException(nameof(generator));
            _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
            _sender = sender ?? throw new ArgumentNullException(nameof(sender));
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            _passwordManager = passwordManager ?? throw new ArgumentNullException(nameof(passwordManager));
            _normalizer = normalizer ?? throw new ArgumentNullException(nameof(normalizer));
            _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
            _forgotOptions = forgotOptions?.Value ?? throw new ArgumentNullException(nameof(forgotOptions));
            _options.Validate();
            _forgotOptions.Validate();
            _timeProvider = timeProvider ?? TimeProvider.System;
        }

        public async Task<VerificationOperationResult> StartAsync(
            TUser user, VerificationPurpose purpose, VerificationChannel channel, string destination,
            string customPurpose = null, string customChannel = null, CancellationToken cancellationToken = default) {
            ArgumentNullException.ThrowIfNull(user);
            ArgumentException.ThrowIfNullOrWhiteSpace(destination);
            _options.Validate();

            var now = _timeProvider.GetUtcNow();
            var normalizedDestination = channel == VerificationChannel.Email
                ? _normalizer.NormalizeEmail(destination.Trim())
                : destination.Trim();
            var handle = VerificationHandle.Create();
            var request = new VerificationRequest<TKey> {
                UserId = user.Id, Purpose = purpose, Channel = channel, CustomPurpose = customPurpose,
                CustomChannel = customChannel, Destination = destination.Trim(),
                NormalizedDestination = normalizedDestination, PublicHandleHash = VerificationHandle.ComputeHash(handle),
                CodeVerifier = string.Empty, CodeVersion = 0, FailedAttempts = 0, SendCount = 1,
                CreatedAt = now, LastSentAt = now, ExpiresAt = now.Add(_options.CodeLifetime),
                Status = VerificationRequestStatus.Pending
            };

            bool requestCreated;
            try {
                requestCreated = await _store.TryCreateAsync(
                    request, now.AddHours(-1), _options.MaximumSendsPerHour, cancellationToken);
            } catch(OperationCanceledException) when(cancellationToken.IsCancellationRequested) {
                // A relational commit may win the race with cancellation. If the request is
                // present, finish its verifier and delivery so it is not left unusable.
                var persisted = await _store.FindByHandleHashAsync(request.PublicHandleHash, CancellationToken.None);
                if(persisted == null)
                    throw;
                request = persisted;
                requestCreated = true;
            }

            if(!requestCreated)
                return VerificationOperationResult.Failure("VerificationRateLimited", "The verification send limit has been reached.");

            // The request is now persisted. Complete verifier setup and delivery even if the
            // HTTP request is aborted so we do not leave a pending handle with no credential.
            var credential = await CreateCredentialAsync(user, request, handle, CancellationToken.None);
            if(string.IsNullOrWhiteSpace(credential))
                return VerificationOperationResult.Failure("VerificationCodeGenerationFailed", "A verification credential could not be generated.");
            var protectedVerifier = _verifier.CreateVerifier(credential, request);
            if(!await _store.TrySetInitialVerifierAsync(request.Id, protectedVerifier, now, request.ExpiresAt, CancellationToken.None))
                return VerificationOperationResult.Failure("VerificationRequestUnavailable", "The verification request could not be initialized.");

            var context = CreateContext(user, request, handle, credential);
            await _sender.SendAsync(context, credential, request.ExpiresAt, CancellationToken.None);
            return VerificationOperationResult.Success(handle, request.ExpiresAt);
        }

        public async Task<VerificationOperationResult> ResendAsync(
            string verificationHandle, VerificationPurpose expectedPurpose, VerificationChannel expectedChannel,
            CancellationToken cancellationToken = default) {
            if(string.IsNullOrWhiteSpace(verificationHandle))
                return VerificationOperationResult.Failure("InvalidVerificationHandle", "The verification request is invalid.");

            var request = await _store.FindByHandleHashAsync(VerificationHandle.ComputeHash(verificationHandle), cancellationToken);
            var now = _timeProvider.GetUtcNow();
            if(request == null || request.Status != VerificationRequestStatus.Pending ||
               request.Purpose != expectedPurpose || request.Channel != expectedChannel || request.ExpiresAt <= now)
                return VerificationOperationResult.Failure("VerificationRequestUnavailable", "The verification request is unavailable.");

            var user = await _userManager.FindByIdAsync(Convert.ToString(request.UserId, CultureInfo.InvariantCulture));
            if(user == null || !IsDestinationCurrent(user, request))
                return VerificationOperationResult.Failure("VerificationRequestUnavailable", "The verification request is unavailable.");

            var credential = await CreateCredentialAsync(user, request, verificationHandle, cancellationToken);
            if(string.IsNullOrWhiteSpace(credential))
                return VerificationOperationResult.Failure("VerificationCodeGenerationFailed", "A verification credential could not be generated.");
            var newVerifier = _verifier.CreateVerifier(credential, request);
            var expiresAt = now.Add(_options.CodeLifetime);
            bool resendCommitted;
            try {
                resendCommitted = await _store.TryResendAsync(request.Id, request.CodeVersion, newVerifier, now, expiresAt,
                    _options.ResendCooldown, now.AddHours(-1), _options.MaximumSendsPerHour, cancellationToken);
            } catch(OperationCanceledException) when(cancellationToken.IsCancellationRequested) {
                // If the atomic version update committed while cancellation was racing with
                // the database response, finish delivery using the credential for that version.
                var persisted = await _store.FindByHandleHashAsync(
                    request.PublicHandleHash, CancellationToken.None);
                resendCommitted = persisted?.Status == VerificationRequestStatus.Pending &&
                    persisted.CodeVersion == request.CodeVersion + 1 && persisted.LastSentAt == now;
                if(!resendCommitted)
                    throw;
            }

            if(!resendCommitted)
                return VerificationOperationResult.Failure("VerificationResendUnavailable", "The verification request cannot be resent yet.");

            // The verifier/version update is committed; delivery is essential follow-through.
            await _sender.SendAsync(CreateContext(user, request, verificationHandle, credential), credential, expiresAt, CancellationToken.None);
            return VerificationOperationResult.Success(verificationHandle, expiresAt);
        }

        public async Task<Result<TUser>> CheckAsync(
            string verificationHandle, string credential, VerificationPurpose expectedPurpose,
            VerificationChannel expectedChannel, CancellationToken cancellationToken = default) {
            if(string.IsNullOrWhiteSpace(verificationHandle) || string.IsNullOrWhiteSpace(credential))
                return Failure("InvalidVerificationCode", "The verification credential is invalid.");

            var request = await _store.FindByHandleHashAsync(
                VerificationHandle.ComputeHash(verificationHandle), cancellationToken);
            var now = _timeProvider.GetUtcNow();
            if(request == null || request.Status != VerificationRequestStatus.Pending ||
               request.Purpose != expectedPurpose || request.Channel != expectedChannel || request.ExpiresAt <= now)
                return Failure("InvalidVerificationCode", "The verification credential is invalid.");

            if(!_verifier.Verify(credential, request)) {
                await _store.TryIncrementFailedAttemptsAsync(
                    request.Id, request.CodeVersion, _options.MaximumFailedAttempts, now, cancellationToken);
                return Failure("InvalidVerificationCode", "The verification credential is invalid.");
            }

            var user = await _userManager.FindByIdAsync(Convert.ToString(request.UserId, CultureInfo.InvariantCulture));
            if(user == null || !IsDestinationCurrent(user, request))
                return Failure("InvalidVerificationCode", "The verification credential is invalid.");

            return new Result<TUser>(user);
        }

        public async Task<Result<TUser>> VerifyAsync(
            string verificationHandle, string code, VerificationPurpose expectedPurpose, VerificationChannel expectedChannel,
            CancellationToken cancellationToken = default) {
            if(string.IsNullOrWhiteSpace(verificationHandle) || string.IsNullOrWhiteSpace(code))
                return Failure("InvalidVerificationCode", "The verification code is invalid.");

            var request = await _store.FindByHandleHashAsync(VerificationHandle.ComputeHash(verificationHandle), cancellationToken);
            var now = _timeProvider.GetUtcNow();
            if(request == null || request.Status != VerificationRequestStatus.Pending ||
               request.Purpose != expectedPurpose || request.Channel != expectedChannel || request.ExpiresAt <= now)
                return Failure("VerificationRequestUnavailable", "The verification request is unavailable.");

            if(!_verifier.Verify(code, request)) {
                await _store.TryIncrementFailedAttemptsAsync(request.Id, request.CodeVersion,
                    _options.MaximumFailedAttempts, now, cancellationToken);
                return Failure("InvalidVerificationCode", "The verification code is invalid.");
            }

            var user = await _userManager.FindByIdAsync(Convert.ToString(request.UserId, CultureInfo.InvariantCulture));
            if(user == null || !IsDestinationCurrent(user, request))
                return Failure("VerificationRequestUnavailable", "The verification request is unavailable.");

            if(!await _store.TryConsumeAsync(request.Id, request.CodeVersion, now, cancellationToken))
                return Failure("VerificationRequestUnavailable", "The verification request is unavailable.");

            if(request.Channel == VerificationChannel.Email &&
               (request.Purpose == VerificationPurpose.Registration || request.Purpose == VerificationPurpose.EmailChange)) {
                var currentEmail = _normalizer.NormalizeEmail(user.Email ?? string.Empty);
                if(!string.Equals(currentEmail, request.NormalizedDestination, StringComparison.Ordinal))
                    return Failure("VerificationDestinationChanged", "The email address associated with this request has changed.");
                user.EmailConfirmed = true;
            }

            // Preserve the existing workflow behavior for other verification purposes. Password
            // reset does not mutate the user here; ResetPasswordAsync performs the actual update.
            if(request.Purpose != VerificationPurpose.PasswordReset) {
                var updateResult = await _userManager.UpdateAsync(user);
                if(!updateResult.Succeeded)
                    return new Result<TUser>(ResultCode.BadRequest, updateResult.Errors);
            }
            return new Result<TUser>(user);
        }

        private async Task<string> CreateCredentialAsync(
            TUser user, VerificationRequest<TKey> request, string handle, CancellationToken cancellationToken) {
            if(request.Purpose == VerificationPurpose.PasswordReset && _forgotOptions.Method == ForgotPasswordMethod.Link)
                return await _passwordManager.GeneratePasswordResetTokenAsync(user);
            return await _generator.GenerateAsync(
                CreateContext(user, request, handle, null), _options, cancellationToken);
        }

        private bool IsDestinationCurrent(TUser user, VerificationRequest<TKey> request) {
            if(request.Purpose == VerificationPurpose.PasswordReset && !user.EmailConfirmed)
                return false;
            if(request.Channel != VerificationChannel.Email ||
               (request.Purpose != VerificationPurpose.Registration &&
                request.Purpose != VerificationPurpose.EmailChange &&
                request.Purpose != VerificationPurpose.PasswordReset))
                return true;
            var currentEmail = _normalizer.NormalizeEmail(user.Email ?? string.Empty);
            return string.Equals(currentEmail, request.NormalizedDestination, StringComparison.Ordinal);
        }

        private VerificationCodeContext<TUser, TKey> CreateContext(
            TUser user, VerificationRequest<TKey> request, string handle, string credential) {
            return new VerificationCodeContext<TUser, TKey> {
                User = user, UserId = user.Id, RequestId = request.Id, Purpose = request.Purpose,
                Channel = request.Channel, CustomPurpose = request.CustomPurpose, CustomChannel = request.CustomChannel,
                Destination = request.Destination,
                VerificationHandle = request.Purpose == VerificationPurpose.PasswordReset &&
                                     _forgotOptions.Method == ForgotPasswordMethod.Link ? handle : null,
                TokenGeneratorType = request.Purpose == VerificationPurpose.PasswordReset
                    ? (_forgotOptions.Method == ForgotPasswordMethod.Link
                        ? VerificationTokenGeneratorType.Link
                        : VerificationTokenGeneratorType.Code)
                    : null,
                FrontendResetUrl = request.Purpose == VerificationPurpose.PasswordReset &&
                                   _forgotOptions.Method == ForgotPasswordMethod.Link
                    ? _forgotOptions.FrontendResetUrl
                    : null
            };
        }

        private static Result<TUser> Failure(string code, string description) =>
            new(ResultCode.BadRequest, Result.CreateErrors(code, description));
    }
}
