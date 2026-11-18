using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Service {
    public sealed class VerificationWorkflowService<TUser, TKey> : IVerificationWorkflowService<TUser, TKey>
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey> {
        private readonly IVerificationRequestStore<TKey> _store;
        private readonly IVerificationCodeGenerator<TUser, TKey> _generator;
        private readonly IVerificationCodeVerifier<TKey> _verifier;
        private readonly IVerificationSender<TUser, TKey> _sender;
        private readonly IUserManager<TUser> _userManager;
        private readonly ILookupNormalizer _normalizer;
        private readonly VerificationOptions _options;
        private readonly TimeProvider _timeProvider;

        public VerificationWorkflowService(
            IVerificationRequestStore<TKey> store,
            IVerificationCodeGenerator<TUser, TKey> generator,
            IVerificationCodeVerifier<TKey> verifier,
            IVerificationSender<TUser, TKey> sender,
            IUserManager<TUser> userManager,
            ILookupNormalizer normalizer,
            IOptions<VerificationOptions> options,
            TimeProvider timeProvider = null) {
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _generator = generator ?? throw new ArgumentNullException(nameof(generator));
            _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
            _sender = sender ?? throw new ArgumentNullException(nameof(sender));
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            _normalizer = normalizer ?? throw new ArgumentNullException(nameof(normalizer));
            _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
            _options.Validate();
            _timeProvider = timeProvider ?? TimeProvider.System;
        }

        public async Task<VerificationOperationResult> StartAsync(
            TUser user,
            VerificationPurpose purpose,
            VerificationChannel channel,
            string destination,
            string customPurpose = null,
            string customChannel = null,
            CancellationToken cancellationToken = default) {
            ArgumentNullException.ThrowIfNull(user);
            ArgumentException.ThrowIfNullOrWhiteSpace(destination);
            _options.Validate();

            var now = _timeProvider.GetUtcNow();
            var normalizedDestination = NormalizeDestination(destination, channel);
            var handle = VerificationHandle.Create();
            var request = new VerificationRequest<TKey> {
                UserId = user.Id,
                Purpose = purpose,
                Channel = channel,
                CustomPurpose = customPurpose,
                CustomChannel = customChannel,
                Destination = destination.Trim(),
                NormalizedDestination = normalizedDestination,
                PublicHandleHash = VerificationHandle.ComputeHash(handle),
                CodeVerifier = string.Empty,
                CodeVersion = 0,
                FailedAttempts = 0,
                SendCount = 1,
                CreatedAt = now,
                LastSentAt = now,
                ExpiresAt = now.Add(_options.CodeLifetime),
                Status = VerificationRequestStatus.Pending
            };

            if(!await _store.TryCreateAsync(
                request, now.AddHours(-1), _options.MaximumSendsPerHour, cancellationToken))
                return VerificationOperationResult.Failure("VerificationRateLimited", "The verification send limit has been reached.");

            var context = CreateContext(user, request);
            var code = await _generator.GenerateAsync(context, _options, cancellationToken);
            var protectedVerifier = _verifier.CreateVerifier(code, request);

            if(!await _store.TrySetInitialVerifierAsync(
                request.Id, protectedVerifier, now, request.ExpiresAt, cancellationToken))
                return VerificationOperationResult.Failure("VerificationRequestUnavailable", "The verification request could not be initialized.");

            await _sender.SendAsync(context, code, request.ExpiresAt, cancellationToken);
            return VerificationOperationResult.Success(handle, request.ExpiresAt);
        }

        public async Task<VerificationOperationResult> ResendAsync(
            string verificationHandle,
            CancellationToken cancellationToken = default) {
            if(string.IsNullOrWhiteSpace(verificationHandle))
                return VerificationOperationResult.Failure("InvalidVerificationHandle", "The verification request is invalid.");

            var request = await _store.FindByHandleHashAsync(
                VerificationHandle.ComputeHash(verificationHandle), cancellationToken);
            var now = _timeProvider.GetUtcNow();

            if(request == null || request.Status != VerificationRequestStatus.Pending)
                return VerificationOperationResult.Failure("VerificationRequestUnavailable", "The verification request is unavailable.");

            var user = await _userManager.FindByIdAsync(Convert.ToString(request.UserId));
            if(user == null)
                return VerificationOperationResult.Failure("VerificationRequestUnavailable", "The verification request is unavailable.");

            var context = CreateContext(user, request);
            var code = await _generator.GenerateAsync(context, _options, cancellationToken);
            var newVerifier = _verifier.CreateVerifier(code, request);
            var expiresAt = now.Add(_options.CodeLifetime);

            if(!await _store.TryResendAsync(
                request.Id,
                request.CodeVersion,
                newVerifier,
                now,
                expiresAt,
                _options.ResendCooldown,
                now.AddHours(-1),
                _options.MaximumSendsPerHour,
                cancellationToken))
                return VerificationOperationResult.Failure("VerificationResendUnavailable", "The verification request cannot be resent yet.");

            await _sender.SendAsync(context, code, expiresAt, cancellationToken);
            return VerificationOperationResult.Success(verificationHandle, expiresAt);
        }

        public async Task<Result<TUser>> VerifyAsync(
            string verificationHandle,
            string code,
            CancellationToken cancellationToken = default) {
            if(string.IsNullOrWhiteSpace(verificationHandle) || string.IsNullOrWhiteSpace(code))
                return Failure("InvalidVerificationCode", "The verification code is invalid.");

            var request = await _store.FindByHandleHashAsync(
                VerificationHandle.ComputeHash(verificationHandle), cancellationToken);
            var now = _timeProvider.GetUtcNow();

            if(request == null || request.Status != VerificationRequestStatus.Pending || request.ExpiresAt <= now)
                return Failure("VerificationRequestUnavailable", "The verification request is unavailable.");

            if(!_verifier.Verify(code, request)) {
                await _store.TryIncrementFailedAttemptsAsync(
                    request.Id, request.CodeVersion, _options.MaximumFailedAttempts, now, cancellationToken);
                return Failure("InvalidVerificationCode", "The verification code is invalid.");
            }

            if(!await _store.TryConsumeAsync(request.Id, request.CodeVersion, now, cancellationToken))
                return Failure("VerificationRequestUnavailable", "The verification request is unavailable.");

            var user = await _userManager.FindByIdAsync(Convert.ToString(request.UserId));
            if(user == null)
                return Failure("VerificationRequestUnavailable", "The verification request is unavailable.");

            if(request.Purpose == VerificationPurpose.Registration ||
               request.Purpose == VerificationPurpose.EmailChange)
                user.EmailConfirmed = true;

            var updateResult = await _userManager.UpdateAsync(user);
            if(!updateResult.Succeeded)
                return new Result<TUser>(ResultCode.BadRequest, updateResult.Errors);

            return new Result<TUser>(user);
        }

        private string NormalizeDestination(string destination, VerificationChannel channel) =>
            channel == VerificationChannel.Email
                ? _normalizer.NormalizeEmail(destination.Trim())
                : destination.Trim();

        private VerificationCodeContext<TUser, TKey> CreateContext(TUser user, VerificationRequest<TKey> request) =>
            new() {
                User = user,
                UserId = user.Id,
                RequestId = request.Id,
                Purpose = request.Purpose,
                Channel = request.Channel,
                CustomPurpose = request.CustomPurpose,
                CustomChannel = request.CustomChannel,
                Destination = request.Destination
            };

        private static Result<TUser> Failure(string code, string description) =>
            new(ResultCode.BadRequest, Result.CreateErrors(code, description));
    }
}