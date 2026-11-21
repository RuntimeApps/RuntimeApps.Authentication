using System.Security.Cryptography;
using RuntimeApps.Authentication.Features.Verification.Contracts;
using RuntimeApps.Authentication.Features.Verification.Models;
namespace RuntimeApps.Authentication.Features.Verification.Services {
    public sealed class RandomVerificationCodeGenerator<TUser, TKey>: IVerificationCodeGenerator<TUser, TKey>
        where TKey : IEquatable<TKey> {
        public Task<string> GenerateAsync(
            VerificationCodeContext<TUser, TKey> context,
            VerificationOptions options,
            CancellationToken cancellationToken = default) {
            ArgumentNullException.ThrowIfNull(context);
            ArgumentNullException.ThrowIfNull(options);
            options.Validate();

            cancellationToken.ThrowIfCancellationRequested();
            var characters = new char[options.CodeLength];
            for(var index = 0; index < characters.Length; index++)
                characters[index] = (char)('0' + RandomNumberGenerator.GetInt32(0, 10));

            return Task.FromResult(new string(characters));
        }
    }
}
