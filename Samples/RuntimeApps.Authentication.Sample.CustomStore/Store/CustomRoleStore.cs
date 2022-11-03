using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Sample.CustomStore.Store {
    public class CustomRoleStore: RoleStoreBase<IdentityRole, string, IdentityUserRole<string>, IdentityRoleClaim<string>> {
        private readonly IStoreUnitOfWork _storeUnitOfWork;
        private readonly IdentityErrorDescriber _describer;

        public CustomRoleStore(IdentityErrorDescriber describer, IStoreUnitOfWork storeUnitOfWork) : base(describer) {
            _storeUnitOfWork = storeUnitOfWork;
            _describer = describer;
        }

        public override IQueryable<IdentityRole> Roles => RoleData.Values.AsQueryable();
        private Dictionary<string, IdentityRole> RoleData { get => _storeUnitOfWork.Roles; }
        private List<IdentityRoleClaim<string>> RoleClaims { get => _storeUnitOfWork.RoleClaims; }

        public override Task<IdentityResult> CreateAsync(IdentityRole role, CancellationToken cancellationToken = default) {
            role.Id = role.NormalizedName;
            if(RoleData.TryAdd(role.Id, role))
                return Task.FromResult(IdentityResult.Success);
            else
                return Task.FromResult(IdentityResult.Failed(_describer.DuplicateRoleName(role.Name)));
        }

        public override Task<IdentityResult> UpdateAsync(IdentityRole role, CancellationToken cancellationToken = default) {
            if(RoleData.ContainsKey(role.Id))
                RoleData[role.Id] = role;
            return Task.FromResult(IdentityResult.Success);
        }

        public override Task<IdentityResult> DeleteAsync(IdentityRole role, CancellationToken cancellationToken = default) {
            RoleData.Remove(role.Id);
            return Task.FromResult(IdentityResult.Success);
        }

        public override Task<IdentityRole> FindByIdAsync(string id, CancellationToken cancellationToken = default) {
            RoleData.TryGetValue(id, out var role);
            return Task.FromResult(role);
        }

        public override Task<IdentityRole> FindByNameAsync(string normalizedName, CancellationToken cancellationToken = default) =>
            FindByIdAsync(normalizedName, cancellationToken);

        public override Task AddClaimAsync(IdentityRole role, Claim claim, CancellationToken cancellationToken = default) {
            RoleClaims.Add(new IdentityRoleClaim<string> {
                Id = _storeUnitOfWork.GetRoleClaimId(),
                RoleId = role.Id,
                ClaimType = claim.Type,
                ClaimValue = claim.Value
            });
            return Task.CompletedTask;
        }

        public override Task<IList<Claim>> GetClaimsAsync(IdentityRole role, CancellationToken cancellationToken = default) =>
            Task.FromResult<IList<Claim>>(RoleClaims.Where(c => c.RoleId == role.Id).Select(c => new Claim(c.ClaimType, c.ClaimValue)).ToList());

        public override Task RemoveClaimAsync(IdentityRole role, Claim claim, CancellationToken cancellationToken = default) {
            var roleClaim = RoleClaims.FirstOrDefault(c => c.RoleId == role.Id && c.ClaimType == claim.Type && c.ClaimValue == claim.Value);
            if(roleClaim != null)
                RoleClaims.Remove(roleClaim);
            return Task.CompletedTask;
        }
    }
}
