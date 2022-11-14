using System.Security.Claims;

namespace RuntimeApps.Authentication.Model {
    public class ClaimDto {
        public string Type { get; set; }
        public string Value { get; set; }

        public ClaimDto() { }
        public ClaimDto(Claim claim) {
            Type = claim.Type;
            Value = claim.Value;
        }

        public virtual Claim ToClaim() {
            return new Claim(Type, Value);
        }
    }
}
