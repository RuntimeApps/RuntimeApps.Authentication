using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace RuntimeApps.Authentication.Model {
    public class ApiResult: ObjectResult {
        public ApiResult() : base(new Result()) {
        }
        public ApiResult(ResultCode code, IEnumerable<IdentityError> errors) : base(new Result(code, errors)) {
        }
        public ApiResult(Result result) : base(result) {
        }
        public ApiResult(ResultCode code, string errorCode, string errorDescription) : base(new Result(code, new IdentityError[] {
            new IdentityError() {
                Code = errorCode,
                Description = errorDescription
            }
        })) { }
        public ApiResult(IdentityResult result): base(new Result(result.Succeeded ? ResultCode.Success : ResultCode.BadRequest, result.Errors)) {
        }

        public override void OnFormatting(ActionContext context) {
            if(StatusCode == null && Value is Result result) {
                StatusCode = (int)result.Code;
            }
            base.OnFormatting(context);
        }
    }

    public class ApiResult<T>: ApiResult {
        public ApiResult(T result) : base(new Result<T>(result)) {
        }
        public ApiResult(IdentityResult result, T data): base(new Result<T>(result.Succeeded ? ResultCode.Success : ResultCode.BadRequest, result.Errors) {
            Data = data
        }) {
        }
    }

}
