using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace RuntimeApps.Authentication.Shared.Models {
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
                // ResultCode.BadRequest retains its historical numeric value (401) for
                // serialized compatibility; HTTP semantics are mapped explicitly here.
                StatusCode = result.Code switch {
                    ResultCode.Success => StatusCodes.Status200OK,
                    ResultCode.Accepted => StatusCodes.Status202Accepted,
                    ResultCode.BadRequest => StatusCodes.Status400BadRequest,
                    ResultCode.Forbidden => StatusCodes.Status403Forbidden,
                    ResultCode.Conflict => StatusCodes.Status409Conflict,
                    ResultCode.Locked => StatusCodes.Status423Locked,
                    _ => StatusCodes.Status500InternalServerError
                };
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
