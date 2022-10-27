using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Model {
    public class Result {
        public static IEnumerable<IdentityError> CreateErrors(string code, string description) => new IdentityError[]{
                CreateError(code, description)
            };

        public static IdentityError CreateError(string code, string description) => new IdentityError() {
            Code = code,
            Description = description
        };

        public Result() {
            Code = ResultCode.Success;
            Errors = null;
        }

        public Result(ResultCode code, IEnumerable<IdentityError> errors) {
            Code = code;
            Errors = errors;
        }

        public ResultCode Code { get; set; }
        public bool Succeeded => Code == ResultCode.Success;
        public IEnumerable<IdentityError> Errors { get; set; }
    }

    public class Result<T>: Result {
        public Result() : base() { }
        public Result(ResultCode code, IEnumerable<IdentityError> errors) : base(code, errors) { }
        public Result(T data) : base() {
            Data = data;
        }

        public T Data { get; set; }
    }

    public class Result<TData, TMeta>: Result<TData> {
        public Result() : base() { }
        public Result(ResultCode code, IEnumerable<IdentityError> errors) : base(code, errors) { }
        public Result(TData data, TMeta meta) : base(data) {
            Meta = meta;
        }

        public TMeta Meta { get; set; }
    }

    public class ArrayResult<T>: Result<IEnumerable<T>> {
        public ArrayResult() : base() { }
        public ArrayResult(ResultCode code, IEnumerable<IdentityError> errors) : base(code, errors) { }
        public ArrayResult(IEnumerable<T> data, int? totalHits = null) : base(data) {
            TotalHits = totalHits;
        }

        public int? TotalHits { get; set; }
    }


    public class ArrayResult<TData, TMeta>: ArrayResult<TData> {
        public ArrayResult() : base() { }
        public ArrayResult(ResultCode code, IEnumerable<IdentityError> errors) : base(code, errors) { }
        public ArrayResult(IEnumerable<TData> data, TMeta meta, int? totalHits = null) : base(data, totalHits) {
            Meta = meta;
        }

        public virtual TMeta Meta { get; set; }
    }
}
