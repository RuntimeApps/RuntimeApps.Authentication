namespace RuntimeApps.Authentication.Model {
    public class Result {
        public Result() {
            Code = ResultCode.Success;
        }

        public Result(ResultCode code, string message) {
            Code = code;
            Message = message;
        }

        public ResultCode Code { get; set; }
        public string Message { get; set; }
        public bool Success => Code == ResultCode.Success;
    }

    public class Result<T>: Result {
        public Result() : base() { }
        public Result(ResultCode code, string message) : base(code, message) { }
        public Result(T data) : base() {
            Data = data;
        }

        public T Data { get; set; }
    }

    public class Result<TData, TMeta>: Result<TData> {
        public Result() : base() { }
        public Result(ResultCode code, string message) : base(code, message) { }
        public Result(TData data, TMeta meta) : base(data) {
            Meta = meta;
        }

        public TMeta Meta { get; set; }
    }

    public class ArrayResult<T>: Result<IEnumerable<T>> {
        public ArrayResult() : base() { }
        public ArrayResult(ResultCode code, string message) : base(code, message) { }
        public ArrayResult(IEnumerable<T> data, int? totalHits = null) : base(data) {
            TotalHits = totalHits;
        }

        public int? TotalHits { get; set; }
    }


    public class ArrayResult<TData, TMeta>: ArrayResult<TData> {
        public ArrayResult() : base() { }
        public ArrayResult(ResultCode code, string message) : base(code, message) { }
        public ArrayResult(IEnumerable<TData> data, TMeta meta, int? totalHits = null) : base(data, totalHits) {
            Meta = meta;
        }

        public virtual TMeta Meta { get; set; }
    }
}
