using Microsoft.AspNetCore.Http;

namespace TestProject
{
    internal class TestHttpRequest : HttpRequest
    {
        private string method;
        private string requestUri;

        public TestHttpRequest(string method, string requestUri)
        {
            this.method = method;
            this.requestUri = requestUri;
        }

        public override HttpContext HttpContext => throw new NotImplementedException();

        public override string Method { get => method; set => throw new NotImplementedException(); }
        public override string Scheme { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public override bool IsHttps { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public override HostString Host { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public override PathString PathBase { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public override PathString Path { get => requestUri; set => throw new NotImplementedException(); }
        public override QueryString QueryString { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public override IQueryCollection Query { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public override string Protocol { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public override IHeaderDictionary Headers => throw new NotImplementedException();

        public override IRequestCookieCollection Cookies { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public override long? ContentLength { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public override string ContentType { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public override Stream Body { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public override bool HasFormContentType => throw new NotImplementedException();

        public override IFormCollection Form { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public override Task<IFormCollection> ReadFormAsync(CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }
    }
}