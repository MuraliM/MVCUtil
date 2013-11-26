[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class,
                AllowMultiple = false, Inherited = true)]
    public sealed class ValidateJsonAntiForgeryTokenAttribute
                                : FilterAttribute, IAuthorizationFilter
    {
        private readonly AcceptVerbsAttribute _verbs;

        public ValidateJsonAntiForgeryTokenAttribute()
            : this(HttpVerbs.Post)
        {}

        public ValidateJsonAntiForgeryTokenAttribute(HttpVerbs verbs)
        {
            this._verbs = new AcceptVerbsAttribute(verbs);
        }

        public void OnAuthorization(AuthorizationContext filterContext)
        {
            string httpMethodOverride = filterContext.HttpContext.Request.GetHttpMethodOverride();
            if (this._verbs.Verbs.Contains(httpMethodOverride, StringComparer.OrdinalIgnoreCase))
            {
                if (filterContext == null)
                {
                    throw new ArgumentNullException("filterContext");
                }

                if (filterContext.HttpContext.Request.IsAjaxRequest())
                {

                    var httpContext = filterContext.HttpContext;
                    var cookie = httpContext.Request.Cookies[AntiForgeryConfig.CookieName];
                    AntiForgery.Validate(cookie != null ? cookie.Value : null,
                                         httpContext.Request.Headers["__RequestVerificationToken"]);
                }
                else
                    new ValidateAntiForgeryTokenAttribute().OnAuthorization(filterContext);
            }
        }
