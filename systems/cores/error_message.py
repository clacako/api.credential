def error_message(api_name, error_type, code=None):
    api   = {
        "credential"                : "CDRL",
        "token"                     : "TKN",
        "users"                     : "USR",
        "roles"                     : "RLS",
        "domains"                   : "DMNS",
        "applications"              : "APPS",
        "application_details"       : "APPDTL",
        "application_users"         : "APPUSRS",
        "application_roles"         : "APPRLS",
        "application_domains"       : "APPDMNS",
        "application_domains_users" : "APPDMNSUSRS",
        "application_sckey"         : "APPSCKEY",
    }
    
    errors  = {
        "auth"          : "AUTH",
        "not_found"     : "ODEX",
        "request_data"  : "REQDT",
        "serializer"    : "SRZR",
    }
    
    return f"ERRORCODE: {api.get(api_name)}_{errors.get(error_type)} {code if code else ''}"
