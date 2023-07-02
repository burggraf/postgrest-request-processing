# PRP: PostgREST Request Processing
*Leveraging `db_pre_request` and request headers to create custom claims, advanced, scalable RLS policies, and much more.*

## Features
- Access the JWT token
  - user info: id, email, phone, database role, metadata
  - session id
  - app metadata (authentication provider, other available providers, custom metadata)
  - 2FA data (i.e. is the user currently using 2FA?)
- Access the request headers
  - connection information
  - client type
  - request content information
  - use connection information for:
    - allow-listing and deny-listing all or portions of your application
    - rate limiting users
- Create custom claims
  - Read related data (such as a table of users and roles for your application)
  - Use any custom logic
  - Use the claims in RLS (Row Level Security) policies
  - Claims are always current because they're created on each request
  - Claims are only processed once per request so they're efficient in RLS policies
   

