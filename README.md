# PRP: PostgREST Request Processing
*Leveraging `db_pre_request` and `request headers` to: create custom claims, generate advanced, up-to-date, scalable RLS policies, implement allow and deny lists, rate limiting, and much more.*

## Overview
**PostgREST** provides a setting called `db_pre_request` that accepts the name of a **PostgreSQL** function.  This function is executed at the beginning of each `http request` and can set up data (in memory) for the rest of the request.  Why is this so powerful and so important?

RLS (Row Level Security) policies are evaluated for every row in a query, so if you're retrieving 1000 rows the `select` policy for the table will be executed 1000 times.  To make things scalable, it's advised that you store "custom claims", which are stored in the `auth.users.raw_app_metadata` database field and sent as part of the JWT token with each request.  This puts those claims into memory, making them fast to access (and much more scalable than doing 1000 individual database lookups.)

The problem with this approach is that 1. it's pretty restricting (limited to storing the claims in a specific field in a specific table in a hidden schema), 2. claims are only read when a user logs in, so those claims can become stale if they're changed before a user logs out and then back in, 3. claims can be cumbersome to create and update.

Using `db_pre_request` solves those issues by letting you store claims data anywhere you like.  Since the `db_pre_request` function is run once for every request, claims are always current.  Creating and modifying claims is also fairly easy and very flexible.  The one drawback is that the `db_pre_request` function does need to run one time for every `http request` so it's important to keep that function as efficient as possible.  This function can be optimized, though, through features such as conditional processing.

This method is also more secure than standard claims because no claims are ever exposed to the user. 

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


## Samples

### Restricting access to your application with RBAC or ABAC

- RBAC (Role Based Access Control): [RBAC Demo](examples/RBAC/rbac_demo.sql)

### Multi-tenancy application

### Allow-listing by IP Address

### Rate Limiting

### Gathering basic usage data: country, platform, user-agent

### Conditionally setting claims
#### using custom headers
#### based on the current user

## Reference
sample: `req()->>'claim_name'`

```json
{
  "aal": "aal1",
  "amr": [
    {
      "method": "password",
      "timestamp": 9999999999
    }
  ],
  "aud": "authenticated",
  "exp": 9999999999,
  "sub": "<uuid>",
  "role": "authenticated",
  "email": "<email>",
  "phone": "",
  "headers": {
    "host": "localhost:3000",
    "accept": "*/*",
    "cf-ray": "xxxxxxxxxxxxxxxx-ABC",
    "origin": "<host_url>",
    "referer": "<host_url>",
    "cdn-loop": "cloudflare; subreqs=1",
    "priority": "u=1, i",
    "cf-ew-via": "15",
    "cf-worker": "supabase.co",
    "sec-ch-ua": "\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\"",
    "x-real-ip": "<ip_address>",
    "cf-visitor": "{\"scheme\":\"https\"}",
    "connection": "keep-alive",
    "user-agent": "<user_agent>",
    "cf-ipcountry": "US",
    "content-type": "application/json",
    "authorization": "Bearer <token>",
    "x-client-info": "supabase-js/2.26.0",
    "x-consumer-id": "<id>",
    "content-length": "2",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "cross-site",
    "accept-encoding": "gzip",
    "accept-language": "en-US,en;q=0.9",
    "content-profile": "public",
    "x-forwarded-for": "<ip_address>, <ip_address>",
    "cf-connecting-ip": "<ip_address>",
    "sec-ch-ua-mobile": "?0",
    "x-forwarded-host": "<ref>.supabase.co",
    "x-forwarded-path": "/rest/v1/rpc/req",
    "x-forwarded-port": "443",
    "x-forwarded-proto": "https",
    "sec-ch-ua-platform": "\"<platform>\"",
    "x-forwarded-prefix": "/rest/v1/",
    "x-consumer-username": "anon-key",
    "x-credential-identifier": "<uuid>"
  },
  "session_id": "<uuid>",
  "app_metadata": {
    "provider": "email",
    "mysetting": "AAA",
    "providers": [
      "email"
    ]
  },
  "user_metadata": {},
}
```



