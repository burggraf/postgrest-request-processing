# RBAC: Role Based Access Control

RBAC is a way to control access to your application based on a set of "**user roles**".  These roles are not to be confused with PostgreSQL `roles` (which are synonymous with `users` in PostgreSQL).  These roles are completely arbitrary and you can create as many distinct roles as necessary for your application.

In this simple implementation of RBAC:
- Roles are named `user_role` (to distinguish them from PostgreSQL `roles`).
- Each user of your application (stored in the `auth.users` table) can have zero or one user_role.  (A user with no `user_role` has a `user_role` of `null`).
- Unauthenticated users will always have a `user_role` of `null`.
- The `user_role` is accessible in your RLS policies and PostgreSQL functions through `req()->'user_role'`.

-- RBAC (Role Based Access Control) demo
-- 1.  Create a table called user_roles with columns uid (uuid) and role (text)
-- 2.  Add users to the user_roles table with a designated role
-- 3.  The db_pre_request function will add the user's role to the claims
-- 4.  To access a user's role, use the following syntax: (req()->>'user_role')
-- 5.  Unauthenticated users or users without a role have a null role

## Setting up RBAC

### Step 1: Set up the `user_roles` table

This table requires just two fields:  `uid` which is a foreign key to `auth.users.id` and `role`.  You can add as many other columns to this table as you want, depending on your application needs.

Create the table including primary key and foreign key relationships:

```sql
CREATE TABLE "public"."user_roles"(
    "uid" "uuid" NOT NULL,
    "role" "text" NOT NULL
);
ALTER TABLE "public"."user_roles" OWNER TO "postgres";
ALTER TABLE ONLY "public"."user_roles"
    ADD CONSTRAINT "user_roles_pkey" PRIMARY KEY ("uid");
ALTER TABLE ONLY "public"."user_roles"
    ADD CONSTRAINT "user_roles_uid_fkey" FOREIGN KEY ("uid") REFERENCES "auth"."users"("id") ON DELETE CASCADE;
```

Turn on RLS and set up a policy so users can view their own role:

```sql
ALTER TABLE "public"."user_roles" ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own role" ON "public"."user_roles" AS PERMISSIVE
    FOR SELECT TO public
        USING (uid = auth.uid());
```

Grant usage on this table (don't worry, access to this table is blocked by RLS policies except for the `SELECT` policy we created above.):

```sql
GRANT ALL ON TABLE "public"."user_roles" TO "anon";
GRANT ALL ON TABLE "public"."user_roles" TO "authenticated";
GRANT ALL ON TABLE "public"."user_roles" TO "service_role";
```

### Step 2: Create the `db_pre_request` function

This function will add the `user_role` claim to the `req()` (request):

```sql
CREATE OR REPLACE FUNCTION db_pre_request()
    RETURNS jsonb
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public
AS $$
DECLARE
    claims jsonb;
    user_role text;
    headers jsonb;
BEGIN
    -- get the claims from the JWT
    SELECT coalesce(current_setting('request.jwt.claims', TRUE), '{}') INTO claims;
    SELECT coalesce(current_setting('request.headers', TRUE), '{}') INTO headers;
    claims := claims || jsonb_build_object('headers', headers);
    -- ******************************** CUSTOM CLAIMS ********************************
    -- get user_role from the user_roles table and add it to the claims
    SELECT role FROM user_roles
    WHERE uid =((claims::jsonb) ->> 'sub')::uuid 
    INTO user_role;
    claims := claims || jsonb_build_object('user_role', user_role);
    -- *******************************************************************************
    PERFORM set_config('request.claims'::text, claims::text, FALSE /* is_local */);
    RETURN claims;
END;
$$;
```

Now we "turn on" the `db_pre_request` function so it runs on every PostgREST request:

```sql
ALTER ROLE authenticator SET pgrst.db_pre_request TO 'public.db_pre_request';
NOTIFY pgrst,
'reload config';
```

And lastly, we create the `req()` function to make it easy to get at the results of the `db_pre_request` function from inside of *RLS Policies* and *PostgreSQL Functions*:

```sql
-- this helper function returns the current claims set by the db_pre_request function
CREATE OR REPLACE FUNCTION req()
    RETURNS "jsonb"
    LANGUAGE "sql"
    STABLE
AS $$
  select coalesce(current_setting('request.claims', true), '{}')::JSONB
$$;
```

## Using RBAC in your application

It's your responsibility to set up user roles in the `user_roles` table.  You can do that:
- manually with sql
- with triggers
- with an adminstrative page that sets roles for your users
- from an edge function

A good example might be setting roles equal to subscription plans for your application.  So you might have plans: FREE, PRO, DELUXE, and ENTERPRISE.  You could create a page where users subscribe to a plan which calls an edge function.  The edge function calls Stripe to process a credit card, and when successful the edge function sets the user's `user_role` to match their selected plan.

### Using the `user_role` in an RLS (Row Level Security) Policy

To check a user's role in an RLS policy or a postgresql function, use the following syntax:
`req()->>'user_role'`

(Note we use the `->>` JSONB operator here to make this return `TEXT`.  If we used `->` the result would be a JSONB object instead.)

RLS policy examples:

```sql
CREATE POLICY "Only admin users can view the secret table" 
    ON "public"."secret" 
    AS PERMISSIVE
    FOR SELECT TO public
        USING (req()->>'user_role') = 'admin';
```

```sql
CREATE POLICY "Only users on the enterprise tier can view the this table" 
    ON "public"."enterprise_content" 
    AS PERMISSIVE
    FOR SELECT TO public
        USING (req()->>'user_role') = 'ENTERPRISE';
```

### Using the `user_role` in a PostgreSQL Function

Example postgresql function:

```sql
CREATE OR REPLACE FUNCTION "public"."get_secret"()
   RETURNS "text"
   LANGUAGE "plpgsql"
AS $$
    DECLARE output text;
BEGIN
    IF (req()->>'user_role') = 'admin' THEN
        select secret_code from secret into output;
        RETURN output;
    ELSE
        RAISE EXCEPTION 'You are not authorized to view this secret';
    END IF;
END;
$$;

