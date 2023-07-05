-- RBAC (Role Based Access Control) demo
-- 1.  Create a table called user_roles with columns uid (uuid) and role (text)
-- 2.  Add users to the user_roles table with a designated role
-- 3.  The db_pre_request function will add the user's role to the claims
-- 4.  To access a user's role, use the following syntax: (req()->>'user_role')
-- 5.  Unauthenticated users or users without a role have a null role

-- *****************************************************
-- set up the user_roles table with uid and role columns
-- uid will be a foreign key to auth.users.id
CREATE TABLE "public"."user_roles"(
    "uid" "uuid" NOT NULL,
    "role" "text" NOT NULL
);

ALTER TABLE "public"."user_roles" OWNER TO "postgres";

ALTER TABLE ONLY "public"."user_roles"
    ADD CONSTRAINT "user_roles_pkey" PRIMARY KEY ("uid");

ALTER TABLE ONLY "public"."user_roles"
    ADD CONSTRAINT "user_roles_uid_fkey" FOREIGN KEY ("uid") REFERENCES "auth"."users"("id") ON DELETE CASCADE;

ALTER TABLE "public"."user_roles" ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own role" ON "public"."user_roles" AS PERMISSIVE
    FOR SELECT TO public
        USING (uid = auth.uid());

GRANT ALL ON TABLE "public"."user_roles" TO "anon";
GRANT ALL ON TABLE "public"."user_roles" TO "authenticated";
GRANT ALL ON TABLE "public"."user_roles" TO "service_role";
-- ***** done setting up user_roles table ************************

-- create db_pre_request function
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
    SELECT
        coalesce(current_setting('request.jwt.claims', TRUE), '{}') INTO claims;
    SELECT
        coalesce(current_setting('request.headers', TRUE), '{}') INTO headers;
    claims := claims || jsonb_build_object('headers', headers);
    -- ******************************** CUSTOM CLAIMS ********************************
    -- get user_role from the user_roles table and add it to the claims
    SELECT
        ROLE
    FROM
        user_roles
    WHERE
        uid =((claims::jsonb) ->> 'sub')::uuid INTO user_role;
    claims := claims || jsonb_build_object('user_role', user_role);
    -- *******************************************************************************
    PERFORM
        set_config('request.claims'::text, claims::text, FALSE /* is_local */);
    RETURN claims;
END;
$$;
ALTER ROLE authenticator SET pgrst.db_pre_request TO 'public.db_pre_request';
NOTIFY pgrst,
'reload config';

-- this helper function returns the current claims set by the db_pre_request function
CREATE OR REPLACE FUNCTION req()
    RETURNS "jsonb"
    LANGUAGE "sql"
    STABLE
    AS $$
  select 
  	coalesce(current_setting('request.claims', true), '{}')::JSONB
$$;

-- to check a user's role in an RLS policy or a postgresql function, 
-- use the following syntax: (req()->>'user_role')
--
-- example RLS policy:
-- CREATE POLICY "Only admin users can view the secret table" ON "public"."secret" AS PERMISSIVE
--    FOR SELECT TO public
--        USING (req()->>'user_role') = 'admin';

-- example postgresql function:
-- CREATE OR REPLACE FUNCTION "public"."get_secret"()
--    RETURNS "text"
--    LANGUAGE "plpgsql"
--    AS $$
--      DECLARE output text;
--    BEGIN
--        IF (req()->>'user_role') = 'admin' THEN
--          select secret_code from secret into output;
--          RETURN output;
--        ELSE
--          RAISE EXCEPTION 'You are not authorized to view this secret';
--        END IF;
--    END;
--    $$;
