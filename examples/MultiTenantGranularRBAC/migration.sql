
CREATE TABLE public.tenant (
  id UUID NOT NULL DEFAULT gen_random_uuid(),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  name TEXT NOT NULL,
  features JSONB NULL,
  CONSTRAINT tenant_pkey PRIMARY KEY (id),
  UNIQUE (name)
) TABLESPACE pg_default;

ALTER TABLE public.tenant ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.role (
  id UUID NOT NULL DEFAULT gen_random_uuid(),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  tenant_id UUID NOT NULL,
  name TEXT NOT NULL,
  permissions JSONB NULL,
  CONSTRAINT role_pkey PRIMARY KEY (id),
  CONSTRAINT role_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenant (id) ON DELETE CASCADE,
  UNIQUE (tenant_id, name)
) TABLESPACE pg_default;

ALTER TABLE public.role ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.membership (
  id UUID NOT NULL DEFAULT gen_random_uuid(),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  user_id UUID NOT NULL,
  tenant_id UUID NOT NULL,
  role_id UUID NOT NULL,
  CONSTRAINT membership_pkey PRIMARY KEY (id),
  CONSTRAINT membership_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenant (id) ON DELETE CASCADE,
  CONSTRAINT membership_role_id_fkey FOREIGN KEY (role_id) REFERENCES role (id) ON DELETE CASCADE,
  CONSTRAINT membership_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users (id) ON DELETE CASCADE,
  UNIQUE (user_id, tenant_id)
) TABLESPACE pg_default;

ALTER TABLE public.membership ENABLE ROW LEVEL SECURITY;



-- create db_pre_request function
CREATE OR REPLACE FUNCTION db_pre_request()
  RETURNS jsonb
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path = public
  AS $$
DECLARE
  claims jsonb;
  user_permissions jsonb;
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
    jsonb_object_agg(r.tenant_id, r.permissions)
  FROM
    membership m
  JOIN role r ON m.role_id = r.id
  WHERE
    m.user_id =((claims::jsonb) ->> 'sub')::uuid
  INTO user_permissions;
  claims := claims || jsonb_build_object('permissions', user_permissions);
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


-- Create RLS policies for Tenant, Role, and Membership tables

CREATE POLICY "Tenant: Select any" ON "public"."tenant" AS PERMISSIVE
  FOR SELECT TO public
    USING (req() @@ (format('$.permissions.%I.tenant.read'::text, id))::jsonpath);

CREATE POLICY "Tenant: Insert any" ON "public"."tenant" AS PERMISSIVE
  FOR INSERT TO public
    WITH CHECK ((req() @@ (format('$.permissions.%I.tenant.write'::text, id))::jsonpath));

CREATE POLICY "Tenant: Update any" ON "public"."tenant" AS PERMISSIVE
  FOR UPDATE TO public
    USING ((req() @@ (format('$.permissions.%I.tenant.write'::text, id))::jsonpath))
    WITH CHECK ((req() @@ (format('$.permissions.%I.tenant.write'::text, id))::jsonpath));

-- Implicitly already denied but also denying explicitly here for clarity. No user should have "Delete" access to tenants.
CREATE POLICY "Tenant: Delete any" ON "public"."tenant" AS PERMISSIVE
  FOR DELETE TO public
    USING (FALSE);

-- Implicitly already denied but also denying explicitly here for clarity. No user should have "All" access to tenants.
CREATE POLICY "Tenant: All any" ON "public"."tenant" AS PERMISSIVE
  FOR ALL TO public
    USING (FALSE)
    WITH CHECK (FALSE);


GRANT ALL ON TABLE "public"."tenant" TO "anon";
GRANT ALL ON TABLE "public"."tenant" TO "authenticated";
GRANT ALL ON TABLE "public"."tenant" TO "service_role";


CREATE POLICY "Role: Select any" ON "public"."role" AS PERMISSIVE
  FOR SELECT TO public
    USING (req() @@ (format('$.permissions.%I.role.read'::text, tenant_id))::jsonpath);

CREATE POLICY "Role: Insert any" ON "public"."role" AS PERMISSIVE
  FOR INSERT TO public
    WITH CHECK ((req() @@ (format('$.permissions.%I.role.write'::text, tenant_id))::jsonpath));

CREATE POLICY "Role: Update any" ON "public"."role" AS PERMISSIVE
  FOR UPDATE TO public
    USING ((req() @@ (format('$.permissions.%I.role.write'::text, tenant_id))::jsonpath))
    WITH CHECK ((req() @@ (format('$.permissions.%I.role.write'::text, tenant_id))::jsonpath));

CREATE POLICY "Role: Delete any" ON "public"."role" AS PERMISSIVE
  FOR DELETE TO public
    USING ((req() @@ (format('$.permissions.%I.role.write'::text, tenant_id))::jsonpath));

CREATE POLICY "Role: All any" ON "public"."role" AS PERMISSIVE
  FOR ALL TO public
    USING ((req() @@ (format('$.permissions.%I.role.all'::text, tenant_id))::jsonpath))
    WITH CHECK ((req() @@ (format('$.permissions.%I.role.all'::text, tenant_id))::jsonpath));

GRANT ALL ON TABLE "public"."role" TO "anon";
GRANT ALL ON TABLE "public"."role" TO "authenticated";
GRANT ALL ON TABLE "public"."role" TO "service_role";


CREATE POLICY "Membership: Select own" ON "public"."membership" AS PERMISSIVE
  FOR SELECT TO public
    USING (user_id = auth.uid());

CREATE POLICY "Membership: Select any" ON "public"."membership" AS PERMISSIVE
  FOR SELECT TO public
    USING (req() @@ (format('$.permissions.%I.membership.read'::text, tenant_id))::jsonpath);

CREATE POLICY "Membership: Insert any but own" ON "public"."membership" AS PERMISSIVE
  FOR INSERT TO public
    WITH CHECK (user_id != auth.uid() AND (req() @@ (format('$.permissions.%I.membership.write'::text, tenant_id))::jsonpath));

CREATE POLICY "Membership: Update any but own" ON "public"."membership" AS PERMISSIVE
  FOR UPDATE TO public
    USING (user_id != auth.uid() AND req() @@ (format('$.permissions.%I.membership.write'::text, tenant_id))::jsonpath)
    WITH CHECK (user_id != auth.uid() AND (req() @@ (format('$.permissions.%I.membership.write'::text, tenant_id))::jsonpath));

CREATE POLICY "Membership: Delete any but own" ON "public"."membership" AS PERMISSIVE
  FOR DELETE TO public
  USING (user_id != auth.uid() AND req() @@ (format('$.permissions.%I.membership.write'::text, tenant_id))::jsonpath);

-- CREATE POLICY "Membership: All any" ON "public"."membership" AS PERMISSIVE
--   FOR ALL TO public
--     USING (user_id != auth.uid() AND req() @@ (format('$.permissions.%I.membership.all'::text, tenant_id))::jsonpath)
--     WITH CHECK (user_id != auth.uid() AND (req() @@ (format('$.permissions.%I.membership.all'::text, tenant_id))::jsonpath));


GRANT ALL ON TABLE "public"."membership" TO "anon";
GRANT ALL ON TABLE "public"."membership" TO "authenticated";
GRANT ALL ON TABLE "public"."membership" TO "service_role";



CREATE TABLE public.profile (
  id uuid NOT NULL PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  preferred_name text NULL,
  preferences jsonb NULL
) TABLESPACE pg_default;

ALTER TABLE public.profile ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Profile: Select own" ON "public"."profile" AS PERMISSIVE
  FOR SELECT TO public
  USING (id = auth.uid());

CREATE POLICY "Profile: Update own" ON "public"."profile" AS PERMISSIVE
  FOR UPDATE TO public
  USING (id = auth.uid());

-- Implicitly already denied but also denying explicitly here for clarity. No user should have "Delete" access to profile.
CREATE POLICY "Profile: Delete any" ON "public"."profile" AS PERMISSIVE
  FOR DELETE TO public
    USING (FALSE);

-- Implicitly already denied but also denying explicitly here for clarity. No user should have "All" access to profile.
CREATE POLICY "Profile: All any" ON "public"."profile" AS PERMISSIVE
  FOR ALL TO public
    USING (FALSE);

GRANT ALL ON TABLE "public"."profile" TO "anon";
GRANT ALL ON TABLE "public"."profile" TO "authenticated";
GRANT ALL ON TABLE "public"."profile" TO "service_role";
