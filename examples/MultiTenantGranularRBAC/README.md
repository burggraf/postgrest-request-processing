# Multi-Tenant Granular RBAC: Role Based Access Control

RBAC is a way to control access to your application based on a set of "**user roles**".  These roles are not to be confused with PostgreSQL `roles` (which are synonymous with `users` in PostgreSQL).  These roles are completely arbitrary and you can create as many distinct roles as necessary for your application.

In this complex implementation of RBAC:
- Roles are named `role` (because it's up to you to know the difference between the role table and Postgres `roles`).
- Tenants are separation boundaries between company data in the application. It is possible however for one user to access multiple tenants if they've been given permissions to do so via their `membership`.
- The `membership` table binds a `user` to a `role` and a `tenant`. 
- Each user of your application (stored in the `auth.users` table) can have zero or one membership per tenant. Memberships joined with the role permissions are captured in the `permissions` key.
- The `permissions` is accessible in your RLS policies and PostgreSQL functions through `req()->'permissions'`.


-- RBAC (Role Based Access Control) demo

## WIP