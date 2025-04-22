# GLVD Database Schema

This directory contains the schema for the GLVD Database.

Schema migration is based on [Minimalist PostgreSQL Migrations](https://nalanj.dev/posts/minimalist-postgresql-migrations/).

To make a change to the schema, do the following:

1. Create a new file `00N-add-column-foobar.sql` where `N` is the next available integer from other migrations, and the filename somewhat describes your change

2. Ensure your script contains the approprate calls to `assert_latest_migration` and `log_migration` as in this example (replace `N` with the number of your migration)

```SQL
SELECT
    assert_latest_migration (N-1);

-- your sql to do the migration here

SELECT
    log_migration (N);
```

## Apply Schema migrations to a GLVD Gardener Cluster

To apply a schema migration to your cluster, ensure you have an image available that contains your desired schema and run a command similar to this:

```
kubectl run db-migration$RANDOM --restart='Never' --image=ghcr.io/gardenlinux/glvd-data-ingestion:latest --env=DATABASE_URL=postgres://glvd:$(kubectl get secret/postgres-credentials --template="{{.data.password}}" | base64 -d)@glvd-database-0.glvd-database:5432/glvd -- bash -c "/usr/local/src/bin/migrate /usr/local/src/schema/0XX-your-migration.sql"
```
