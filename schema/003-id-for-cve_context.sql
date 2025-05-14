SELECT
    assert_latest_migration (2);

ALTER TABLE public.cve_context
    DROP CONSTRAINT cve_context_pkey;

ALTER TABLE public.cve_context
    ADD COLUMN id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY;

SELECT
    log_migration (3);
