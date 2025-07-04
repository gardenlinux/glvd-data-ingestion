SELECT
    assert_latest_migration (3);

ALTER TABLE public.cve_context RENAME COLUMN context_descriptor TO use_case;

ALTER TABLE public.cve_context
    ADD COLUMN triaged boolean DEFAULT FALSE;

ALTER TABLE public.cve_context
    ALTER COLUMN is_resolved SET DEFAULT FALSE;

SELECT
    log_migration (4);

