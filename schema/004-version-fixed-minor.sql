SELECT
    assert_latest_migration (3);

ALTER TABLE public.debsec_cve
    ADD COLUMN minor_deb_version_fixed text;

SELECT
    log_migration (4);

