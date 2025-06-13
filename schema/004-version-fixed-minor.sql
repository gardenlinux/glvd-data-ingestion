SELECT
    assert_latest_migration (3);

ALTER TABLE public.debsec_cve
    ADD COLUMN minor_deb_version_fixed text;

ALTER TABLE public.debsrc
    ADD COLUMN minor_deb_version text;

SELECT
    log_migration (4);

