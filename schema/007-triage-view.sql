SELECT
    assert_latest_migration (6);

CREATE OR REPLACE VIEW public.triage AS
SELECT
    deb_cve.cve_id,
    deb_cve.deb_source AS source_package_name,
    deb_cve.deb_version AS source_package_version,
    cve_context.is_resolved AS triage_marked_as_resolved,
    cve_context.create_date AS triage_date,
    cve_context.use_case AS triage_use_case,
    cve_context.description AS triage_description,
    cve_context.gardenlinux_version AS triage_gardenlinux_version,
    nvd_cve.data -> 'vulnStatus'::text AS nvd_vulnerability_status,
    nvd_cve.data -> 'published'::text AS nvd_cve_published_date,
    nvd_cve.data -> 'lastModified'::text AS nvd_cve_last_modified_date,
    ((nvd_cve.data -> 'descriptions'::text) -> 0) -> 'value'::text AS nvd_cve_description,
    CASE WHEN ((((((nvd_cve.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric) IS NOT NULL THEN
        (((((nvd_cve.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric
    WHEN ((((((nvd_cve.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric) IS NOT NULL THEN
        (((((nvd_cve.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric
    WHEN ((((((nvd_cve.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric) IS NOT NULL THEN
        (((((nvd_cve.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric
    WHEN ((((((nvd_cve.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric) IS NOT NULL THEN
        (((((nvd_cve.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric
    ELSE
        NULL::numeric
    END AS nvd_cve_cvss_base_score
FROM
    deb_cve
    JOIN nvd_cve USING (cve_id)
    JOIN cve_context USING (cve_id, gardenlinux_version);

ALTER TABLE public.triage OWNER TO glvd;

SELECT
    log_migration (7);

