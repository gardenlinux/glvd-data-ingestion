SELECT
    assert_latest_migration (1);

CREATE OR REPLACE VIEW public.sourcepackagecve AS
SELECT
    all_cve.cve_id,
    deb_cve.deb_source AS source_package_name,
    deb_cve.deb_version AS source_package_version,
    dist_cpe.cpe_version AS gardenlinux_version,
    (deb_cve.debsec_vulnerable
        AND cve_context.is_resolved IS NOT TRUE) = TRUE AS is_vulnerable,
    deb_cve.debsec_vulnerable,
    cve_context.is_resolved,
    all_cve.data ->> 'published'::text AS cve_published_date,
    all_cve.data ->> 'lastModified'::text AS cve_last_modified_date,
    all_cve.last_mod AS cve_last_ingested_date,
    CASE WHEN ((((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric) IS NOT NULL THEN
        (((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric
    WHEN ((((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric) IS NOT NULL THEN
        (((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric
    WHEN ((((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric) IS NOT NULL THEN
        (((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric
    WHEN ((((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric) IS NOT NULL THEN
        (((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric
    ELSE
        NULL::numeric
    END AS base_score,
    CASE WHEN (((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text) IS NOT NULL THEN
        ((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text
    WHEN (((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text) IS NOT NULL THEN
        ((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text
    WHEN (((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text) IS NOT NULL THEN
        ((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text
    WHEN (((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text) IS NOT NULL THEN
        ((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text
    ELSE
        NULL::text
    END AS vector_string,
    (((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric AS base_score_v40,
    (((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric AS base_score_v31,
    (((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric AS base_score_v30,
    (((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric AS base_score_v2,
    ((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text AS vector_string_v40,
    ((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text AS vector_string_v31,
    ((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text AS vector_string_v30,
    ((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text AS vector_string_v2
FROM
    all_cve
    JOIN deb_cve USING (cve_id)
    JOIN dist_cpe ON deb_cve.dist_id = dist_cpe.id
    FULL JOIN cve_context USING (cve_id, dist_id)
WHERE
    dist_cpe.cpe_product = 'gardenlinux'::text
    AND deb_cve.debsec_vulnerable = TRUE
    -- change view to ignore linux-specific CVEs as we are getting them from cve_context_kernel which is filled from the upstream kernel
    AND deb_cve.deb_source <> 'linux';

ALTER TABLE public.sourcepackagecve OWNER TO glvd;

CREATE OR REPLACE VIEW public.kernel_vulns AS
SELECT
    all_cve.cve_id,
    deb_cve.deb_source AS source_package_name,
    deb_cve.deb_version AS source_package_version,
    dist_cpe.cpe_version AS gardenlinux_version,
    ((deb_cve.deb_version < cve_context_kernel.fixed_version::debversion
        OR cve_context_kernel.fixed_version IS NULL)
    AND cve_context_kernel.is_relevant_subsystem IS TRUE
    AND cve_context.is_resolved IS NOT TRUE) = TRUE AS is_vulnerable,
    cve_context_kernel.is_relevant_subsystem,
    cve_context_kernel.lts_version,
    cve_context_kernel.fixed_version::debversion AS fixed_version,
    cve_context_kernel.is_fixed
FROM
    all_cve
    JOIN deb_cve USING (cve_id)
    JOIN dist_cpe ON deb_cve.dist_id = dist_cpe.id
    FULL JOIN cve_context USING (cve_id, dist_id)
    JOIN cve_context_kernel cve_context_kernel (cve_id_1, lts_version, fixed_version, is_fixed, is_relevant_subsystem, source_data) ON all_cve.cve_id = cve_context_kernel.cve_id_1
        AND cve_context_kernel.lts_version = concat(split_part(deb_cve.deb_version::text, '.'::text, 1), '.', split_part(deb_cve.deb_version::text, '.'::text, 2))
WHERE
    dist_cpe.cpe_product = 'gardenlinux'::text
    AND ((deb_cve.deb_version < cve_context_kernel.fixed_version::debversion
            OR cve_context_kernel.fixed_version IS NULL)
        AND cve_context_kernel.is_relevant_subsystem IS TRUE
        AND cve_context.is_resolved IS NOT TRUE) = TRUE
    AND deb_cve.deb_source = 'linux'::text;

ALTER TABLE public.kernel_vulns OWNER TO glvd;

CREATE OR REPLACE VIEW public.kernel_cve AS
SELECT
    k.cve_id,
    k.source_package_name,
    k.source_package_version,
    k.lts_version,
    k.gardenlinux_version,
    k.is_vulnerable,
    k.fixed_version,
    nvd.data ->> 'published'::text AS cve_published_date,
    nvd.data ->> 'lastModified'::text AS cve_last_modified_date,
    nvd.last_mod AS cve_last_ingested_date,
    CASE WHEN ((((((nvd.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric) IS NOT NULL THEN
        (((((nvd.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric
    WHEN ((((((nvd.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric) IS NOT NULL THEN
        (((((nvd.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric
    WHEN ((((((nvd.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric) IS NOT NULL THEN
        (((((nvd.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric
    WHEN ((((((nvd.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric) IS NOT NULL THEN
        (((((nvd.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric
    ELSE
        NULL::numeric
    END AS base_score,
    CASE WHEN (((((nvd.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text) IS NOT NULL THEN
        ((((nvd.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text
    WHEN (((((nvd.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text) IS NOT NULL THEN
        ((((nvd.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text
    WHEN (((((nvd.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text) IS NOT NULL THEN
        ((((nvd.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text
    WHEN (((((nvd.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text) IS NOT NULL THEN
        ((((nvd.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text
    ELSE
        NULL::text
    END AS vector_string,
    (((((nvd.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric AS base_score_v40,
    (((((nvd.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric AS base_score_v31,
    (((((nvd.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric AS base_score_v30,
    (((((nvd.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric AS base_score_v2,
    ((((nvd.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text AS vector_string_v40,
    ((((nvd.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text AS vector_string_v31,
    ((((nvd.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text AS vector_string_v30,
    ((((nvd.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text AS vector_string_v2
FROM
    kernel_vulns k
    JOIN nvd_cve nvd USING (cve_id);

ALTER TABLE public.kernel_cve OWNER TO glvd;

CREATE OR REPLACE VIEW public.kernel_cvedetails AS
SELECT
    nvd_cve.cve_id AS cve_id,
    nvd_cve.data -> 'vulnStatus'::text AS vulnstatus,
    nvd_cve.data -> 'published'::text AS published,
    nvd_cve.data -> 'lastModified'::text AS modified,
    nvd_cve.last_mod AS ingested,
    array_agg(cve_context_kernel.lts_version) AS lts_version,
    array_agg(cve_context_kernel.fixed_version) AS fixed_version,
    array_agg(cve_context_kernel.is_fixed) AS is_fixed,
    array_agg(cve_context_kernel.is_relevant_subsystem) AS is_relevant_subsystem,
    ((nvd_cve.data -> 'descriptions'::text) -> 0) -> 'value'::text AS description,
    (((((nvd_cve.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric AS base_score_v40,
    (((((nvd_cve.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric AS base_score_v31,
    (((((nvd_cve.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric AS base_score_v30,
    (((((nvd_cve.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric AS base_score_v2,
    ((((nvd_cve.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text AS vector_string_v40,
    ((((nvd_cve.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text AS vector_string_v31,
    ((((nvd_cve.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text AS vector_string_v30,
    ((((nvd_cve.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text AS vector_string_v2
FROM
    nvd_cve
    JOIN cve_context_kernel USING (cve_id)
GROUP BY
    nvd_cve.cve_id;

ALTER TABLE public.kernel_cvedetails OWNER TO glvd;

SELECT
    log_migration (2);
