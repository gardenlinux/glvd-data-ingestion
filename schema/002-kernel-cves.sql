SELECT
    assert_latest_migration (1);

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

SELECT
    log_migration (2);

