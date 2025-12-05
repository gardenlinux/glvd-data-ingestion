SELECT
    assert_latest_migration (8);

-- new table to keep track of image variants
-- https://github.com/gardenlinux/glvd/issues/189
CREATE TABLE image_variant (
    id bigserial PRIMARY KEY,
    -- namespace is intended for future releases where third parties might add their own image variants to glvd
    -- similar to orgs/repos on github
    -- there is no process for registering namespaces yet, this needs to be safe against abuse
    namespace text NOT NULL DEFAULT 'gardenlinux',
    image_name text NOT NULL,
    image_version text NOT NULL,
    commit_id text,
    metadata jsonb DEFAULT '{}'
);

ALTER TABLE image_variant
    ADD CONSTRAINT image_variant_namespace_name_version_unique UNIQUE (namespace, image_name, image_version);

ALTER TABLE public.image_variant OWNER TO glvd;

CREATE TABLE image_package (
    image_variant_id bigint NOT NULL REFERENCES image_variant (id) ON DELETE CASCADE,
    package_name text NOT NULL,
    PRIMARY KEY (image_variant_id, package_name)
);

ALTER TABLE public.image_package OWNER TO glvd;

CREATE INDEX idx_image_package_package ON image_package (package_name);

CREATE INDEX idx_image_package_image ON image_package (image_variant_id);

ALTER TABLE image_variant
    ADD COLUMN packages text[] DEFAULT '{}'::text[];

CREATE INDEX idx_image_variant_packages_gin ON image_variant USING GIN (packages);

-- version of the sourcepackagecve view to filter by image variant
CREATE OR REPLACE VIEW public.imagesourcepackagecve AS SELECT DISTINCT
    all_cve.cve_id,
    deb_cve.deb_source AS source_package_name,
    deb_cve.deb_version AS source_package_version,
    dist_cpe.cpe_version AS gardenlinux_version,
    iv.namespace AS gardenlinux_image_namespace,
    iv.image_name AS gardenlinux_image_name,
    iv.image_version AS gardenlinux_image_version,
    iv.commit_id AS gardenlinux_image_commit_id,
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
    ((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text AS vector_string_v2,
    all_cve.data ->> 'vulnStatus'::text AS vuln_status
FROM
    all_cve
    JOIN deb_cve USING (cve_id)
    JOIN dist_cpe ON deb_cve.dist_id = dist_cpe.id
    FULL JOIN cve_context USING (cve_id, dist_id)
    JOIN public.image_package ip ON ip.package_name = deb_cve.deb_source
    JOIN public.image_variant iv ON iv.id = ip.image_variant_id
WHERE
    dist_cpe.cpe_product = 'gardenlinux'::text
    AND iv.namespace = 'gardenlinux'::text
    AND deb_cve.debsec_vulnerable = TRUE
    AND deb_cve.deb_source <> 'linux'::text
    AND dist_cpe.cpe_version = iv.image_version;

ALTER TABLE public.imagesourcepackagecve OWNER TO glvd;

-- View: public.sourcepackagecve_anyimage
-- DROP VIEW public.sourcepackagecve_anyimage;
CREATE OR REPLACE VIEW public.sourcepackagecve_anyimage AS SELECT DISTINCT
    cve_id,
    source_package_name,
    source_package_version,
    gardenlinux_version,
    is_vulnerable,
    debsec_vulnerable,
    is_resolved,
    cve_published_date,
    cve_last_modified_date,
    cve_last_ingested_date,
    base_score,
    vector_string,
    base_score_v40,
    base_score_v31,
    base_score_v30,
    base_score_v2,
    vector_string_v40,
    vector_string_v31,
    vector_string_v30,
    vector_string_v2,
    vuln_status
FROM
    imagesourcepackagecve;

ALTER TABLE public.sourcepackagecve_anyimage OWNER TO glvd;

SELECT
    log_migration (9);

