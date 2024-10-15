-- View: public.sourcepackagecve

-- DROP VIEW public.sourcepackagecve;

CREATE OR REPLACE VIEW public.sourcepackagecve
 AS
 SELECT all_cve.cve_id AS cve_id,
    deb_cve.deb_source AS source_package_name,
    deb_cve.deb_version AS source_package_version,
    dist_cpe.cpe_version AS gardenlinux_version,
    deb_cve.debsec_vulnerable AS is_vulnerable,
    all_cve.data ->> 'published'::text AS cve_published_date,
    CASE
     WHEN (data->'metrics'->'cvssMetricV31'->0->'cvssData'->>'baseScore')::numeric IS NOT NULL THEN
    (data->'metrics'->'cvssMetricV31'->0->'cvssData'->>'baseScore')::numeric
     WHEN (data->'metrics'->'cvssMetricV30'->0->'cvssData'->>'baseScore')::numeric IS NOT NULL THEN
    (data->'metrics'->'cvssMetricV30'->0->'cvssData'->>'baseScore')::numeric
     WHEN (data->'metrics'->'cvssMetricV2'->0->'cvssData'->>'baseScore')::numeric IS NOT NULL THEN
    (data->'metrics'->'cvssMetricV2'->0->'cvssData'->>'baseScore')::numeric
     WHEN (data->'metrics'->'cvssMetricV40'->0->'cvssData'->>'baseScore')::numeric IS NOT NULL THEN
    (data->'metrics'->'cvssMetricV40'->0->'cvssData'->>'baseScore')::numeric
    END AS base_score,
    CASE
     WHEN (data->'metrics'->'cvssMetricV31'->0->'cvssData'->>'vectorString')::text IS NOT NULL THEN
    (data->'metrics'->'cvssMetricV31'->0->'cvssData'->>'vectorString')::text
     WHEN (data->'metrics'->'cvssMetricV30'->0->'cvssData'->>'vectorString')::text IS NOT NULL THEN
    (data->'metrics'->'cvssMetricV30'->0->'cvssData'->>'vectorString')::text
     WHEN (data->'metrics'->'cvssMetricV2'->0->'cvssData'->>'vectorString')::text IS NOT NULL THEN
    (data->'metrics'->'cvssMetricV2'->0->'cvssData'->>'vectorString')::text
     WHEN (data->'metrics'->'cvssMetricV40'->0->'cvssData'->>'vectorString')::text IS NOT NULL THEN
    (data->'metrics'->'cvssMetricV40'->0->'cvssData'->>'vectorString')::text
    END AS vector_string,
    (data->'metrics'->'cvssMetricV40'->0->'cvssData'->>'baseScore')::numeric AS base_score_v40,
    (data->'metrics'->'cvssMetricV31'->0->'cvssData'->>'baseScore')::numeric AS base_score_v31,
    (data->'metrics'->'cvssMetricV30'->0->'cvssData'->>'baseScore')::numeric AS base_score_v30,
    (data->'metrics'->'cvssMetricV2'->0->'cvssData'->>'baseScore')::numeric AS base_score_v2,
    (data->'metrics'->'cvssMetricV40'->0->'cvssData'->>'vectorString')::text AS vector_string_v40,
    (data->'metrics'->'cvssMetricV31'->0->'cvssData'->>'vectorString')::text AS vector_string_v31,
    (data->'metrics'->'cvssMetricV30'->0->'cvssData'->>'vectorString')::text AS vector_string_v30,
    (data->'metrics'->'cvssMetricV2'->0->'cvssData'->>'vectorString')::text AS vector_string_v2
   FROM all_cve
     JOIN deb_cve USING (cve_id)
     JOIN dist_cpe ON deb_cve.dist_id = dist_cpe.id
  WHERE
    dist_cpe.cpe_product = 'gardenlinux'::text AND
    deb_cve.debsec_vulnerable = TRUE;

ALTER TABLE public.sourcepackagecve
    OWNER TO glvd;

-- View: public.sourcepackage

-- DROP VIEW public.sourcepackage;

CREATE OR REPLACE VIEW public.sourcepackage
 AS
 SELECT debsrc.deb_source AS source_package_name,
    debsrc.deb_version AS source_package_version,
    dist_cpe.cpe_version AS gardenlinux_version
   FROM debsrc
     JOIN dist_cpe ON debsrc.dist_id = dist_cpe.id
  WHERE dist_cpe.cpe_product = 'gardenlinux'::text;

ALTER TABLE public.sourcepackage
    OWNER TO glvd;

-- View: public.cvedetails

-- DROP VIEW public.cvedetails;

CREATE OR REPLACE VIEW public.cvedetails
 AS
 SELECT all_cve.cve_id AS cve_id,
    all_cve.data -> 'vulnStatus'::text AS vulnstatus,
    all_cve.data -> 'published'::text AS published,
    array_agg(dist_cpe.cpe_product) AS distro,
    array_agg(dist_cpe.cpe_version) AS distro_version,
    array_agg(deb_cve.debsec_vulnerable) AS is_vulnerable,
    array_agg(deb_cve.deb_source) AS source_package_name,
    array_agg(deb_cve.deb_version::text) AS source_package_version,
    ((all_cve.data -> 'descriptions'::text) -> 0) -> 'value'::text AS description,
    (((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric AS base_score_v40,
    (((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric AS base_score_v31,
    (((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric AS base_score_v30,
    (((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric AS base_score_v2,
    ((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text AS vector_string_v40,
    ((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text AS vector_string_v31,
    ((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text AS vector_string_v30,
    ((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text AS vector_string_v2
   FROM all_cve
     JOIN deb_cve USING (cve_id)
     JOIN dist_cpe ON deb_cve.dist_id = dist_cpe.id
  GROUP BY all_cve.cve_id;

ALTER TABLE public.cvedetails
    OWNER TO glvd;
