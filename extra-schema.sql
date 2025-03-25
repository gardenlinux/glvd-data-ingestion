-- Table: public.cve_context
-- NOTE: This is WIP
-- The purpose of this table is to add context information for CVEs.
-- A CVE with context information will not be visible in the default view.
-- Context information might be something like 'this does not apply in usage scenario xy'

CREATE TABLE public.cve_context (
    dist_id integer NOT NULL,
    cve_id text NOT NULL,
    create_date timestamp with time zone DEFAULT now() NOT NULL,
    context_descriptor text NOT NULL, -- i.e. what variant/environment/image-type does this apply to?
    score_override numeric,
    description text NOT NULL,
    is_resolved boolean DEFAULT TRUE
);

ALTER TABLE public.cve_context OWNER TO glvd;

ALTER TABLE ONLY public.cve_context
    ADD CONSTRAINT cve_context_pkey PRIMARY KEY (dist_id, cve_id, create_date, context_descriptor);

-- View: public.cve_with_context

-- DROP VIEW public.cve_with_context;

CREATE OR REPLACE VIEW public.cve_with_context
 AS
 SELECT cve_context.dist_id,
    cve_context.cve_id
   FROM cve_context
  GROUP BY cve_context.dist_id, cve_context.cve_id;

ALTER TABLE public.cve_with_context
    OWNER TO glvd;


-- Query to filter sourcepackagecve with context
-- select * from sourcepackagecve
-- left outer join cve_with_context using (cve_id)
-- where cve_with_context.cve_id is null;

-- View: public.sourcepackagecve

-- DROP VIEW public.sourcepackagecve;

CREATE OR REPLACE VIEW public.sourcepackagecve
 AS
 SELECT all_cve.cve_id,
    deb_cve.deb_source AS source_package_name,
    deb_cve.deb_version AS source_package_version,
    dist_cpe.cpe_version AS gardenlinux_version,
    (deb_cve.debsec_vulnerable AND cve_context.is_resolved IS NOT TRUE) = true AS is_vulnerable,
    deb_cve.debsec_vulnerable,
    cve_context.is_resolved,
    all_cve.data ->> 'published'::text AS cve_published_date,
    all_cve.data ->> 'lastModified'::text AS cve_last_modified_date,
    all_cve.last_mod AS cve_last_ingested_date,
        CASE
            WHEN ((((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric) IS NOT NULL THEN (((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric
            WHEN ((((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric) IS NOT NULL THEN (((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric
            WHEN ((((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric) IS NOT NULL THEN (((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric
            WHEN ((((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric) IS NOT NULL THEN (((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric
            ELSE NULL::numeric
        END AS base_score,
        CASE
            WHEN (((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text) IS NOT NULL THEN ((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text
            WHEN (((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text) IS NOT NULL THEN ((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text
            WHEN (((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text) IS NOT NULL THEN ((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text
            WHEN (((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text) IS NOT NULL THEN ((((all_cve.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text
            ELSE NULL::text
        END AS vector_string,
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
     FULL JOIN cve_context USING (cve_id, dist_id)
  WHERE dist_cpe.cpe_product = 'gardenlinux'::text AND deb_cve.debsec_vulnerable = true;

ALTER TABLE public.sourcepackagecve
    OWNER TO glvd;

-- View: public.recentsourcepackagecve

-- DROP VIEW public.recentsourcepackagecve;

CREATE OR REPLACE VIEW public.recentsourcepackagecve
 AS
 SELECT sourcepackagecve.cve_id,
    sourcepackagecve.source_package_name,
    sourcepackagecve.source_package_version,
    sourcepackagecve.gardenlinux_version,
    sourcepackagecve.is_vulnerable,
    sourcepackagecve.cve_published_date,
    sourcepackagecve.base_score,
    sourcepackagecve.vector_string,
    sourcepackagecve.base_score_v40,
    sourcepackagecve.base_score_v31,
    sourcepackagecve.base_score_v30,
    sourcepackagecve.base_score_v2,
    sourcepackagecve.vector_string_v40,
    sourcepackagecve.vector_string_v31,
    sourcepackagecve.vector_string_v30,
    sourcepackagecve.vector_string_v2
   FROM sourcepackagecve
  WHERE sourcepackagecve.cve_published_date::timestamp with time zone > (now() - '10 days'::interval);

ALTER TABLE public.recentsourcepackagecve
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

-- View: public.nvd_exclusive_cve

-- DROP VIEW public.nvd_exclusive_cve;

CREATE OR REPLACE VIEW public.nvd_exclusive_cve
 AS
 SELECT nvd_cve.cve_id, nvd_cve.data,
   FROM nvd_cve
     LEFT JOIN all_cve ON nvd_cve.cve_id = all_cve.cve_id
  WHERE all_cve.cve_id IS NULL
  ORDER BY nvd_cve.cve_id DESC
 LIMIT 500;

ALTER TABLE public.nvd_exclusive_cve
    OWNER TO glvd;

-- View: public.nvd_exclusive_cve_matching_gl

-- DROP VIEW public.nvd_exclusive_cve_matching_gl;

CREATE OR REPLACE VIEW public.nvd_exclusive_cve_matching_gl
 AS
 SELECT nvd_exclusive_cve.cve_id,
    ((nvd_exclusive_cve.data -> 'descriptions'::text) -> 0) -> 'value'::text AS description,
    nvd_exclusive_cve.data -> 'vulnStatus'::text AS vulnstatus,
    nvd_exclusive_cve.data -> 'published'::text AS published,
    nvd_exclusive_cve.data -> 'lastModified'::text AS modified
   FROM nvd_exclusive_cve
     JOIN ( SELECT debsrc.deb_source
           FROM debsrc
          WHERE debsrc.dist_id = 15) filtered_debsrc ON (EXISTS ( SELECT 1
           FROM jsonb_array_elements(nvd_exclusive_cve.data::jsonb -> 'descriptions'::text) description(value)
          WHERE (description.value ->> 'lang'::text) = 'en'::text AND (description.value ->> 'value'::text) ~~* (('%'::text || filtered_debsrc.deb_source) || '%'::text)));

ALTER TABLE public.nvd_exclusive_cve_matching_gl
    OWNER TO glvd;

-- View: public.kernel_vulns
-- Not to be directly exposed to the user, used as abstraction for kernel_cve

-- DROP VIEW public.kernel_vulns;

CREATE OR REPLACE VIEW public.kernel_vulns
 AS
 SELECT all_cve.cve_id,
    deb_cve.deb_source AS source_package_name,
    deb_cve.deb_version AS source_package_version,
    dist_cpe.cpe_version AS gardenlinux_version,
    ((deb_cve.deb_version < cve_context_kernel.fixed_version::debversion OR cve_context_kernel.fixed_version IS NULL) AND cve_context_kernel.is_relevant_subsystem IS TRUE AND cve_context.is_resolved IS NOT TRUE) = true AS is_vulnerable,
    cve_context_kernel.is_relevant_subsystem,
    cve_context_kernel.lts_version,
    cve_context_kernel.fixed_version::debversion AS fixed_version,
    cve_context_kernel.is_fixed
   FROM all_cve
     JOIN deb_cve USING (cve_id)
     JOIN dist_cpe ON deb_cve.dist_id = dist_cpe.id
     FULL JOIN cve_context USING (cve_id, dist_id)
     JOIN cve_context_kernel cve_context_kernel(cve_id_1, lts_version, fixed_version, is_fixed, is_relevant_subsystem, source_data) ON all_cve.cve_id = cve_context_kernel.cve_id_1 AND cve_context_kernel.lts_version = concat(split_part(deb_cve.deb_version::text, '.'::text, 1), '.', split_part(deb_cve.deb_version::text, '.'::text, 2))
  WHERE dist_cpe.cpe_product = 'gardenlinux'::text AND ((deb_cve.deb_version < cve_context_kernel.fixed_version::debversion OR cve_context_kernel.fixed_version IS NULL) AND cve_context_kernel.is_relevant_subsystem IS TRUE AND cve_context.is_resolved IS NOT TRUE) = true AND deb_cve.deb_source = 'linux'::text;

ALTER TABLE public.kernel_vulns
    OWNER TO glvd;

-- View: public.kernel_cve
-- Kernel-specific counterpart for sourcepackagecve

-- DROP VIEW public.kernel_cve;

CREATE OR REPLACE VIEW public.kernel_cve
 AS
 SELECT k.cve_id,
    k.source_package_name,
    k.source_package_version,
    k.gardenlinux_version,
    k.is_vulnerable,
    k.fixed_version,
    nvd.data ->> 'published'::text AS cve_published_date,
    nvd.data ->> 'lastModified'::text AS cve_last_modified_date,
    nvd.last_mod AS cve_last_ingested_date,
        CASE
            WHEN ((((((nvd.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric) IS NOT NULL THEN (((((nvd.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric
            WHEN ((((((nvd.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric) IS NOT NULL THEN (((((nvd.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric
            WHEN ((((((nvd.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric) IS NOT NULL THEN (((((nvd.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric
            WHEN ((((((nvd.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric) IS NOT NULL THEN (((((nvd.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric
            ELSE NULL::numeric
        END AS base_score,
        CASE
            WHEN (((((nvd.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text) IS NOT NULL THEN ((((nvd.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text
            WHEN (((((nvd.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text) IS NOT NULL THEN ((((nvd.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text
            WHEN (((((nvd.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text) IS NOT NULL THEN ((((nvd.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text
            WHEN (((((nvd.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text) IS NOT NULL THEN ((((nvd.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text
            ELSE NULL::text
        END AS vector_string,
    (((((nvd.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric AS base_score_v40,
    (((((nvd.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric AS base_score_v31,
    (((((nvd.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric AS base_score_v30,
    (((((nvd.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text)::numeric AS base_score_v2,
    ((((nvd.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text AS vector_string_v40,
    ((((nvd.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text AS vector_string_v31,
    ((((nvd.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text AS vector_string_v30,
    ((((nvd.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text AS vector_string_v2
   FROM kernel_vulns k
     JOIN nvd_cve nvd USING (cve_id);

ALTER TABLE public.kernel_cve
    OWNER TO glvd;


CREATE OR REPLACE VIEW public.combined_cve AS
SELECT
    COALESCE(kc.cve_id, spc.cve_id) AS cve_id,
    COALESCE(kc.source_package_name, spc.source_package_name) AS source_package_name,
    COALESCE(kc.source_package_version, spc.source_package_version) AS source_package_version,
    COALESCE(kc.gardenlinux_version, spc.gardenlinux_version) AS gardenlinux_version,
    COALESCE(kc.is_vulnerable, spc.is_vulnerable) AS is_vulnerable,
    COALESCE(kc.cve_published_date, spc.cve_published_date) AS cve_published_date,
    COALESCE(kc.cve_last_modified_date, spc.cve_last_modified_date) AS cve_last_modified_date,
    COALESCE(kc.cve_last_ingested_date, spc.cve_last_ingested_date) AS cve_last_ingested_date,
    COALESCE(kc.base_score, spc.base_score) AS base_score,
    COALESCE(kc.vector_string, spc.vector_string) AS vector_string,
    COALESCE(kc.base_score_v40, spc.base_score_v40) AS base_score_v40,
    COALESCE(kc.base_score_v31, spc.base_score_v31) AS base_score_v31,
    COALESCE(kc.base_score_v30, spc.base_score_v30) AS base_score_v30,
    COALESCE(kc.base_score_v2, spc.base_score_v2) AS base_score_v2,
    COALESCE(kc.vector_string_v40, spc.vector_string_v40) AS vector_string_v40,
    COALESCE(kc.vector_string_v31, spc.vector_string_v31) AS vector_string_v31,
    COALESCE(kc.vector_string_v30, spc.vector_string_v30) AS vector_string_v30,
    COALESCE(kc.vector_string_v2, spc.vector_string_v2) AS vector_string_v2
FROM
    public.kernel_cve kc
FULL JOIN
    public.sourcepackagecve spc
ON
    kc.cve_id = spc.cve_id;
