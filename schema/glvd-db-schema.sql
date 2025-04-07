CREATE TABLE public.all_cve (
    cve_id text NOT NULL,
    last_mod timestamp with time zone DEFAULT now() NOT NULL,
    data json NOT NULL
);
ALTER TABLE public.all_cve OWNER TO glvd;

CREATE TABLE public.nvd_cve (
    cve_id text NOT NULL,
    last_mod timestamp with time zone NOT NULL,
    data json NOT NULL
);
ALTER TABLE public.nvd_cve OWNER TO glvd;

CREATE TABLE public.cve_context (
    dist_id integer,
    gardenlinux_version text,
    cve_id text NOT NULL,
    create_date timestamp with time zone DEFAULT now() NOT NULL,
    context_descriptor text NOT NULL,
    score_override numeric,
    description text NOT NULL,
    is_resolved boolean DEFAULT true
);
ALTER TABLE public.cve_context OWNER TO glvd;
ALTER TABLE ONLY public.cve_context
    ADD CONSTRAINT cve_context_pkey PRIMARY KEY (dist_id, cve_id, create_date, context_descriptor);

CREATE TABLE public.cve_context_kernel (
    cve_id text NOT NULL,
    lts_version text NOT NULL,
    fixed_version text,
    is_fixed boolean NOT NULL,
    is_relevant_module boolean NOT NULL,
    source_data jsonb NOT NULL
);
ALTER TABLE public.cve_context_kernel OWNER TO glvd;

CREATE TABLE public.deb_cve (
    dist_id integer,
    gardenlinux_version text,
    cve_id text NOT NULL,
    last_mod timestamp with time zone DEFAULT now() NOT NULL,
    cvss_severity integer,
    deb_source text NOT NULL,
    deb_version public.debversion NOT NULL,
    deb_version_fixed public.debversion,
    debsec_vulnerable boolean NOT NULL,
    data_cpe_match json NOT NULL
);
ALTER TABLE public.deb_cve OWNER TO glvd;

CREATE TABLE public.debsec_cve (
    dist_id integer,
    gardenlinux_version text,
    cve_id text NOT NULL,
    last_mod timestamp with time zone DEFAULT now() NOT NULL,
    deb_source text NOT NULL,
    deb_version_fixed public.debversion,
    debsec_tag text,
    debsec_note text
);
ALTER TABLE public.debsec_cve OWNER TO glvd;

CREATE TABLE public.debsrc (
    dist_id integer,
    gardenlinux_version text,
    last_mod timestamp with time zone DEFAULT now() NOT NULL,
    deb_source text NOT NULL,
    deb_version public.debversion NOT NULL
);
ALTER TABLE public.debsrc OWNER TO glvd;

CREATE TABLE public.dist_cpe (
    id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    cpe_vendor text NOT NULL,
    cpe_product text NOT NULL,
    cpe_version text NOT NULL,
    deb_codename text NOT NULL
);
ALTER TABLE public.dist_cpe OWNER TO glvd;

CREATE OR REPLACE VIEW public.cve_with_context
 AS
 SELECT cve_context.dist_id,
    cve_context.cve_id
   FROM cve_context
  GROUP BY cve_context.dist_id, cve_context.cve_id;
ALTER TABLE public.cve_with_context
    OWNER TO glvd;

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

-- fixme fwilhe
-- CREATE OR REPLACE VIEW public.cvedetails AS
--  SELECT nvd_cve.cve_id,
--     (nvd_cve.data -> 'vulnStatus'::text) AS vulnstatus,
--     (nvd_cve.data -> 'published'::text) AS published,
--     (nvd_cve.data -> 'lastModified'::text) AS modified,
--     nvd_cve.last_mod AS ingested,
--     array_agg(cve_context.description) AS cve_context_description,
--     array_agg(dist_cpe.cpe_product) AS distro,
--     array_agg(dist_cpe.cpe_version) AS distro_version,
--     array_agg(deb_cve.debsec_vulnerable) AS is_vulnerable,
--     array_agg(deb_cve.deb_source) AS source_package_name,
--     array_agg((deb_cve.deb_version)::text) AS source_package_version,
--     array_agg((deb_cve.deb_version_fixed)::text) AS version_fixed,
--     (((nvd_cve.data -> 'descriptions'::text) -> 0) -> 'value'::text) AS description,
--     ((((((nvd_cve.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text))::numeric AS base_score_v40,
--     ((((((nvd_cve.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text))::numeric AS base_score_v31,
--     ((((((nvd_cve.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text))::numeric AS base_score_v30,
--     ((((((nvd_cve.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'baseScore'::text))::numeric AS base_score_v2,
--     (((((nvd_cve.data -> 'metrics'::text) -> 'cvssMetricV40'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text) AS vector_string_v40,
--     (((((nvd_cve.data -> 'metrics'::text) -> 'cvssMetricV31'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text) AS vector_string_v31,
--     (((((nvd_cve.data -> 'metrics'::text) -> 'cvssMetricV30'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text) AS vector_string_v30,
--     (((((nvd_cve.data -> 'metrics'::text) -> 'cvssMetricV2'::text) -> 0) -> 'cvssData'::text) ->> 'vectorString'::text) AS vector_string_v2
--    FROM (((public.nvd_cve
--      JOIN public.deb_cve USING (cve_id))
--      JOIN public.dist_cpe ON ((deb_cve.dist_id = dist_cpe.id)))
--      FULL JOIN public.cve_context USING (cve_id, dist_id))
--   GROUP BY nvd_cve.cve_id;
-- ALTER TABLE public.cvedetails
--     OWNER TO glvd;

-- CREATE OR REPLACE VIEW public.nvd_exclusive_cve
--  AS
--  SELECT nvd_cve.cve_id, nvd_cve.data,
--    FROM nvd_cve
--      LEFT JOIN all_cve ON nvd_cve.cve_id = all_cve.cve_id
--   WHERE all_cve.cve_id IS NULL
--   ORDER BY nvd_cve.cve_id DESC
--  LIMIT 500;
-- ALTER TABLE public.nvd_exclusive_cve
--     OWNER TO glvd;

-- CREATE OR REPLACE VIEW public.nvd_exclusive_cve_matching_gl
--  AS
--  SELECT nvd_exclusive_cve.cve_id,
--     ((nvd_exclusive_cve.data -> 'descriptions'::text) -> 0) -> 'value'::text AS description,
--     nvd_exclusive_cve.data -> 'vulnStatus'::text AS vulnstatus,
--     nvd_exclusive_cve.data -> 'published'::text AS published,
--     nvd_exclusive_cve.data -> 'lastModified'::text AS modified
--    FROM nvd_exclusive_cve
--      JOIN ( SELECT debsrc.deb_source
--            FROM debsrc
--           WHERE debsrc.dist_id = 15) filtered_debsrc ON (EXISTS ( SELECT 1
--            FROM jsonb_array_elements(nvd_exclusive_cve.data::jsonb -> 'descriptions'::text) description(value)
--           WHERE (description.value ->> 'lang'::text) = 'en'::text AND (description.value ->> 'value'::text) ~~* (('%'::text || filtered_debsrc.deb_source) || '%'::text)));
-- ALTER TABLE public.nvd_exclusive_cve_matching_gl
--     OWNER TO glvd;

