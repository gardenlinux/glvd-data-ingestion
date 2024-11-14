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
  WHERE dist_cpe.cpe_product = 'gardenlinux'::text;

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

-- View: public.cvedetails

-- DROP VIEW public.cvedetails;

CREATE OR REPLACE VIEW public.cvedetails
 AS
 SELECT all_cve.cve_id AS cve_id,
    all_cve.data -> 'vulnStatus'::text AS vulnstatus,
    all_cve.data -> 'published'::text AS published,
    array_agg(cve_context.description) AS cve_context_description,
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
     FULL JOIN cve_context USING (cve_id, dist_id)
  GROUP BY all_cve.cve_id;

ALTER TABLE public.cvedetails
    OWNER TO glvd;
