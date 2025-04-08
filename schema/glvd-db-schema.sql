CREATE TABLE public.all_cve (
    cve_id text NOT NULL,
    last_mod timestamp with time zone DEFAULT now() NOT NULL,
    data json NOT NULL
);
ALTER TABLE public.all_cve OWNER TO glvd;
ALTER TABLE ONLY public.all_cve
    ADD CONSTRAINT all_cve_pkey PRIMARY KEY (cve_id);

CREATE TABLE public.nvd_cve (
    cve_id text NOT NULL,
    last_mod timestamp with time zone NOT NULL,
    data json NOT NULL
);
ALTER TABLE public.nvd_cve OWNER TO glvd;
ALTER TABLE ONLY public.nvd_cve
    ADD CONSTRAINT nvd_cve_pkey PRIMARY KEY (cve_id);

CREATE TABLE public.cve_context (
    dist_id integer NOT NULL,
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
ALTER TABLE ONLY public.cve_context_kernel
    ADD CONSTRAINT cve_context_kernel_pkey PRIMARY KEY (cve_id, lts_version);

CREATE TABLE public.deb_cve (
    dist_id integer NOT NULL,
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
ALTER TABLE ONLY public.deb_cve
    ADD CONSTRAINT deb_cve_pkey PRIMARY KEY (dist_id, cve_id, deb_source);
CREATE INDEX deb_cve_search ON public.deb_cve USING btree (dist_id, debsec_vulnerable, deb_source, deb_version);

CREATE TABLE public.debsec_cve (
    dist_id integer NOT NULL,
    gardenlinux_version text,
    cve_id text NOT NULL,
    last_mod timestamp with time zone DEFAULT now() NOT NULL,
    deb_source text NOT NULL,
    deb_version_fixed public.debversion,
    debsec_tag text,
    debsec_note text
);
ALTER TABLE public.debsec_cve OWNER TO glvd;
ALTER TABLE ONLY public.debsec_cve
    ADD CONSTRAINT debsec_cve_pkey PRIMARY KEY (dist_id, cve_id, deb_source);

CREATE TABLE public.debsrc (
    dist_id integer NOT NULL,
    gardenlinux_version text,
    last_mod timestamp with time zone DEFAULT now() NOT NULL,
    deb_source text NOT NULL,
    deb_version public.debversion NOT NULL
);
ALTER TABLE public.debsrc OWNER TO glvd;
ALTER TABLE ONLY public.debsrc
    ADD CONSTRAINT debsrc_pkey PRIMARY KEY (dist_id, deb_source);

CREATE TABLE public.dist_cpe (
    id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    cpe_vendor text NOT NULL,
    cpe_product text NOT NULL,
    cpe_version text NOT NULL,
    deb_codename text NOT NULL
);
ALTER TABLE public.dist_cpe OWNER TO glvd;
