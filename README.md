# Garden Linux Vulnerability Database - Data Ingestion
This repository contains the workflow files to trigger a nightly pipeline for gathering data needed by the Garden Linux Security Tracker [glvd](https://github.com/gardenlinux/glvd) to process vulnerability requests from users.

Thereby, the Github Action processes the following steps to gather all information from external sources and to push them to the corresponding database of `glvd`:

| Step | Execution Environment | Description |
|------|-----------------------|-------------|
|`ingest-nvd`| EC2 Instance | This step ingest all data from NVD so that `glvd` don't need to request CVE information each time it requires it. |
|`ingest-debsec`| Github Action | This step reads the CVE list of each supported distribution into the database, so that `glvd` can decide if CVEs might be fixed already.|
|`ingest-debsrc`| Github Action | This step imports the information of all source packages of a supported distribution. |
|`combine-deb`| Github Action | To keep the processing simple, this step puts all required information together and stores them in the `dev_cve` table.|
|`combine-all`| Github Action | To keep the processing simple, this steps puts all required information together and stores them in the `all_cve` table.|

Those Github Action steps are executed by the following workflow: [data_ingestion.yml](./.github/workflows/data_ingestion.yml)

This workflow is triggered by the following events:
* Pushes to this repo
* Manually triggered via the WebUI
* Each night at 2:00am UTC.

The `ingest-nvd` step is the only step, that is not executed by this repository and its corresponding Github Action since this steps involves a lot of data from NVD which would exceed the general runtime of Github Actions. For this reason, this step is executed on the EC2 instance of `glvd` itself which speeds up this step by a huge margin. This is because the actual import then happens on localhost and it eliminates the need to send all gathered information from a Github Runner to the actual database over the internet which would slow down this step.

Currently, the following distributions are supported by this Security Tracker:
* Debian Buster
* Debian Bulleye
* Debian Bookworm
* Debian Trixie
* Garden Linux >= TBD