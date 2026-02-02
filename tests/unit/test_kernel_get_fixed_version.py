import pytest

from glvd.cli.data.ingest_kernel import get_fixed_versions

@pytest.mark.parametrize(
    "lts_versions, cve_data, expected",
    [
        (
            ["6.6", "6.12", "6.18"],
            {
                "containers": {
                    "cna": {
                        "defaultStatus": "affected",
                        "affected": [
                            {
                                "versions": [
                                    {"version": "6.8", "status": "affected"},
                                    {
                                        "version": "0",
                                        "lessThan": "6.8",
                                        "status": "unaffected",
                                        "versionType": "semver",
                                    },
                                    {
                                        "version": "6.11.4",
                                        "lessThanOrEqual": "6.11.*",
                                        "status": "unaffected",
                                        "versionType": "semver",
                                    },
                                    {
                                        "version": "6.12",
                                        "lessThanOrEqual": "*",
                                        "status": "unaffected",
                                        "versionType": "original_commit_for_fix",
                                    },
                                ]
                            }
                        ]
                    }
                }
            },
            {
                "6.6": "6.6",    # unaffected (lessThan 6.8)
                "6.12": "6.12",  # unaffected (direct match)
                "6.18": "6.18",  # unaffected (lessThanOrEqual: *)
            },
        ),
    ],
)
def test_get_fixed_versions(lts_versions, cve_data, expected):
    result = get_fixed_versions(lts_versions, cve_data)
    assert result == expected
