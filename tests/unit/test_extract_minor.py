import pytest
from glvd.util.minor import extract_minor

@pytest.mark.parametrize("version,expected", [
    ("1.2.3-4", "1.2"),
    ("1.2.3+deb10u1", "1.2"),
    ("1:1.37.0-5", "1.37"),
    ("2:4.15.0-112.113", "4.15"),
    ("1.2", "1.2"),
    ("1", "1"),
    ("1.2.3", "1.2"),
    ("1.2.3.4", "1.2"),
    ("1.2.3~beta1", "1.2"),
    ("1.2.3+dfsg-1", "1.2"),
    ("1.2.3-1gl1", "1.2"),
    ("1.2.3-1+b1", "1.2"),
    ("1:2.7.15-3+deb10u1", "2.7"),
    ("0:3.0-1", "3.0"),
    ("", None),
    (None, None),
    ("1:0", "0"),
    ("1.2~rc1-1", "1.2"),
    ("1.2.3.4.5-6", "1.2"),
    ("1.2.3-4+b5", "1.2"),
    ("1.2.3-4~exp1", "1.2"),
])
def test_extract_minor(version, expected):
    assert extract_minor(version) == expected
