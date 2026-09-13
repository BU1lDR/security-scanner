import dataclasses

import pytest

from scanner.core.location import Location, LocationKind


def test_for_url_builds_a_url_location():
    loc = Location.for_url("https://example.com/search", method="GET", param="q")
    assert loc.kind is LocationKind.URL
    assert loc.url == "https://example.com/search"
    assert loc.method == "GET"
    assert loc.param == "q"


def test_for_file_builds_a_file_location():
    loc = Location.for_file("src/app.py", line=42, column=5)
    assert loc.kind is LocationKind.FILE
    assert loc.path == "src/app.py"
    assert loc.line == 42
    assert loc.column == 5


def test_for_dependency_builds_a_dependency_location():
    loc = Location.for_dependency("PyPI", "requests", version="2.19.0", path="requirements.txt", line=3)
    assert loc.kind is LocationKind.DEPENDENCY
    assert loc.ecosystem == "PyPI"
    assert loc.package == "requests"
    assert loc.version == "2.19.0"
    assert loc.path == "requirements.txt"
    assert loc.line == 3


def test_location_is_immutable():
    loc = Location.for_file("src/app.py", line=1)
    with pytest.raises(dataclasses.FrozenInstanceError):
        loc.line = 2


def test_str_of_url_location_shows_url_and_param():
    text = str(Location.for_url("https://example.com/search", method="GET", param="q"))
    assert "https://example.com/search" in text
    assert "q" in text


def test_str_of_file_location_shows_path_and_line():
    assert str(Location.for_file("src/app.py", line=42)) == "src/app.py:42"


def test_str_of_dependency_location_shows_package_and_version():
    text = str(Location.for_dependency("PyPI", "requests", version="2.19.0"))
    assert "requests" in text
    assert "2.19.0" in text


def test_str_of_file_location_shows_column_even_without_a_line():
    # A column must not be silently dropped when line is absent.
    assert str(Location.for_file("src/app.py", column=5)) == "src/app.py::5"


def test_str_of_dependency_location_shows_its_manifest_path_and_line():
    text = str(
        Location.for_dependency("PyPI", "requests", version="2.0", path="requirements.txt", line=3)
    )
    assert "requests" in text
    assert "requirements.txt:3" in text
