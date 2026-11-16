"""The schema fixture supplies migrations without replacing runtime models."""
from pathlib import Path

import controlplane_db
from controlplane_db import _share_lookup_hardening, migrations, models


def test_schema_helpers_are_test_only_and_models_remain_installed():
    fixture = Path(controlplane_db._acl_schema_fixture.name)
    assert Path(migrations.__file__).is_relative_to(fixture)
    assert Path(_share_lookup_hardening.__file__).is_relative_to(fixture)
    assert not Path(models.__file__).is_relative_to(fixture)
    assert callable(_share_lookup_hardening.apply)
