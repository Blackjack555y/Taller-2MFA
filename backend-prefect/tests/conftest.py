"""Los tests no dependen del .env: SQLite temporal y un Prefect efímero."""
import os

# load_dotenv no sobreescribe variables ya definidas, así que esto gana al .env
os.environ["SUPABASE_URL"] = ""
os.environ["SUPABASE_SERVICE_KEY"] = ""

import pytest
from prefect.testing.utilities import prefect_test_harness


@pytest.fixture(autouse=True, scope="session")
def prefect_ephemeral():
    with prefect_test_harness():
        yield
