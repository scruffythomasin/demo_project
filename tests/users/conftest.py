from unittest.mock import patch

import pytest


@pytest.fixture
def mock_send_mail():
    with patch("myapp.services.send_mail") as send_mail_mock:
        yield send_mail_mock
