import pytest
from unittest.mock import MagicMock
from src.modules.sqli import SQLInjection
from src.modules.xss import XSS
from src.modules.html_inj import HTMLInjection
from src.modules.cmd_inj import CommandInjection
from src.modules.ldap import LDAPInjection


def test_modules_no_name_error():
    # Mock requester response
    mock_response = MagicMock()
    mock_response.text = "test response syntax error XSS CMD_INJ_TEST"
    mock_response.elapsed.total_seconds.return_value = 0.1

    mock_requester = MagicMock()
    mock_requester.get.return_value = mock_response
    mock_requester.post.return_value = mock_response

    # Dummy form structure
    dummy_form = {
        "action": "http://example.com/vuln",
        "method": "post",
        "inputs": [
            {"name": "username", "value": "admin", "type": "text"},
            {"name": "password", "value": "secret", "type": "password"},
            {"name": "submit", "value": "Submit", "type": "submit"}
        ]
    }

    # Instantiate modules
    sqli = SQLInjection(mock_requester)
    xss = XSS(mock_requester)
    html_inj = HTMLInjection(mock_requester)
    cmd_inj = CommandInjection(mock_requester)
    ldap = LDAPInjection(mock_requester)

    # Run scan on dummy form and verify they don't raise exceptions (especially NameError)
    sqli_results = sqli.scan(dummy_form)
    assert isinstance(sqli_results, list)

    xss_results = xss.scan(dummy_form)
    assert isinstance(xss_results, list)

    html_results = html_inj.scan(dummy_form)
    assert isinstance(html_results, list)

    cmd_results = cmd_inj.scan(dummy_form)
    assert isinstance(cmd_results, list)

    ldap_results = ldap.scan(dummy_form)
    assert isinstance(ldap_results, list)
