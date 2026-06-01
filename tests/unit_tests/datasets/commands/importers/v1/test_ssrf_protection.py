# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Tests for SSRF protection in validate_data_uri."""

from unittest.mock import patch

import pytest
from flask import current_app

from superset.commands.dataset.exceptions import DatasetForbiddenDataURI
from superset.commands.dataset.importers.v1.utils import (
    _is_private_address,
    validate_data_uri,
)


@pytest.mark.parametrize(
    "data_uri",
    [
        "file:///etc/passwd",
        "file:///proc/self/environ",
        "ftp://evil.com/data.csv",
        "gopher://evil.com/_test",
        "dict://evil.com/info",
    ],
)
def test_validate_data_uri_blocks_dangerous_schemes(app_context: None, data_uri: str):
    """Schemes other than http/https are rejected regardless of allowlist."""
    current_app.config["DATASET_IMPORT_ALLOWED_DATA_URLS"] = [r".*"]
    with pytest.raises(DatasetForbiddenDataURI):
        validate_data_uri(data_uri)


@pytest.mark.parametrize(
    "data_uri",
    [
        "http://127.0.0.1/secret",
        "http://localhost/data.csv",
        "http://10.0.0.1:8080/admin",
        "http://172.16.0.1/internal",
        "http://192.168.1.1/config",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/data",
    ],
)
def test_validate_data_uri_blocks_private_ips(app_context: None, data_uri: str):
    """Private, loopback, and link-local addresses are rejected."""
    current_app.config["DATASET_IMPORT_ALLOWED_DATA_URLS"] = [r".*"]
    with patch(
        "superset.commands.dataset.importers.v1.utils.socket.getaddrinfo"
    ) as mock_getaddrinfo:
        # Simulate DNS resolution to the private IP from the URL
        from urllib.parse import urlparse

        parsed = urlparse(data_uri)
        hostname = parsed.hostname or ""
        # Map hostnames to their expected resolved IPs
        ip_map = {
            "127.0.0.1": "127.0.0.1",
            "localhost": "127.0.0.1",
            "10.0.0.1": "10.0.0.1",
            "172.16.0.1": "172.16.0.1",
            "192.168.1.1": "192.168.1.1",
            "169.254.169.254": "169.254.169.254",
            "::1": "::1",
        }
        resolved_ip = ip_map.get(hostname, "127.0.0.1")
        import socket

        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", (resolved_ip, 0))
        ]
        if resolved_ip == "::1":
            mock_getaddrinfo.return_value = [
                (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::1", 0, 0, 0))
            ]

        with pytest.raises(DatasetForbiddenDataURI):
            validate_data_uri(data_uri)


def test_validate_data_uri_empty_allowlist_blocks_all(app_context: None):
    """Default empty allowlist rejects all URLs."""
    current_app.config["DATASET_IMPORT_ALLOWED_DATA_URLS"] = []
    with patch(
        "superset.commands.dataset.importers.v1.utils.socket.getaddrinfo"
    ) as mock_getaddrinfo:
        import socket

        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 0))
        ]
        with pytest.raises(DatasetForbiddenDataURI):
            validate_data_uri("https://example.com/data.csv")


def test_validate_data_uri_allows_configured_public_url(app_context: None):
    """A properly configured allowlist permits matching public URLs."""
    current_app.config["DATASET_IMPORT_ALLOWED_DATA_URLS"] = [
        r"^https://data\.example\.com/.*"
    ]
    with patch(
        "superset.commands.dataset.importers.v1.utils.socket.getaddrinfo"
    ) as mock_getaddrinfo:
        import socket

        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.4.4", 0))
        ]
        # Should not raise
        validate_data_uri("https://data.example.com/datasets/test.csv")


def test_validate_data_uri_rejects_non_matching_public_url(app_context: None):
    """A URL not matching the allowlist is rejected even if it's public."""
    current_app.config["DATASET_IMPORT_ALLOWED_DATA_URLS"] = [
        r"^https://data\.example\.com/.*"
    ]
    with patch(
        "superset.commands.dataset.importers.v1.utils.socket.getaddrinfo"
    ) as mock_getaddrinfo:
        import socket

        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 0))
        ]
        with pytest.raises(DatasetForbiddenDataURI):
            validate_data_uri("https://evil.com/data.csv")


@pytest.mark.parametrize(
    "hostname,expected",
    [
        ("127.0.0.1", True),
        ("10.0.0.1", True),
        ("172.16.5.5", True),
        ("192.168.0.1", True),
        ("169.254.169.254", True),
    ],
)
def test_is_private_address(hostname: str, expected: bool):
    """_is_private_address correctly identifies private IPs."""
    with patch(
        "superset.commands.dataset.importers.v1.utils.socket.getaddrinfo"
    ) as mock_getaddrinfo:
        import socket

        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", (hostname, 0))
        ]
        assert _is_private_address(hostname) == expected


def test_is_private_address_dns_failure():
    """DNS resolution failure is treated as private (fail-closed)."""
    with patch(
        "superset.commands.dataset.importers.v1.utils.socket.getaddrinfo"
    ) as mock_getaddrinfo:
        import socket

        mock_getaddrinfo.side_effect = socket.gaierror("Name resolution failed")
        assert _is_private_address("nonexistent.invalid") is True
