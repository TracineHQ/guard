# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Unit tests for _check_sensitive_env_prefix helper."""

from __future__ import annotations

from guard.hooks._admin_specs import (
    _AWS_SENSITIVE_ENV_VARS,
    _AZ_SENSITIVE_ENV_VARS,
    _GCLOUD_SENSITIVE_ENV_VARS,
)
from guard.hooks.bash_command_validator import _check_sensitive_env_prefix


class TestAwsSensitiveEnvVars:
    def test_aws_endpoint_url(self) -> None:
        assert (
            _check_sensitive_env_prefix(
                "AWS_ENDPOINT_URL=http://evil aws sts get-caller-identity", _AWS_SENSITIVE_ENV_VARS
            )
            == "AWS_ENDPOINT_URL"
        )

    def test_aws_endpoint_url_prefix_match(self) -> None:
        # AWS_ENDPOINT_URL_* matches service-specific overrides
        assert (
            _check_sensitive_env_prefix(
                "AWS_ENDPOINT_URL_S3=http://evil aws s3 ls", _AWS_SENSITIVE_ENV_VARS
            )
            == "AWS_ENDPOINT_URL_S3"
        )

    def test_aws_endpoint_url_prefix_sts(self) -> None:
        assert (
            _check_sensitive_env_prefix(
                "AWS_ENDPOINT_URL_STS=http://evil aws sts get-caller-identity",
                _AWS_SENSITIVE_ENV_VARS,
            )
            == "AWS_ENDPOINT_URL_STS"
        )

    def test_aws_ca_bundle(self) -> None:
        assert (
            _check_sensitive_env_prefix(
                "AWS_CA_BUNDLE=/evil/ca.crt aws s3 ls", _AWS_SENSITIVE_ENV_VARS
            )
            == "AWS_CA_BUNDLE"
        )

    def test_https_proxy(self) -> None:
        assert (
            _check_sensitive_env_prefix(
                "HTTPS_PROXY=http://proxy:8080 aws ec2 describe-instances", _AWS_SENSITIVE_ENV_VARS
            )
            == "HTTPS_PROXY"
        )

    def test_http_proxy(self) -> None:
        assert (
            _check_sensitive_env_prefix(
                "HTTP_PROXY=http://proxy:8080 aws ec2 describe-instances", _AWS_SENSITIVE_ENV_VARS
            )
            == "HTTP_PROXY"
        )

    def test_aws_shared_credentials_file(self) -> None:
        assert (
            _check_sensitive_env_prefix(
                "AWS_SHARED_CREDENTIALS_FILE=/evil/creds aws iam list-users",
                _AWS_SENSITIVE_ENV_VARS,
            )
            == "AWS_SHARED_CREDENTIALS_FILE"
        )

    def test_aws_config_file(self) -> None:
        assert (
            _check_sensitive_env_prefix(
                "AWS_CONFIG_FILE=/evil/config aws ec2 describe-instances", _AWS_SENSITIVE_ENV_VARS
            )
            == "AWS_CONFIG_FILE"
        )

    def test_aws_profile(self) -> None:
        assert (
            _check_sensitive_env_prefix(
                "AWS_PROFILE=attacker aws iam list-users", _AWS_SENSITIVE_ENV_VARS
            )
            == "AWS_PROFILE"
        )

    def test_multiple_assignments_first_match(self) -> None:
        # First sensitive var wins
        result = _check_sensitive_env_prefix(
            "AWS_ENDPOINT_URL=evil AWS_CA_BUNDLE=/x aws s3 ls", _AWS_SENSITIVE_ENV_VARS
        )
        assert result == "AWS_ENDPOINT_URL"

    def test_multiple_assignments_second_match(self) -> None:
        # Non-sensitive first, sensitive second
        result = _check_sensitive_env_prefix(
            "SOME_VAR=x AWS_ENDPOINT_URL=evil aws s3 ls", _AWS_SENSITIVE_ENV_VARS
        )
        # SOME_VAR stops scan (not a sensitive var), but the scan continues
        # Actually our scanner stops at non-sensitive (still-assignment) tokens
        # This tests that the second assignment is still checked
        assert result == "AWS_ENDPOINT_URL"

    def test_safe_env_var_not_matched(self) -> None:
        assert (
            _check_sensitive_env_prefix(
                "FOO=bar aws ec2 describe-instances", _AWS_SENSITIVE_ENV_VARS
            )
            is None
        )

    def test_no_env_prefix(self) -> None:
        assert (
            _check_sensitive_env_prefix("aws ec2 describe-instances", _AWS_SENSITIVE_ENV_VARS)
            is None
        )

    def test_env_after_cli_not_matched(self) -> None:
        # Env var appearing after the CLI binary is not a prefix assignment
        assert (
            _check_sensitive_env_prefix(
                "aws ec2 describe-instances AWS_ENDPOINT_URL=evil", _AWS_SENSITIVE_ENV_VARS
            )
            is None
        )


class TestGcloudSensitiveEnvVars:
    def test_cloudsdk_api_endpoint_overrides_prefix(self) -> None:
        assert (
            _check_sensitive_env_prefix(
                "CLOUDSDK_API_ENDPOINT_OVERRIDES_COMPUTE=http://evil gcloud compute instances list",
                _GCLOUD_SENSITIVE_ENV_VARS,
            )
            == "CLOUDSDK_API_ENDPOINT_OVERRIDES_COMPUTE"
        )

    def test_cloudsdk_auth_credential_file_override(self) -> None:
        assert (
            _check_sensitive_env_prefix(
                "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE=/evil/key.json gcloud projects list",
                _GCLOUD_SENSITIVE_ENV_VARS,
            )
            == "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"
        )

    def test_cloudsdk_core_project(self) -> None:
        assert (
            _check_sensitive_env_prefix(
                "CLOUDSDK_CORE_PROJECT=attacker-proj gcloud projects list",
                _GCLOUD_SENSITIVE_ENV_VARS,
            )
            == "CLOUDSDK_CORE_PROJECT"
        )


class TestAzSensitiveEnvVars:
    def test_azure_config_dir(self) -> None:
        assert (
            _check_sensitive_env_prefix(
                "AZURE_CONFIG_DIR=/evil/.azure az vm list", _AZ_SENSITIVE_ENV_VARS
            )
            == "AZURE_CONFIG_DIR"
        )

    def test_azure_cli_disable_connection_verification(self) -> None:
        assert (
            _check_sensitive_env_prefix(
                "AZURE_CLI_DISABLE_CONNECTION_VERIFICATION=1 az vm list", _AZ_SENSITIVE_ENV_VARS
            )
            == "AZURE_CLI_DISABLE_CONNECTION_VERIFICATION"
        )

    def test_requests_ca_bundle(self) -> None:
        assert (
            _check_sensitive_env_prefix(
                "REQUESTS_CA_BUNDLE=/evil/ca.crt az account show", _AZ_SENSITIVE_ENV_VARS
            )
            == "REQUESTS_CA_BUNDLE"
        )
