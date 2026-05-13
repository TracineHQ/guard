# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Unit tests for _check_admin_forbidden_flag helper."""

from __future__ import annotations

from guard.hooks._admin_specs import (
    _AWS_SPEC,
    _AZ_SPEC,
    _GCLOUD_SPEC,
    _KUBECTL_SPEC,
)
from guard.hooks.bash_command_validator import _check_admin_forbidden_flag


class TestAwsForbiddenFlags:
    def test_endpoint_url_space_form(self) -> None:
        assert (
            _check_admin_forbidden_flag(_AWS_SPEC, ["sts", "--endpoint-url", "http://evil"])
            == "--endpoint-url"
        )

    def test_endpoint_url_fused_form(self) -> None:
        assert (
            _check_admin_forbidden_flag(_AWS_SPEC, ["sts", "--endpoint-url=http://evil"])
            == "--endpoint-url"
        )

    def test_no_verify_ssl(self) -> None:
        assert (
            _check_admin_forbidden_flag(_AWS_SPEC, ["s3", "--no-verify-ssl", "ls"])
            == "--no-verify-ssl"
        )

    def test_ca_bundle(self) -> None:
        assert (
            _check_admin_forbidden_flag(_AWS_SPEC, ["--ca-bundle", "/evil/ca.crt", "s3", "ls"])
            == "--ca-bundle"
        )

    def test_no_sign_request(self) -> None:
        assert (
            _check_admin_forbidden_flag(_AWS_SPEC, ["s3", "ls", "--no-sign-request"])
            == "--no-sign-request"
        )

    def test_profile(self) -> None:
        assert (
            _check_admin_forbidden_flag(_AWS_SPEC, ["--profile", "attacker", "iam", "list-users"])
            == "--profile"
        )

    def test_profile_fused(self) -> None:
        assert (
            _check_admin_forbidden_flag(_AWS_SPEC, ["--profile=attacker", "iam", "list-users"])
            == "--profile"
        )

    def test_debug(self) -> None:
        assert (
            _check_admin_forbidden_flag(_AWS_SPEC, ["--debug", "sts", "get-caller-identity"])
            == "--debug"
        )

    def test_cli_input_json(self) -> None:
        assert (
            _check_admin_forbidden_flag(_AWS_SPEC, ["ec2", "--cli-input-json", "file://x"])
            == "--cli-input-json"
        )

    def test_cli_input_yaml(self) -> None:
        assert (
            _check_admin_forbidden_flag(_AWS_SPEC, ["ec2", "--cli-input-yaml=file://x"])
            == "--cli-input-yaml"
        )

    def test_safe_flag_not_matched(self) -> None:
        assert (
            _check_admin_forbidden_flag(
                _AWS_SPEC, ["--region", "us-east-1", "ec2", "describe-instances"]
            )
            is None
        )

    def test_no_flags(self) -> None:
        assert _check_admin_forbidden_flag(_AWS_SPEC, ["ec2", "describe-instances"]) is None


class TestGcloudForbiddenFlags:
    def test_impersonate_service_account(self) -> None:
        assert (
            _check_admin_forbidden_flag(
                _GCLOUD_SPEC,
                [
                    "--impersonate-service-account",
                    "sa@proj.iam.gserviceaccount.com",
                    "compute",
                    "instances",
                    "list",
                ],
            )
            == "--impersonate-service-account"
        )

    def test_impersonate_fused(self) -> None:
        assert (
            _check_admin_forbidden_flag(
                _GCLOUD_SPEC, ["--impersonate-service-account=sa@proj.iam.gserviceaccount.com"]
            )
            == "--impersonate-service-account"
        )

    def test_credential_file_override(self) -> None:
        assert (
            _check_admin_forbidden_flag(
                _GCLOUD_SPEC, ["--credential-file-override", "/evil/key.json"]
            )
            == "--credential-file-override"
        )

    def test_access_token_file(self) -> None:
        assert (
            _check_admin_forbidden_flag(_GCLOUD_SPEC, ["--access-token-file=/tmp/token"])
            == "--access-token-file"
        )

    def test_configuration(self) -> None:
        assert (
            _check_admin_forbidden_flag(_GCLOUD_SPEC, ["--configuration", "evil"])
            == "--configuration"
        )

    def test_account(self) -> None:
        assert (
            _check_admin_forbidden_flag(
                _GCLOUD_SPEC, ["--account", "attacker@proj.iam.gserviceaccount.com"]
            )
            == "--account"
        )

    def test_log_http(self) -> None:
        assert (
            _check_admin_forbidden_flag(
                _GCLOUD_SPEC, ["--log-http", "compute", "instances", "list"]
            )
            == "--log-http"
        )

    def test_flags_file(self) -> None:
        assert (
            _check_admin_forbidden_flag(_GCLOUD_SPEC, ["--flags-file=/tmp/evil.yaml"])
            == "--flags-file"
        )

    def test_safe_format_not_matched(self) -> None:
        assert (
            _check_admin_forbidden_flag(
                _GCLOUD_SPEC, ["--format", "json", "compute", "instances", "list"]
            )
            is None
        )


class TestAzForbiddenFlags:
    def test_debug(self) -> None:
        assert _check_admin_forbidden_flag(_AZ_SPEC, ["vm", "list", "--debug"]) == "--debug"

    def test_debug_fused(self) -> None:
        # az --debug takes no value, but fused form shouldn't match normally; test space form
        assert _check_admin_forbidden_flag(_AZ_SPEC, ["account", "show", "--debug"]) == "--debug"

    def test_safe_output_not_matched(self) -> None:
        assert _check_admin_forbidden_flag(_AZ_SPEC, ["--output", "json", "vm", "list"]) is None


class TestKubectlForbiddenFlags:
    def test_as_impersonation(self) -> None:
        assert (
            _check_admin_forbidden_flag(_KUBECTL_SPEC, ["get", "pods", "--as=cluster-admin"])
            == "--as"
        )

    def test_as_group(self) -> None:
        assert (
            _check_admin_forbidden_flag(
                _KUBECTL_SPEC, ["get", "secrets", "--as-group", "system:masters"]
            )
            == "--as-group"
        )

    def test_as_uid(self) -> None:
        assert (
            _check_admin_forbidden_flag(_KUBECTL_SPEC, ["get", "pods", "--as-uid=123"])
            == "--as-uid"
        )

    def test_server(self) -> None:
        assert (
            _check_admin_forbidden_flag(_KUBECTL_SPEC, ["get", "pods", "--server=https://evil.com"])
            == "--server"
        )

    def test_server_short(self) -> None:
        assert (
            _check_admin_forbidden_flag(_KUBECTL_SPEC, ["-s", "https://evil.com", "get", "pods"])
            == "-s"
        )

    def test_token(self) -> None:
        assert (
            _check_admin_forbidden_flag(_KUBECTL_SPEC, ["get", "pods", "--token=stolen"])
            == "--token"
        )

    def test_kubeconfig(self) -> None:
        assert (
            _check_admin_forbidden_flag(_KUBECTL_SPEC, ["--kubeconfig=/evil/config", "get", "pods"])
            == "--kubeconfig"
        )

    def test_insecure_skip_tls_verify(self) -> None:
        assert (
            _check_admin_forbidden_flag(
                _KUBECTL_SPEC, ["get", "pods", "--insecure-skip-tls-verify"]
            )
            == "--insecure-skip-tls-verify"
        )

    def test_certificate_authority(self) -> None:
        assert (
            _check_admin_forbidden_flag(
                _KUBECTL_SPEC, ["get", "pods", "--certificate-authority=/evil/ca.crt"]
            )
            == "--certificate-authority"
        )

    def test_client_certificate(self) -> None:
        assert (
            _check_admin_forbidden_flag(
                _KUBECTL_SPEC, ["get", "pods", "--client-certificate=/evil/cert.pem"]
            )
            == "--client-certificate"
        )

    def test_client_key(self) -> None:
        assert (
            _check_admin_forbidden_flag(
                _KUBECTL_SPEC, ["get", "pods", "--client-key=/evil/key.pem"]
            )
            == "--client-key"
        )

    def test_context(self) -> None:
        assert (
            _check_admin_forbidden_flag(_KUBECTL_SPEC, ["--context=evil-cluster", "get", "pods"])
            == "--context"
        )

    def test_user(self) -> None:
        assert (
            _check_admin_forbidden_flag(_KUBECTL_SPEC, ["--user=attacker", "get", "pods"])
            == "--user"
        )

    def test_username(self) -> None:
        assert (
            _check_admin_forbidden_flag(_KUBECTL_SPEC, ["--username=admin", "get", "pods"])
            == "--username"
        )

    def test_password(self) -> None:
        assert (
            _check_admin_forbidden_flag(_KUBECTL_SPEC, ["--password=secret", "get", "pods"])
            == "--password"
        )

    def test_verbosity(self) -> None:
        assert _check_admin_forbidden_flag(_KUBECTL_SPEC, ["get", "pods", "-v", "9"]) == "-v"

    def test_verbosity_long(self) -> None:
        assert _check_admin_forbidden_flag(_KUBECTL_SPEC, ["get", "pods", "--v=9"]) == "--v"

    def test_safe_namespace_not_matched(self) -> None:
        assert (
            _check_admin_forbidden_flag(_KUBECTL_SPEC, ["-n", "kube-system", "get", "pods"]) is None
        )

    def test_empty_tokens(self) -> None:
        assert _check_admin_forbidden_flag(_KUBECTL_SPEC, []) is None
