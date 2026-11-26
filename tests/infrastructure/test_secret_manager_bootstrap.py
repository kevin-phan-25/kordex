import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "infrastructure/terraform/gcp/self-managed-lab/secret_manager_bootstrap.py"
SPEC = importlib.util.spec_from_file_location("secret_manager_bootstrap", SOURCE)
assert SPEC and SPEC.loader
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


class SecretManagerBootstrapTests(unittest.TestCase):
    def test_publish_pipes_secret_and_prints_only_version_reference(self):
        secret = b"K10ca-hash::abcdef.0123456789abcdef"
        output = io.StringIO()
        with patch.object(helper.sys, "stdin", io.TextIOWrapper(io.BytesIO(secret))), \
                patch.object(helper, "numeric_project_id", return_value="209068399397"), \
                patch.object(helper, "request", return_value=(200, b'{"name":"projects/kordex-project/secrets/kordex-lab-join/versions/1"}')) as request, \
                contextlib.redirect_stdout(output):
            helper.publish("kordex-project", "kordex-lab-join")
        self.assertEqual(request.call_args.args[1], "projects/kordex-project/secrets/kordex-lab-join:addVersion")
        self.assertNotIn(secret.decode(), output.getvalue())
        self.assertEqual(output.getvalue(), "projects/kordex-project/secrets/kordex-lab-join/versions/1\n")

    def test_publish_rejects_mismatched_resource_response_without_secret_output(self):
        secret = b"K10ca-hash::abcdef.0123456789abcdef"
        output = io.StringIO()
        with patch.object(helper.sys, "stdin", io.TextIOWrapper(io.BytesIO(secret))), \
                patch.object(helper, "numeric_project_id", return_value="209068399397"), \
                patch.object(helper, "request", return_value=(200, b'{"name":"projects/other-project/secrets/other/versions/1"}')), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(helper.SecretManagerError):
                helper.publish("kordex-project", "kordex-lab-join")
        self.assertEqual(output.getvalue(), "")

    def test_publish_accepts_gce_bound_numeric_project_number_response(self):
        secret = b"K10ca-hash::abcdef.0123456789abcdef"
        output = io.StringIO()
        with patch.object(helper.sys, "stdin", io.TextIOWrapper(io.BytesIO(secret))), \
                patch.object(helper, "numeric_project_id", return_value="209068399397"), \
                patch.object(helper, "request", return_value=(200, b'{"name":"projects/209068399397/secrets/kordex-lab-join/versions/2"}')), \
                contextlib.redirect_stdout(output):
            helper.publish("kordex-project", "kordex-lab-join")
        self.assertEqual(output.getvalue(), "projects/209068399397/secrets/kordex-lab-join/versions/2\n")

    def test_publish_rejects_numeric_project_number_not_matching_gce_metadata(self):
        secret = b"K10ca-hash::abcdef.0123456789abcdef"
        output = io.StringIO()
        with patch.object(helper.sys, "stdin", io.TextIOWrapper(io.BytesIO(secret))), \
                patch.object(helper, "numeric_project_id", return_value="209068399397"), \
                patch.object(helper, "request", return_value=(200, b'{"name":"projects/123456789012/secrets/kordex-lab-join/versions/2"}')), \
                contextlib.redirect_stdout(output), self.assertRaises(helper.SecretManagerError):
            helper.publish("kordex-project", "kordex-lab-join")
        self.assertEqual(output.getvalue(), "")

    def test_fetch_writes_only_root_private_file(self):
        import base64

        value = b"K10ca-hash::abcdef.0123456789abcdef"
        body = b'{"payload":{"data":"' + base64.b64encode(value) + b'"}}'
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "token"
            with patch.object(helper, "request", return_value=(200, body)):
                helper.fetch("kordex-project", "kordex-lab-join", destination)
            self.assertEqual(destination.read_bytes(), value)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

    def test_invalid_version_reference_is_rejected_before_api_call(self):
        with patch.object(helper, "request") as request, self.assertRaises(helper.SecretManagerError):
            helper.destroy("projects/other/secrets/secret/versions/1", "kordex-project", "secret")
        request.assert_not_called()

    def test_destroy_uses_secret_manager_destroy_method_and_fails_closed_on_404(self):
        version = "projects/209068399397/secrets/kordex-lab-join/versions/7"
        with patch.object(helper, "numeric_project_id", return_value="209068399397"), \
                patch.object(helper, "request", return_value=(200, b"")) as request:
            helper.destroy(version, "kordex-project", "kordex-lab-join")
        request.assert_called_once_with("POST", version + ":destroy", b"{}")
        with patch.object(helper, "numeric_project_id", return_value="209068399397"), \
                patch.object(helper, "request", return_value=(404, b"")) as request:
            with self.assertRaisesRegex(helper.SecretManagerError, "HTTP 404"):
                helper.destroy(version, "kordex-project", "kordex-lab-join")
        request.assert_called_once_with("POST", version + ":destroy", b"{}")

    def test_destroy_accepts_project_id_and_rejects_wrong_secret_or_project_number(self):
        version = "projects/kordex-project/secrets/kordex-lab-join/versions/3"
        with patch.object(helper, "request", return_value=(204, b"")) as request:
            helper.destroy(version, "kordex-project", "kordex-lab-join")
        request.assert_called_once_with("POST", version + ":destroy", b"{}")

        with patch.object(helper, "request") as request, self.assertRaises(helper.SecretManagerError):
            helper.destroy(version, "kordex-project", "another-secret")
        request.assert_not_called()

        numeric_version = "projects/123456789012/secrets/kordex-lab-join/versions/3"
        with patch.object(helper, "numeric_project_id", return_value="209068399397"), \
                patch.object(helper, "request") as request, self.assertRaisesRegex(
                    helper.SecretManagerError, "different project"
                ):
            helper.destroy(numeric_version, "kordex-project", "kordex-lab-join")
        request.assert_not_called()

    def test_present_checks_metadata_without_accessing_secret_payload(self):
        with patch.object(helper, "request", return_value=(200, b'{"state":"ENABLED"}')) as request:
            self.assertTrue(helper.present("kordex-project", "kordex-lab-join"))
        self.assertEqual(request.call_args.args[1], "projects/kordex-project/secrets/kordex-lab-join/versions/latest")
        self.assertNotIn(":access", request.call_args.args[1])
        with patch.object(helper, "request", return_value=(200, b'{"state":"DESTROYED"}')):
            self.assertFalse(helper.present("kordex-project", "kordex-lab-join"))
        with patch.object(helper, "request", return_value=(404, b"")):
            self.assertFalse(helper.present("kordex-project", "kordex-lab-join"))


if __name__ == "__main__":
    unittest.main()
