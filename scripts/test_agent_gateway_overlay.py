#!/usr/bin/env python3
"""Guard the opt-in Cloudflare gateway wiring for the self-managed agent."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class AgentGatewayOverlayTests(unittest.TestCase):
    def test_gateway_auth_is_off_by_default_and_required_for_self_managed(self) -> None:
        base = (ROOT / "deployments/kustomize/components/agent/settings.yaml").read_text()
        overlay = (ROOT / "deployments/kustomize/overlays/self-managed/agent-settings.patch.yaml").read_text()
        self.assertIn('gatewayAuthRequired: "false"', base)
        self.assertIn('gatewayAuthRequired: "true"', overlay)

    def test_agent_reads_credentials_only_from_named_secret(self) -> None:
        deployment = (ROOT / "deployments/kustomize/components/agent/deployment.yaml").read_text()
        self.assertIn("name: KORDEX_GATEWAY_AUTH_REQUIRED", deployment)
        self.assertIn("name: KORDEX_GATEWAY_CLIENT_ID", deployment)
        self.assertIn("name: KORDEX_GATEWAY_CLIENT_SECRET", deployment)
        self.assertIn("name: kordex-api-gateway", deployment)
        self.assertIn("key: client-id", deployment)
        self.assertIn("key: client-secret", deployment)
        self.assertNotIn("CF-Access-Client-Secret:", deployment)
        self.assertNotIn("client-secret: ", deployment)


if __name__ == "__main__":
    unittest.main()
