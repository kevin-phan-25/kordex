#!/usr/bin/env python3
"""Unit checks for fail-closed GKE NetworkPolicy enforcement detection."""
import importlib.util
from pathlib import Path
from unittest.mock import patch
import subprocess

path = Path(__file__).with_name("validate-gke-private-lab.py")
spec = importlib.util.spec_from_file_location("gke_private_lab_validator", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

assert module.network_policy_enforced({}) is False
assert module.network_policy_enforced({"networkPolicy": {"enabled": True, "provider": "CALICO"}}) is False

def successful(*args, **kwargs):
    return subprocess.CompletedProcess(args[0], 0, '{"status":{"desiredNumberScheduled":3,"numberReady":3}}', "")

with patch.object(module.subprocess, "run", side_effect=successful):
    assert module.network_policy_enforced({"networkConfig": {"datapathProvider": "ADVANCED_DATAPATH"}}) is True

def no_daemonset(*args, **kwargs):
    return subprocess.CompletedProcess(args[0], 1, "", "not found")

with patch.object(module.subprocess, "run", side_effect=no_daemonset):
    assert module.network_policy_enforced({"networkConfig": {"datapathProvider": "ADVANCED_DATAPATH"}}) is False
    assert module.network_policy_enforced({"networkPolicy": {"enabled": True, "provider": "CALICO"}}) is False

def calico_ready(*args, **kwargs):
    command = args[0]
    if "daemonset" in command:
        return subprocess.CompletedProcess(command, 0, '{"status":{"desiredNumberScheduled":3,"numberReady":3}}', "")
    return subprocess.CompletedProcess(command, 0, '{"items":[{"metadata":{"labels":{"projectcalico.org/ds-ready":"true"}}},{"metadata":{"labels":{"projectcalico.org/ds-ready":"true"}}}]}', "")

with patch.object(module.subprocess, "run", side_effect=calico_ready):
    assert module.network_policy_enforced({"networkPolicy": {"enabled": True, "provider": "CALICO"}}) is True

print("private lab validator NetworkPolicy enforcement tests passed")
