import importlib.util
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).with_name("m3_cost_model.py")
SPEC = importlib.util.spec_from_file_location("m3_cost_model", MODULE_PATH)
cost_model = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cost_model)


class CostModelTest(unittest.TestCase):
    def base(self, **overrides):
        values = {
            "vm_hours_per_vm": 0,
            "snapshot_stored_gib_hours": 0,
            "monthly_logging_gib": [0, 0, 0],
            "network_cost_bound_usd": 0,
            "artifact_storage_cost_bound_usd": 0,
            "registry_storage_cost_bound_usd": 0,
            "rhel_subscription_cost_bound_usd": 0,
            "other_cost_bound_usd": 0,
        }
        values.update(overrides)
        return values

    def test_persistent_costs_continue_when_vms_are_stopped(self):
        report = cost_model.estimate(**self.base())
        self.assertEqual(report["costsUsd"]["vmCompute"], 0)
        self.assertEqual(report["costsUsd"]["persistentBalancedBootDisks"], 35.51)
        self.assertEqual(report["costsUsd"]["privateDnsZone"], 0.59)
        self.assertEqual(report["status"], "BLOCKED_BILLING_HEADROOM_NOT_PROVIDED")

    def test_rhel_stopped_license_uncertainty_is_modeled_conservatively(self):
        report = cost_model.estimate(**self.base(vm_hours_per_vm=720))
        costs = report["costsUsd"]
        self.assertEqual(costs["vmCompute"], 144.74)
        self.assertEqual(costs["rhelPaygActiveRuntimeScenario"], 62.21)
        self.assertEqual(costs["rhelPaygContinuousScenario"], 186.62)
        self.assertEqual(report["status"], "BLOCKED_BILLING_HEADROOM_NOT_PROVIDED")

    def test_full_time_rhel_case_exceeds_ceiling_with_reserve(self):
        report = cost_model.estimate(**self.base(
            vm_hours_per_vm=720,
            snapshot_stored_gib_hours=120 * 90 * 24,
            billing_headroom_usd=300,
        ))
        self.assertEqual(report["status"], "BLOCKED_WORST_CASE_EXCEEDS_POLICY_CEILING")
        self.assertGreater(
            report["costsUsd"]["scenarioTotalsWithReserve"]["rhelLicenseChargedContinuouslyWhileStopped"],
            300,
        )

    def test_logging_bound_does_not_assume_project_free_allowance_is_unused(self):
        report = cost_model.estimate(**self.base(monthly_logging_gib=[60, 50, 70]))
        self.assertEqual(report["costsUsd"]["cloudLoggingOverage"], 90)

    def test_unbounded_runtime_and_bad_inputs_are_rejected(self):
        with self.assertRaises(cost_model.CostModelError):
            cost_model.estimate(**self.base(vm_hours_per_vm=2161))
        with self.assertRaises(cost_model.CostModelError):
            cost_model.estimate(**self.base(network_cost_bound_usd=float("nan")))
        with self.assertRaises(cost_model.CostModelError):
            cost_model.estimate(**self.base(monthly_logging_gib=[1, 2]))

    def test_headroom_number_never_counts_as_independent_verification(self):
        report = cost_model.estimate(**self.base(billing_headroom_usd=300))
        self.assertEqual(
            report["status"],
            "MODELED_WITHIN_CEILING_PENDING_INDEPENDENT_COST_AND_BILLING_VERIFICATION",
        )


if __name__ == "__main__":
    unittest.main()
