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
            "machine_type": "e2-medium",
            "boot_disk_size_gib": 40,
            "debian_scenario_hours_per_vm": 0,
            "debian_cleanup_restore_hours_per_vm": 0,
            "rhel_scenario_hours_per_vm": 0,
            "rhel_cleanup_restore_hours_per_vm": 0,
            "wrong_machine_id_extra_host_hours_per_os": 0,
            "rhel_license_mode": "payg",
            "rhel_license_hours_per_vm": 0,
            "debian_boot_disk_gib_hours": 3 * 40 * 45 * 24,
            "rhel_boot_disk_gib_hours": 3 * 40 * 45 * 24,
            "wrong_machine_id_extra_host_disk_gib_hours_per_os": 0,
            "snapshot_stored_gib_hours": 0,
            "private_dns_queries": 0,
            "monthly_logging_gib": [0, 0, 0],
            "logging_retention_cost_bound_usd": 0,
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
        report = cost_model.estimate(**self.base(
            rhel_scenario_hours_per_vm=720, rhel_license_hours_per_vm=720))
        costs = report["costsUsd"]
        self.assertEqual(costs["vmCompute"], 72.37)
        self.assertEqual(costs["rhelPaygActiveRuntimeScenario"], 62.21)
        self.assertEqual(costs["rhelPaygContinuousScenario"], 186.62)
        self.assertEqual(report["status"], "BLOCKED_WORST_CASE_EXCEEDS_POLICY_CEILING")

    def test_full_time_rhel_case_exceeds_ceiling_with_reserve(self):
        report = cost_model.estimate(**self.base(
            rhel_scenario_hours_per_vm=720,
            rhel_license_hours_per_vm=720,
            wrong_machine_id_extra_host_disk_gib_hours_per_os=80,
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
            cost_model.estimate(**self.base(debian_scenario_hours_per_vm=2161))
        with self.assertRaises(cost_model.CostModelError):
            cost_model.estimate(**self.base(network_cost_bound_usd=float("nan")))
        with self.assertRaises(cost_model.CostModelError):
            cost_model.estimate(**self.base(monthly_logging_gib=[1, 2]))

    def test_headroom_cannot_override_continuous_rhel_cost_ceiling(self):
        report = cost_model.estimate(**self.base(billing_headroom_usd=300, network_cost_bound_usd=20))
        self.assertEqual(
            report["status"],
            "BLOCKED_WORST_CASE_EXCEEDS_POLICY_CEILING",
        )

    def test_byos_high_water_uses_the_selected_subscription_bound(self):
        report = cost_model.estimate(**self.base(
            rhel_license_mode="byos",
            rhel_subscription_cost_bound_usd=25,
            billing_headroom_usd=300,
        ))
        self.assertEqual(report["costsUsd"]["conservativeHighWaterScenario"], "rhelByosSubscription")
        self.assertLessEqual(report["costsUsd"]["conservativeHighWaterUsd"], 300)
        self.assertEqual(report["status"],
                         "MODELED_WITHIN_CEILING_PENDING_INDEPENDENT_COST_AND_BILLING_VERIFICATION")

    def test_e2_medium_price_and_sequential_os_transition_are_independent(self):
        report = cost_model.estimate(**self.base(
            debian_scenario_hours_per_vm=40,
            debian_cleanup_restore_hours_per_vm=8,
            rhel_scenario_hours_per_vm=40,
            rhel_cleanup_restore_hours_per_vm=8,
            rhel_license_hours_per_vm=48,
        ))
        costs = report["costsUsd"]
        self.assertEqual(report["inputs"]["machineType"], "e2-medium")
        self.assertEqual(report["inputs"]["machineHourlyUsd"], 0.03350571)
        self.assertEqual(report["topology"]["maximumConcurrentVms"], 4)
        self.assertEqual(report["topology"]["profileExecution"], "sequential")
        self.assertEqual(costs["debianVmHoursAcrossThreeNodes"], 144)
        self.assertEqual(costs["rhelVmHoursAcrossThreeNodes"], 144)
        self.assertEqual(costs["totalVmHoursAcrossSequentialCampaigns"], 288)
        self.assertEqual(costs["debianVmCompute"], 4.82)
        self.assertEqual(costs["rhelVmCompute"], 4.82)
        self.assertEqual(costs["vmCompute"], 9.65)
        self.assertEqual(costs["rhelPaygActiveRuntimeScenario"], 4.15)

    def test_rhel_license_hours_are_independent_from_compute_hours(self):
        report = cost_model.estimate(**self.base(
            rhel_scenario_hours_per_vm=8,
            rhel_license_hours_per_vm=80,
        ))
        costs = report["costsUsd"]
        self.assertEqual(costs["rhelVmCompute"], 0.80)
        self.assertEqual(costs["rhelPaygActiveRuntimeScenario"], 0.69)
        self.assertEqual(costs["rhelPaygSuppliedLicenseHoursScenario"], 6.91)

    def test_rhel_license_hours_cannot_understate_running_hours(self):
        with self.assertRaisesRegex(cost_model.CostModelError, "cannot be lower"):
            cost_model.estimate(**self.base(
                rhel_scenario_hours_per_vm=8,
                rhel_license_hours_per_vm=7,
            ))

    def test_disks_cover_three_nodes_extra_host_retention_and_dns_queries(self):
        report = cost_model.estimate(**self.base(
            debian_scenario_hours_per_vm=10,
            rhel_scenario_hours_per_vm=10,
            wrong_machine_id_extra_host_hours_per_os=2,
            wrong_machine_id_extra_host_disk_gib_hours_per_os=80,
            rhel_license_hours_per_vm=10,
            private_dns_queries=1_000_000,
        ))
        costs = report["costsUsd"]
        self.assertEqual(report["topology"]["wrongMachineIdExtraHostsPerOsProfile"], 1)
        self.assertEqual(costs["wrongMachineIdExtraHostVmHours"], 4)
        self.assertEqual(costs["privateDnsQueries"], 0.4)
        with self.assertRaisesRegex(cost_model.CostModelError, "boot-disk GiB-hours"):
            cost_model.estimate(**self.base(
                debian_scenario_hours_per_vm=10,
                debian_boot_disk_gib_hours=100,
            ))

    def test_machine_type_without_verified_price_is_rejected(self):
        with self.assertRaisesRegex(cost_model.CostModelError, "no verified price"):
            cost_model.estimate(**self.base(machine_type="e2-standard-4"))

    def test_unknown_rhel_license_mode_is_rejected(self):
        with self.assertRaisesRegex(cost_model.CostModelError, "license mode"):
            cost_model.estimate(**self.base(rhel_license_mode="unknown"))

    def test_sequential_campaign_total_cannot_exceed_ninety_days(self):
        with self.assertRaisesRegex(cost_model.CostModelError, "sequential OS campaign"):
            cost_model.estimate(**self.base(
                debian_scenario_hours_per_vm=1200,
                rhel_scenario_hours_per_vm=1000,
                rhel_license_hours_per_vm=1000,
            ))


if __name__ == "__main__":
    unittest.main()
