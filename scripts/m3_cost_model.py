#!/usr/bin/env python3
"""Offline 90-day cost model for the self-managed GCP qualification lab.

This is an estimate, not a billing integration or authorization. Public list
prices below were checked on 2026-11-22. Variable costs and RHEL stopped-VM
license treatment must be bounded and independently confirmed by the billing
owner before a plan can be approved.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import sys
from typing import Sequence


PROJECT_ID = "kordex-fleet-platform-515416"
PROJECT_NUMBER = "209068399397"
REGION = "us-east1"
DAYS = 90
CEILING_USD = 300.0
RESERVE_FRACTION = 0.20

# Public on-demand prices for us-east1, USD. The selected profile's explicit
# machine type is required; never silently price a different Terraform default.
MACHINE_TYPE_PRICES = {
    "e2-medium": {"hourlyUsd": 0.03350571, "vcpus": 2},
}
PD_BALANCED_GIB_PER_HOUR = 0.000136986
STANDARD_SNAPSHOT_GIB_PER_HOUR = 0.00006849
PRIVATE_DNS_ZONE_PER_HOUR = 0.000273973
PRIVATE_DNS_QUERY_PER_MILLION = 0.40
RHEL_PAYG_PER_CORE_HOUR = 0.0144  # up to 8 vCPUs
CLOUD_LOGGING_PER_GIB = 0.50


class CostModelError(ValueError):
    pass


def estimate(
    *,
    machine_type: str,
    boot_disk_size_gib: float,
    debian_scenario_hours_per_vm: float,
    debian_cleanup_restore_hours_per_vm: float,
    rhel_scenario_hours_per_vm: float,
    rhel_cleanup_restore_hours_per_vm: float,
    wrong_machine_id_extra_host_hours_per_os: float,
    rhel_license_mode: str,
    rhel_license_hours_per_vm: float,
    debian_boot_disk_gib_hours: float,
    rhel_boot_disk_gib_hours: float,
    wrong_machine_id_extra_host_disk_gib_hours_per_os: float,
    snapshot_stored_gib_hours: float,
    private_dns_queries: float,
    monthly_logging_gib: Sequence[float],
    logging_retention_cost_bound_usd: float,
    network_cost_bound_usd: float,
    artifact_storage_cost_bound_usd: float,
    registry_storage_cost_bound_usd: float,
    rhel_subscription_cost_bound_usd: float,
    other_cost_bound_usd: float,
    billing_headroom_usd: float | None = None,
) -> dict:
    """Return bounded modeled costs, never a customer/billing verification.

    Scenario and cleanup/restoration runtime are per VM. The wrong-machine-ID
    case gets a separately billed disposable host on each OS profile. The two
    profiles run sequentially, so at most four VMs are billed at once.
    Provisioned boot disks and stored snapshots have separate retention inputs.
    RHEL licensing is reported using runtime, supplied billable-hours, and a
    conservative continuous-90-day upper bound.
    """
    machine = MACHINE_TYPE_PRICES.get(machine_type)
    if machine is None:
        raise CostModelError(f"no verified price is configured for machine type {machine_type!r}")
    if rhel_license_mode not in {"payg", "byos"}:
        raise CostModelError("RHEL license mode must be payg or byos")
    numeric = {
        "debian_scenario_hours_per_vm": debian_scenario_hours_per_vm,
        "debian_cleanup_restore_hours_per_vm": debian_cleanup_restore_hours_per_vm,
        "rhel_scenario_hours_per_vm": rhel_scenario_hours_per_vm,
        "rhel_cleanup_restore_hours_per_vm": rhel_cleanup_restore_hours_per_vm,
        "wrong_machine_id_extra_host_hours_per_os": wrong_machine_id_extra_host_hours_per_os,
        "boot_disk_size_gib": boot_disk_size_gib,
        "rhel_license_hours_per_vm": rhel_license_hours_per_vm,
        "debian_boot_disk_gib_hours": debian_boot_disk_gib_hours,
        "rhel_boot_disk_gib_hours": rhel_boot_disk_gib_hours,
        "wrong_machine_id_extra_host_disk_gib_hours_per_os": wrong_machine_id_extra_host_disk_gib_hours_per_os,
        "snapshot_stored_gib_hours": snapshot_stored_gib_hours,
        "private_dns_queries": private_dns_queries,
        "logging_retention_cost_bound_usd": logging_retention_cost_bound_usd,
        "network_cost_bound_usd": network_cost_bound_usd,
        "artifact_storage_cost_bound_usd": artifact_storage_cost_bound_usd,
        "registry_storage_cost_bound_usd": registry_storage_cost_bound_usd,
        "rhel_subscription_cost_bound_usd": rhel_subscription_cost_bound_usd,
        "other_cost_bound_usd": other_cost_bound_usd,
    }
    if any(not math.isfinite(value) or value < 0 for value in numeric.values()):
        raise CostModelError("cost inputs must be finite and nonnegative")
    max_hours = DAYS * 24
    debian_vm_hours_per_vm = debian_scenario_hours_per_vm + debian_cleanup_restore_hours_per_vm
    rhel_vm_hours_per_vm = rhel_scenario_hours_per_vm + rhel_cleanup_restore_hours_per_vm
    if boot_disk_size_gib < 30 or boot_disk_size_gib > 200:
        raise CostModelError("boot disk size must match the Terraform 30-200 GiB range")
    if debian_vm_hours_per_vm > max_hours or rhel_vm_hours_per_vm > max_hours:
        raise CostModelError("per-VM runtime for either sequential OS campaign exceeds the 90-day window")
    if rhel_license_hours_per_vm < rhel_vm_hours_per_vm:
        raise CostModelError("RHEL billable license hours cannot be lower than RHEL running hours")
    if rhel_license_hours_per_vm > max_hours:
        raise CostModelError("per-VM RHEL license hours exceed the 90-day window")
    if wrong_machine_id_extra_host_hours_per_os > min(debian_vm_hours_per_vm, rhel_vm_hours_per_vm):
        raise CostModelError("extra wrong-machine-id host hours cannot exceed its OS campaign runtime")
    if debian_vm_hours_per_vm + rhel_vm_hours_per_vm + 2 * wrong_machine_id_extra_host_hours_per_os > max_hours:
        raise CostModelError("sequential OS campaign runtime exceeds the 90-day window")
    if (debian_boot_disk_gib_hours < 3 * boot_disk_size_gib * debian_vm_hours_per_vm
            or rhel_boot_disk_gib_hours < 3 * boot_disk_size_gib * rhel_vm_hours_per_vm):
        raise CostModelError("boot-disk GiB-hours do not cover all three cluster VMs while running")
    if debian_boot_disk_gib_hours + rhel_boot_disk_gib_hours > 3 * boot_disk_size_gib * max_hours:
        raise CostModelError("sequential cluster boot-disk retention exceeds the 90-day single-cluster window")
    if wrong_machine_id_extra_host_disk_gib_hours_per_os < boot_disk_size_gib * wrong_machine_id_extra_host_hours_per_os:
        raise CostModelError("extra-host disk GiB-hours do not cover the wrong-machine-id runtime")
    if len(monthly_logging_gib) != 3 or any(
        not math.isfinite(value) or value < 0 for value in monthly_logging_gib
    ):
        raise CostModelError("provide three finite, nonnegative monthly logging volumes")
    if billing_headroom_usd is not None and (
        not math.isfinite(billing_headroom_usd) or billing_headroom_usd < 0
    ):
        raise CostModelError("billing headroom must be finite and nonnegative")

    total_vm_hours = 3 * (debian_vm_hours_per_vm + rhel_vm_hours_per_vm) + 2 * wrong_machine_id_extra_host_hours_per_os
    debian_compute = (3 * debian_vm_hours_per_vm + wrong_machine_id_extra_host_hours_per_os) * machine["hourlyUsd"]
    rhel_compute = (3 * rhel_vm_hours_per_vm + wrong_machine_id_extra_host_hours_per_os) * machine["hourlyUsd"]
    vm_compute = debian_compute + rhel_compute
    disk = (debian_boot_disk_gib_hours + rhel_boot_disk_gib_hours
            + 2 * wrong_machine_id_extra_host_disk_gib_hours_per_os) * PD_BALANCED_GIB_PER_HOUR
    dns = max_hours * PRIVATE_DNS_ZONE_PER_HOUR
    dns_queries = private_dns_queries / 1_000_000 * PRIVATE_DNS_QUERY_PER_MILLION
    snapshots = snapshot_stored_gib_hours * STANDARD_SNAPSHOT_GIB_PER_HOUR
    # Do not assume the project's free allotment is unused by existing
    # workloads. Charge the full submitted project-wide volume for a bound.
    logging = sum(monthly_logging_gib) * CLOUD_LOGGING_PER_GIB
    rhel_active = (3 * rhel_vm_hours_per_vm + wrong_machine_id_extra_host_hours_per_os) * machine["vcpus"] * RHEL_PAYG_PER_CORE_HOUR
    rhel_supplied = (3 * rhel_license_hours_per_vm + wrong_machine_id_extra_host_hours_per_os) * machine["vcpus"] * RHEL_PAYG_PER_CORE_HOUR
    rhel_continuous = (3 * max_hours + wrong_machine_id_extra_host_hours_per_os) * machine["vcpus"] * RHEL_PAYG_PER_CORE_HOUR
    bounded_variable = (
        logging
        + logging_retention_cost_bound_usd
        + network_cost_bound_usd
        + artifact_storage_cost_bound_usd
        + registry_storage_cost_bound_usd
        + other_cost_bound_usd
    )
    common = vm_compute + disk + dns + dns_queries + snapshots + bounded_variable
    reserve = CEILING_USD * RESERVE_FRACTION
    scenarios = {
        "rhelLicenseChargedOnlyForRuntime": common + rhel_active,
        "rhelLicenseUsingSuppliedBillableHours": common + rhel_supplied,
        "rhelLicenseChargedContinuouslyWhileStopped": common + rhel_continuous,
        "rhelByosSubscription": common + rhel_subscription_cost_bound_usd,
    }
    with_reserve = {name: total + reserve for name, total in scenarios.items()}
    selected_scenarios = ("rhelLicenseChargedContinuouslyWhileStopped",) if rhel_license_mode == "payg" else ("rhelByosSubscription",)
    conservative_high_water = max(with_reserve[name] for name in selected_scenarios)
    if conservative_high_water > CEILING_USD:
        status = "BLOCKED_WORST_CASE_EXCEEDS_POLICY_CEILING"
    elif billing_headroom_usd is None:
        status = "BLOCKED_BILLING_HEADROOM_NOT_PROVIDED"
    elif conservative_high_water > billing_headroom_usd:
        status = "BLOCKED_WORST_CASE_EXCEEDS_REPORTED_HEADROOM_PENDING_VERIFICATION"
    else:
        # A caller-supplied number cannot establish billing headroom. This
        # status intentionally never becomes VERIFIED or APPROVED.
        status = "MODELED_WITHIN_CEILING_PENDING_INDEPENDENT_COST_AND_BILLING_VERIFICATION"

    return {
        "schemaVersion": 2,
        "projectId": PROJECT_ID,
        "projectNumber": PROJECT_NUMBER,
        "region": REGION,
        "periodDays": DAYS,
        "policyCeilingUsd": CEILING_USD,
        "reserveFraction": RESERVE_FRACTION,
        "reserveUsd": round(reserve, 2),
        "topology": {
            "nodesPerOsProfile": 3,
            "wrongMachineIdExtraHostsPerOsProfile": 1,
            "maximumConcurrentVms": 4,
            "profileExecution": "sequential",
        },
        "inputs": {
            "machineType": machine_type,
            "bootDiskSizeGiB": boot_disk_size_gib,
            "machineVcpus": machine["vcpus"],
            "machineHourlyUsd": machine["hourlyUsd"],
            "debianScenarioHoursPerVm": debian_scenario_hours_per_vm,
            "debianCleanupRestoreHoursPerVm": debian_cleanup_restore_hours_per_vm,
            "debianTotalVmHoursPerVm": debian_vm_hours_per_vm,
            "rhelScenarioHoursPerVm": rhel_scenario_hours_per_vm,
            "rhelCleanupRestoreHoursPerVm": rhel_cleanup_restore_hours_per_vm,
            "rhelTotalVmHoursPerVm": rhel_vm_hours_per_vm,
            "wrongMachineIdExtraHostHoursPerOs": wrong_machine_id_extra_host_hours_per_os,
            "rhelLicenseMode": rhel_license_mode,
            "rhelLicenseHoursPerVm": rhel_license_hours_per_vm,
            "debianBootDiskGiBHours": debian_boot_disk_gib_hours,
            "rhelBootDiskGiBHours": rhel_boot_disk_gib_hours,
            "wrongMachineIdExtraHostDiskGiBHoursPerOs": wrong_machine_id_extra_host_disk_gib_hours_per_os,
            "snapshotStoredGiBHours": snapshot_stored_gib_hours,
            "privateDnsQueries": private_dns_queries,
            "monthlyLoggingGiB": list(monthly_logging_gib),
            "loggingRetentionCostBoundUsd": logging_retention_cost_bound_usd,
            "networkCostBoundUsd": network_cost_bound_usd,
            "artifactStorageCostBoundUsd": artifact_storage_cost_bound_usd,
            "registryStorageCostBoundUsd": registry_storage_cost_bound_usd,
            "rhelSubscriptionCostBoundUsd": rhel_subscription_cost_bound_usd,
            "otherCostBoundUsd": other_cost_bound_usd,
            "billingHeadroomUsd": billing_headroom_usd,
        },
        "costsUsd": {
            "vmCompute": round(vm_compute, 2),
            "debianVmCompute": round(debian_compute, 2),
            "rhelVmCompute": round(rhel_compute, 2),
            "debianVmHoursAcrossThreeNodes": round(3 * debian_vm_hours_per_vm, 2),
            "rhelVmHoursAcrossThreeNodes": round(3 * rhel_vm_hours_per_vm, 2),
            "wrongMachineIdExtraHostVmHours": round(2 * wrong_machine_id_extra_host_hours_per_os, 2),
            "totalVmHoursAcrossSequentialCampaigns": round(total_vm_hours, 2),
            "persistentBalancedBootDisks": round(disk, 2),
            "privateDnsZone": round(dns, 2),
            "privateDnsQueries": round(dns_queries, 2),
            "privateVPCAndFirewallResources": 0.0,
            "standardSnapshots": round(snapshots, 2),
            "cloudLoggingOverage": round(logging, 2),
            "cloudLoggingRetentionBound": round(logging_retention_cost_bound_usd, 2),
            "networkBound": round(network_cost_bound_usd, 2),
            "artifactStorageBound": round(artifact_storage_cost_bound_usd, 2),
            "registryStorageBound": round(registry_storage_cost_bound_usd, 2),
            "rhelSubscriptionBound": round(rhel_subscription_cost_bound_usd, 2),
            "otherBound": round(other_cost_bound_usd, 2),
            "rhelPaygActiveRuntimeScenario": round(rhel_active, 2),
            "rhelPaygSuppliedLicenseHoursScenario": round(rhel_supplied, 2),
            "rhelPaygContinuousScenario": round(rhel_continuous, 2),
            "startupShutdownOperationFee": 0.0,
            "scenarioTotals": {k: round(v, 2) for k, v in scenarios.items()},
            "scenarioTotalsWithReserve": {k: round(v, 2) for k, v in with_reserve.items()},
            "conservativeHighWaterScenario": selected_scenarios[0],
            "conservativeHighWaterUsd": round(conservative_high_water, 2),
        },
        "formulas": {
            "vmComputeUsd": "(3 * Debian total VM-hours + Debian extra-host hours + 3 * RHEL total VM-hours + RHEL extra-host hours) * e2-medium hourly rate",
            "bootDiskUsd": "(Debian + RHEL + both extra-host provisioned disk GiB-hours) * balanced PD rate",
            "snapshotUsd": "stored snapshot GiB-hours * standard snapshot rate",
            "dnsUsd": "90-day private zone hours * zone rate + private DNS queries / 1,000,000 * query rate",
            "loggingUsd": "sum of three project-wide monthly GiB bounds * logging ingestion rate (no free allotment assumed)",
            "loggingRetentionUsd": "owner-supplied bound for retention beyond default log-bucket retention",
            "rhelPaygConservativeUsd": "(3 * 90 * 24 + extra wrong-machine-id host hours per OS) * machine vCPUs * RHEL PAYG core-hour rate",
            "contingencyReserveUsd": "20% * $300 policy ceiling",
            "conservativeHighWaterUsd": "selected RHEL license mode upper-bound scenario + contingency reserve",
        },
        "status": status,
        "limitations": [
            "Public list prices are not actual billing or available credit.",
            "RHEL PAYG charges while stopped require billing-owner confirmation; both cases are modeled.",
            "For PAYG, the selected upper bound charges the three RHEL cluster VMs for the full 90 days and the extra wrong-machine-id host for its bounded scenario runtime. For BYOS, the selected upper bound is the supplied subscription bound. Unselected license scenarios remain visible for comparison.",
            "Network, artifact, registry, BYOS, and other costs are supplied bounds, not independently verified prices.",
            "Logging ingestion is charged at the published rate without assuming any project free allotment remains; retention beyond default is a separate supplied bound.",
            "This report does not enforce a hard spending cap and cannot authorize Terraform planning or apply.",
            "The guarded VM lifecycle commands are separate from this estimator and require live identity checks.",
        ],
        "priceSources": {
            "checkedDate": "2026-11-23",
            "e2": "https://cloud.google.com/products/compute/pricing/general-purpose",
            "disksAndSnapshots": "https://cloud.google.com/compute/disks-image-pricing",
            "dns": "https://cloud.google.com/dns/pricing",
            "logging": "https://cloud.google.com/products/observability/pricing",
            "rhel": "https://cloud.google.com/compute/disks-image-pricing#rhel",
        },
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--machine-type", required=True,
                        choices=sorted(MACHINE_TYPE_PRICES),
                        help="exact selected Terraform machine type")
    result.add_argument("--boot-disk-size-gib", type=float, required=True,
                        help="exact selected Terraform boot_disk_size_gb")
    result.add_argument("--debian-scenario-hours-per-vm", type=float, required=True,
                        help="upper-bound scenario execution hours per Debian cluster VM")
    result.add_argument("--debian-cleanup-restore-hours-per-vm", type=float, required=True,
                        help="upper-bound cleanup and baseline restoration hours per Debian cluster VM")
    result.add_argument("--rhel-scenario-hours-per-vm", type=float, required=True,
                        help="upper-bound scenario execution hours per RHEL cluster VM")
    result.add_argument("--rhel-cleanup-restore-hours-per-vm", type=float, required=True,
                        help="upper-bound cleanup and baseline restoration hours per RHEL cluster VM")
    result.add_argument("--wrong-machine-id-extra-host-hours-per-os", type=float, required=True,
                        help="runtime bound for one additional disposable host during wrong-machine-id on each OS")
    result.add_argument("--rhel-license-mode", choices=("payg", "byos"), required=True,
                        help="selected RHEL license model; PAYG uses the continuous 90-day stopped-instance bound")
    result.add_argument("--rhel-license-hours-per-vm", type=float, required=True,
                        help="upper-bound billable RHEL license hours per VM, including any stopped-instance billing")
    result.add_argument("--snapshot-stored-gib-hours", type=float, required=True,
                        help="upper-bound stored snapshot GiB-hours across all retained snapshots")
    result.add_argument("--debian-boot-disk-gib-hours", type=float, required=True,
                        help="provisioned Debian boot-disk GiB-hours including post-stop retention")
    result.add_argument("--rhel-boot-disk-gib-hours", type=float, required=True,
                        help="provisioned RHEL boot-disk GiB-hours including post-stop retention")
    result.add_argument("--wrong-machine-id-extra-host-disk-gib-hours-per-os", type=float, required=True,
                        help="provisioned extra-host disk GiB-hours per OS profile including retention")
    result.add_argument("--private-dns-query-bound", type=float, required=True,
                        help="upper bound on private Cloud DNS queries over the 90-day period")
    result.add_argument("--monthly-logging-gib", type=float, nargs=3, required=True,
                        metavar=("MONTH1", "MONTH2", "MONTH3"),
                        help="project-wide logging ingestion GiB per 30-day period")
    result.add_argument("--logging-retention-cost-bound-usd", type=float, required=True,
                        help="upper bound on logging retention charges beyond default retention")
    result.add_argument("--network-cost-bound-usd", type=float, required=True)
    result.add_argument("--artifact-storage-cost-bound-usd", type=float, required=True)
    result.add_argument("--registry-storage-cost-bound-usd", type=float, required=True)
    result.add_argument("--rhel-subscription-cost-bound-usd", type=float, required=True,
                        help="external RHEL BYOS subscription cost bound")
    result.add_argument("--other-cost-bound-usd", type=float, required=True)
    result.add_argument("--billing-headroom-usd", type=float,
                        help="customer-supplied value; never independently verified by this command")
    result.add_argument("--output", type=Path)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        report = estimate(
            machine_type=args.machine_type,
            boot_disk_size_gib=args.boot_disk_size_gib,
            debian_scenario_hours_per_vm=args.debian_scenario_hours_per_vm,
            debian_cleanup_restore_hours_per_vm=args.debian_cleanup_restore_hours_per_vm,
            rhel_scenario_hours_per_vm=args.rhel_scenario_hours_per_vm,
            rhel_cleanup_restore_hours_per_vm=args.rhel_cleanup_restore_hours_per_vm,
            wrong_machine_id_extra_host_hours_per_os=args.wrong_machine_id_extra_host_hours_per_os,
            rhel_license_mode=args.rhel_license_mode,
            rhel_license_hours_per_vm=args.rhel_license_hours_per_vm,
            debian_boot_disk_gib_hours=args.debian_boot_disk_gib_hours,
            rhel_boot_disk_gib_hours=args.rhel_boot_disk_gib_hours,
            wrong_machine_id_extra_host_disk_gib_hours_per_os=args.wrong_machine_id_extra_host_disk_gib_hours_per_os,
            snapshot_stored_gib_hours=args.snapshot_stored_gib_hours,
            private_dns_queries=args.private_dns_query_bound,
            monthly_logging_gib=args.monthly_logging_gib,
            logging_retention_cost_bound_usd=args.logging_retention_cost_bound_usd,
            network_cost_bound_usd=args.network_cost_bound_usd,
            artifact_storage_cost_bound_usd=args.artifact_storage_cost_bound_usd,
            registry_storage_cost_bound_usd=args.registry_storage_cost_bound_usd,
            rhel_subscription_cost_bound_usd=args.rhel_subscription_cost_bound_usd,
            other_cost_bound_usd=args.other_cost_bound_usd,
            billing_headroom_usd=args.billing_headroom_usd,
        )
        encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(encoded, encoding="utf-8")
        else:
            sys.stdout.write(encoded)
        return 2 if report["status"] == "BLOCKED_WORST_CASE_EXCEEDS_POLICY_CEILING" else 0
    except (CostModelError, OSError) as error:
        print(f"m3-cost-model: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
