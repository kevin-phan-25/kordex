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

# Public on-demand prices for us-east1, USD. Refresh against the linked
# provider price sheets before any later plan; these are not billing records.
E2_STANDARD_2_PER_HOUR = 0.06701142
PD_BALANCED_GIB_PER_HOUR = 0.000136986
STANDARD_SNAPSHOT_GIB_PER_HOUR = 0.00006849
PRIVATE_DNS_ZONE_PER_HOUR = 0.000273973
RHEL_PAYG_PER_CORE_HOUR = 0.0144  # up to 8 vCPUs
CLOUD_LOGGING_PER_GIB = 0.50


class CostModelError(ValueError):
    pass


def estimate(
    *,
    vm_hours_per_vm: float,
    snapshot_stored_gib_hours: float,
    monthly_logging_gib: Sequence[float],
    network_cost_bound_usd: float,
    artifact_storage_cost_bound_usd: float,
    registry_storage_cost_bound_usd: float,
    rhel_subscription_cost_bound_usd: float,
    other_cost_bound_usd: float,
    billing_headroom_usd: float | None = None,
) -> dict:
    """Return bounded modeled costs, never a customer/billing verification.

    ``vm_hours_per_vm`` includes each VM start's one-minute minimum. Snapshot
    input is actual stored-data GiB-hours, not provisioned disk capacity.
    RHEL is deliberately reported under both active-runtime-only and
    continuous-90-day license assumptions until the billing owner confirms
    the treatment for the selected image/license.
    """
    numeric = {
        "vm_hours_per_vm": vm_hours_per_vm,
        "snapshot_stored_gib_hours": snapshot_stored_gib_hours,
        "network_cost_bound_usd": network_cost_bound_usd,
        "artifact_storage_cost_bound_usd": artifact_storage_cost_bound_usd,
        "registry_storage_cost_bound_usd": registry_storage_cost_bound_usd,
        "rhel_subscription_cost_bound_usd": rhel_subscription_cost_bound_usd,
        "other_cost_bound_usd": other_cost_bound_usd,
    }
    if any(not math.isfinite(value) or value < 0 for value in numeric.values()):
        raise CostModelError("cost inputs must be finite and nonnegative")
    max_hours = DAYS * 24
    if vm_hours_per_vm > max_hours:
        raise CostModelError("per-VM runtime exceeds the 90-day window")
    if len(monthly_logging_gib) != 3 or any(
        not math.isfinite(value) or value < 0 for value in monthly_logging_gib
    ):
        raise CostModelError("provide three finite, nonnegative monthly logging volumes")
    if billing_headroom_usd is not None and (
        not math.isfinite(billing_headroom_usd) or billing_headroom_usd < 0
    ):
        raise CostModelError("billing headroom must be finite and nonnegative")

    vm_compute = 3 * vm_hours_per_vm * E2_STANDARD_2_PER_HOUR
    disk = 3 * 40 * max_hours * PD_BALANCED_GIB_PER_HOUR
    dns = max_hours * PRIVATE_DNS_ZONE_PER_HOUR
    snapshots = snapshot_stored_gib_hours * STANDARD_SNAPSHOT_GIB_PER_HOUR
    # Do not assume the project's free allotment is unused by existing
    # workloads. Charge the full submitted project-wide volume for a bound.
    logging = sum(monthly_logging_gib) * CLOUD_LOGGING_PER_GIB
    rhel_active = 3 * 2 * vm_hours_per_vm * RHEL_PAYG_PER_CORE_HOUR
    rhel_continuous = 3 * 2 * max_hours * RHEL_PAYG_PER_CORE_HOUR
    bounded_variable = (
        logging
        + network_cost_bound_usd
        + artifact_storage_cost_bound_usd
        + registry_storage_cost_bound_usd
        + other_cost_bound_usd
    )
    common = vm_compute + disk + dns + snapshots + bounded_variable
    reserve = CEILING_USD * RESERVE_FRACTION
    scenarios = {
        "rhelLicenseChargedOnlyForRuntime": common + rhel_active,
        "rhelLicenseChargedContinuouslyWhileStopped": common + rhel_continuous,
        "rhelByosSubscription": common + rhel_subscription_cost_bound_usd,
    }
    with_reserve = {name: total + reserve for name, total in scenarios.items()}
    if billing_headroom_usd is None:
        status = "BLOCKED_BILLING_HEADROOM_NOT_PROVIDED"
    elif max(with_reserve.values()) > CEILING_USD:
        status = "BLOCKED_WORST_CASE_EXCEEDS_POLICY_CEILING"
    elif max(with_reserve.values()) > billing_headroom_usd:
        status = "BLOCKED_WORST_CASE_EXCEEDS_REPORTED_HEADROOM_PENDING_VERIFICATION"
    else:
        # A caller-supplied number cannot establish billing headroom. This
        # status intentionally never becomes VERIFIED or APPROVED.
        status = "MODELED_WITHIN_CEILING_PENDING_INDEPENDENT_COST_AND_BILLING_VERIFICATION"

    return {
        "schemaVersion": 1,
        "projectId": PROJECT_ID,
        "projectNumber": PROJECT_NUMBER,
        "region": REGION,
        "periodDays": DAYS,
        "policyCeilingUsd": CEILING_USD,
        "reserveFraction": RESERVE_FRACTION,
        "reserveUsd": round(reserve, 2),
        "inputs": {
            "vmHoursPerVm": vm_hours_per_vm,
            "snapshotStoredGiBHours": snapshot_stored_gib_hours,
            "monthlyLoggingGiB": list(monthly_logging_gib),
            "networkCostBoundUsd": network_cost_bound_usd,
            "artifactStorageCostBoundUsd": artifact_storage_cost_bound_usd,
            "registryStorageCostBoundUsd": registry_storage_cost_bound_usd,
            "rhelSubscriptionCostBoundUsd": rhel_subscription_cost_bound_usd,
            "otherCostBoundUsd": other_cost_bound_usd,
            "billingHeadroomUsd": billing_headroom_usd,
        },
        "costsUsd": {
            "vmCompute": round(vm_compute, 2),
            "persistentBalancedBootDisks": round(disk, 2),
            "privateDnsZone": round(dns, 2),
            "privateVPCAndFirewallResources": 0.0,
            "standardSnapshots": round(snapshots, 2),
            "cloudLoggingOverage": round(logging, 2),
            "networkBound": round(network_cost_bound_usd, 2),
            "artifactStorageBound": round(artifact_storage_cost_bound_usd, 2),
            "registryStorageBound": round(registry_storage_cost_bound_usd, 2),
            "rhelSubscriptionBound": round(rhel_subscription_cost_bound_usd, 2),
            "otherBound": round(other_cost_bound_usd, 2),
            "rhelPaygActiveRuntimeScenario": round(rhel_active, 2),
            "rhelPaygContinuousScenario": round(rhel_continuous, 2),
            "startupShutdownOperationFee": 0.0,
            "scenarioTotals": {k: round(v, 2) for k, v in scenarios.items()},
            "scenarioTotalsWithReserve": {k: round(v, 2) for k, v in with_reserve.items()},
        },
        "status": status,
        "limitations": [
            "Public list prices are not actual billing or available credit.",
            "RHEL PAYG charges while stopped require billing-owner confirmation; both cases are modeled.",
            "Network, artifact, registry, BYOS, and other costs are supplied bounds, not independently verified prices.",
            "Logging is charged at the published rate without assuming any project free allotment remains.",
            "This report does not enforce a hard spending cap and cannot authorize Terraform planning or apply.",
            "VM stop/start is not implemented by this estimator.",
        ],
        "priceSources": {
            "checkedDate": "2026-11-22",
            "e2": "https://cloud.google.com/products/compute/pricing/general-purpose",
            "disksAndSnapshots": "https://cloud.google.com/compute/disks-image-pricing",
            "dns": "https://cloud.google.com/dns/pricing",
            "logging": "https://cloud.google.com/products/observability/pricing",
            "rhel": "https://cloud.google.com/compute/docs/images/premium/rhel-faq",
        },
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--vm-hours-per-vm", type=float, required=True,
                        help="upper-bound running hours per VM over the 90-day window")
    result.add_argument("--snapshot-stored-gib-hours", type=float, required=True,
                        help="upper-bound stored snapshot GiB-hours across all retained snapshots")
    result.add_argument("--monthly-logging-gib", type=float, nargs=3, required=True,
                        metavar=("MONTH1", "MONTH2", "MONTH3"),
                        help="project-wide logging ingestion GiB per 30-day period")
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
            vm_hours_per_vm=args.vm_hours_per_vm,
            snapshot_stored_gib_hours=args.snapshot_stored_gib_hours,
            monthly_logging_gib=args.monthly_logging_gib,
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
        return 0
    except (CostModelError, OSError) as error:
        print(f"m3-cost-model: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
