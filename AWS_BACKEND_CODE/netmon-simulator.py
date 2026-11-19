"""NetMon Simulator — configurable CPU/RAM update cadence.

EventBridge Scheduler MUST invoke this function at rate(1 minute), flexible window OFF.
Reads intervalMinutes (1..60) from NetworkSettings/settingKey=simulation.
Only updates explicit SIMULATED devices. EC2 CloudWatch measurements are never touched.
DynamoDB Streams -> netmon-device-monitor remains responsible for SNS alerts.

Test events (Lambda test, NOT EventBridge schedule payload):
  {"dryRun": true}             # Preview eligible devices due now
  {"forceRun": true}           # Force refresh simulated devices
  {"deviceId": "SW001", "forcePeak": true} # One-device alert test
  {"deviceId": "SW001", "forceNormal": true}
"""
import datetime as dt
import os
import random
from decimal import Decimal

import boto3
from botocore.exceptions import ClientError

DYNAMO = boto3.resource("dynamodb")
DEVICES = DYNAMO.Table(os.getenv("DEVICES_TABLE", "NetworkDevices"))
SETTINGS = DYNAMO.Table(os.getenv("SETTINGS_TABLE", "NetworkSettings"))
MAX_DEVICES = 100
DEFAULT_INTERVAL_MINUTES = 5


def configured_interval():
    data = SETTINGS.get_item(
        Key={"settingKey": "simulation"}, ConsistentRead=True
    ).get("Item") or {}
    try:
        minutes = int(data.get("intervalMinutes", DEFAULT_INTERVAL_MINUTES))
        if minutes not in range(1, 61):
            return DEFAULT_INTERVAL_MINUTES
        return minutes
    except (TypeError, ValueError, OverflowError):
        return DEFAULT_INTERVAL_MINUTES


def all_devices():
    params = {}
    scanned = 0
    while True:
        page = DEVICES.scan(**params)
        for row in page.get("Items", []):
            if str(row.get("metricsSource") or "").upper() != "SIMULATED":
                continue
            if row.get("instanceId") or str(row.get("monitoringSource") or "").upper() == "CLOUDWATCH":
                continue
            yield row
            scanned += 1
            if scanned >= MAX_DEVICES:
                return
        if "LastEvaluatedKey" not in page:
            return
        params["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def next_value(current, peak=False, normal=False):
    if peak:
        return random.randint(90, 97)
    if normal:
        return random.randint(25, 45)
    try:
        old = int(Decimal(str(current)))
    except (TypeError, ValueError, ArithmeticError):
        old = random.randint(30, 55)
    if random.random() < 0.12:
        return random.randint(83, 95)
    return max(15, min(78, old + random.randint(-14, 14)))


def is_due(device, cutoff, force=False):
    if force:
        return True
    last = device.get("lastSimulatedAt")
    if not last:
        return True
    try:
        when = dt.datetime.fromisoformat(str(last).replace("Z", "+00:00"))
        if when.tzinfo is None:
            return True
        return when <= cutoff
    except (ValueError, TypeError):
        return True


def lambda_handler(event, context):
    event = event or {}
    only = str(event.get("deviceId") or "")
    dry_run = event.get("dryRun") is True
    peak = event.get("forcePeak") is True
    normal = event.get("forceNormal") is True
    force = event.get("forceRun") is True or peak or normal
    if peak and normal:
        return {"statusCode": 400, "error": "Cannot forcePeak and forceNormal together"}
    minutes = configured_interval()
    now = dt.datetime.now(dt.timezone.utc)
    cutoff = now - dt.timedelta(minutes=minutes)
    now_iso, cutoff_iso = now.isoformat(), cutoff.isoformat()
    summary = {
        "checked": 0, "due": 0, "updated": 0, "skippedInterval": 0,
        "intervalMinutes": minutes, "dryRun": dry_run, "samples": []
    }
    for device in all_devices():
        device_id = str(device["deviceId"])
        if only and only != device_id:
            continue
        summary["checked"] += 1
        if not is_due(device, cutoff, force):
            summary["skippedInterval"] += 1
            continue
        summary["due"] += 1
        cpu = next_value(device.get("cpuUsage"), peak=peak, normal=normal)
        ram = next_value(device.get("memoryUsage"), peak=peak, normal=normal)
        if len(summary["samples"]) < 10:
            summary["samples"].append({"deviceId": device_id, "cpu": cpu, "ram": ram})
        if dry_run:
            continue
        condition = (
            "attribute_exists(deviceId) AND metricsSource = :sim "
            "AND attribute_not_exists(instanceId) "
            "AND (attribute_not_exists(monitoringSource) OR monitoringSource <> :cloud)"
        )
        if not force:
            # Server-side check prevents two overlapping Scheduler invocations
            # from updating same device before its configured interval.
            condition += " AND (attribute_not_exists(lastSimulatedAt) OR lastSimulatedAt <= :cutoff)"
        values = {
            ":cpu": Decimal(cpu), ":ram": Decimal(ram),
            ":now": now_iso, ":sim": "SIMULATED", ":cloud": "CLOUDWATCH"
        }
        if not force:
            values[":cutoff"] = cutoff_iso
        try:
            DEVICES.update_item(
                Key={"deviceId": device_id},
                UpdateExpression=(
                    "SET cpuUsage=:cpu, memoryUsage=:ram, "
                    "lastUpdated=:now, lastSimulatedAt=:now"
                ),
                ConditionExpression=condition,
                ExpressionAttributeValues=values,
            )
            summary["updated"] += 1
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                summary["skippedInterval"] += 1
                continue
            raise
    return {"statusCode": 200, "body": summary}
