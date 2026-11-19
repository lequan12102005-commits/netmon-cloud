
"""
NetMon Cloud - API Gateway
Handler: lambda_function.lambda_handler

Chuc nang:
- Quan ly thiet bi: GET, POST, PUT, DELETE
- Quan ly canh bao: GET, PUT
- Lay CPU/RAM/Network tu CloudWatch
- Xem nhat ky AWS: GET /logs
- Doc cau hinh: GET /settings
- Luu cau hinh: PUT /settings
"""

import os
import json
import uuid
import base64
import random
import re
import datetime as dt

from decimal import Decimal, InvalidOperation

import boto3

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError


# ==================================================
# 1. CAU HINH AWS
# ==================================================

db = boto3.resource("dynamodb")

devices = db.Table(
    os.getenv("DEVICES_TABLE", "NetworkDevices")
)

alerts = db.Table(
    os.getenv("ALERTS_TABLE", "NetworkAlerts")
)

audit_logs = db.Table(
    os.getenv("AUDIT_LOGS_TABLE", "NetworkAuditLogs")
)

settings = db.Table(
    os.getenv("SETTINGS_TABLE", "NetworkSettings")
)

cloudwatch = boto3.client("cloudwatch")

# [SNS-STATUS] Khong gui email tu API nay; chi xac minh Topic va Subscription.
sns_status_client = boto3.client("sns")
SNS_STATUS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN", "").strip()



# ==================================================
# 2. CHUYEN DU LIEU DYNAMODB THANH JSON
# ==================================================

class DynamoEncoder(json.JSONEncoder):

    def default(self, value):

        if isinstance(value, Decimal):
            return float(value)

        return super().default(value)


def respond(status, payload):

    return {
        "statusCode": status,

        "headers": {
            "Content-Type": "application/json",

            "Access-Control-Allow-Origin": os.getenv(
                "CORS_ORIGIN",
                "http://localhost:5500"
            ),

            "Access-Control-Allow-Headers":
                "Content-Type,Authorization",

            "Access-Control-Allow-Methods":
                "GET,POST,PUT,DELETE,OPTIONS",

            "X-Netmon-Build":
                "netmon-cloud"
        },

        "body": json.dumps(
            payload,
            cls=DynamoEncoder,
            ensure_ascii=False
        )
    }


def utc_now():

    return dt.datetime.now(
        dt.timezone.utc
    ).isoformat()


# ==================================================
# 3. DOC TOAN BO DU LIEU DYNAMODB
# ==================================================

def scan_all(table):

    result = []
    args = {}

    while True:

        page = table.scan(**args)

        result.extend(
            page.get("Items", [])
        )

        if "LastEvaluatedKey" not in page:
            return result

        args["ExclusiveStartKey"] = (
            page["LastEvaluatedKey"]
        )


# ==================================================
# 4. KIEM TRA CPU / RAM
# ==================================================

def percentage(value):

    if isinstance(value, bool):
        raise ValueError(
            "CPU/RAM must be a number from 0 to 100"
        )

    try:
        number = Decimal(str(value))

    except (InvalidOperation, TypeError, ValueError):
        raise ValueError(
            "CPU/RAM must be a number from 0 to 100"
        )

    if (
        not number.is_finite()
        or not 0 <= number <= 100
    ):
        raise ValueError(
            "CPU/RAM must be between 0 and 100"
        )

    return number


def is_ec2_device(item):

    return bool(
        item.get("instanceId")

        or str(
            item.get("monitoringSource") or ""
        ).upper() == "CLOUDWATCH"

        # [AUTO-SIM] Khong de dong thiet bi da gan CloudWatch
        # bi hieu nham thanh mo phong khi thieu instanceId.
        or str(
            item.get("metricsSource") or ""
        ).upper() == "CLOUDWATCH"
    )


def register_ec2(item, device_id=None):
    """Verify an existing EC2 in the deployment region; never launch an instance."""
    instance_id = str(item.get("instanceId") or "").strip()
    if not re.fullmatch(r"i-(?:[0-9a-f]{8}|[0-9a-f]{17})", instance_id):
        raise ValueError("EC2 Instance ID khong hop le")
    region = os.getenv("AWS_REGION", "us-east-1")
    if item.get("region") and item["region"] != region:
        raise ValueError("EC2 phai cung region voi API: " + region)
    for row in scan_all(devices):
        if row.get("instanceId") == instance_id and row.get("deviceId") != device_id:
            raise ValueError("EC2 nay da duoc dang ky trong NetMon")
    try:
        response = boto3.client("ec2", region_name=region).describe_instances(InstanceIds=[instance_id])
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "")
        if code in ("InvalidInstanceID.NotFound", "InvalidInstanceID.Malformed"):
            raise ValueError("Khong tim thay EC2 trong AWS region " + region) from error
        raise
    matches = [instance for res in response.get("Reservations", [])
               for instance in res.get("Instances", []) if instance.get("InstanceId") == instance_id]
    if not matches or matches[0].get("State", {}).get("Name") in ("terminated", "shutting-down"):
        raise ValueError("EC2 khong ton tai hoac da terminate")
    instance = matches[0]
    item.update(deviceType="EC2", instanceId=instance_id, region=region,
                metricsSource="CLOUDWATCH", monitoringSource="CLOUDWATCH")
    if not str(item.get("ipAddress") or "").strip():
        item["ipAddress"] = instance.get("PrivateIpAddress", "")
    if instance.get("VpcId"):
        item["vpcId"] = instance["VpcId"]
    return item


# ==================================================
# 5. LAY DU LIEU CLOUDWATCH
# ==================================================

def cloudwatch_points(namespace, name, instance_id, statistic="Average", minutes=45, period=300):
    """Return sorted real CloudWatch points; never fill gaps with fake values.

    EC2 Basic Monitoring naturally publishes most metrics about every 5 min.
    A Period of 300 does not enable paid Detailed Monitoring.
    """
    end = dt.datetime.now(dt.timezone.utc)
    start = end - dt.timedelta(minutes=minutes)
    response = cloudwatch.get_metric_statistics(
        Namespace=namespace,
        MetricName=name,
        Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
        StartTime=start,
        EndTime=end,
        Period=period,
        Statistics=[statistic]
    )
    result = []
    for point in response.get("Datapoints", []):
        if statistic not in point or not point.get("Timestamp"):
            continue
        result.append({
            "time": point["Timestamp"].astimezone(dt.timezone.utc).isoformat(),
            "value": round(float(point[statistic]), 2),
        })
    return sorted(result, key=lambda point: point["time"])


def latest_metric(namespace, name, instance_id, statistic="Average", with_time=False):
    """Backward compatible numeric result; optionally include AWS sample time."""
    points = cloudwatch_points(namespace, name, instance_id, statistic, 45, 300)
    item = points[-1] if points else None
    if item is not None or namespace != "CWAgent":
        return item if with_time else (item["value"] if item else None)

    # Keep the historical CloudWatch Agent dimensions fallback.
    try:
        response = cloudwatch.list_metrics(
            Namespace=namespace,
            MetricName=name,
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}]
        )
        end = dt.datetime.now(dt.timezone.utc)
        start = end - dt.timedelta(minutes=45)
        for metric in response.get("Metrics", [])[:5]:
            dimensions = metric.get("Dimensions") or []
            if not dimensions:
                continue
            result = cloudwatch.get_metric_statistics(
                Namespace=namespace, MetricName=name, Dimensions=dimensions,
                StartTime=start, EndTime=end, Period=300, Statistics=[statistic]
            ).get("Datapoints", [])
            if result:
                newest = max(result, key=lambda value: value["Timestamp"])
                item = {
                    "time": newest["Timestamp"].astimezone(dt.timezone.utc).isoformat(),
                    "value": round(float(newest[statistic]), 2)
                }
                return item if with_time else item["value"]
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        if code not in ("AccessDenied", "AccessDeniedException"):
            raise
        print("Missing cloudwatch:ListMetrics permission")
    return None


def ec2_history(instance_id, minutes):
    """Real CloudWatch history 15min–24h. EC2 Basic uses 5-minute points.

    Custom RAM is read at 60s for short windows, 300s for long ones.
    Period is a *query aggregation*, not the metric publication interval.
    No extra EC2 Detailed Monitoring is activated.
    """
    ram_period = 60 if minutes <= 60 else 300
    cpu_points = cloudwatch_points(
        "AWS/EC2", "CPUUtilization", instance_id, minutes=minutes, period=300
    )
    ram_points = cloudwatch_points(
        "NetMon/EC2", "mem_used_percent", instance_id, minutes=minutes, period=ram_period
    )
    merged = {}
    for point in cpu_points:
        merged.setdefault(point["time"], {"time": point["time"], "cpu": None, "ram": None})["cpu"] = point["value"]
    for point in ram_points:
        merged.setdefault(point["time"], {"time": point["time"], "cpu": None, "ram": None})["ram"] = point["value"]
    return {
        "instanceId": instance_id,
        "historyMinutes": minutes,
        "periodSeconds": {"cpu": 300, "ram": ram_period},
        "samples": {"cpu": len(cpu_points), "ram": len(ram_points)},
        "history": [merged[key] for key in sorted(merged)],
        "source": "CloudWatch",
        "checkedAt": utc_now(),
    }


# ==================================================
# 6. TONG HOP METRICS THIET BI
# ==================================================

def collect_metrics():

    result = []

    for item in scan_all(devices):

        metric = {
            "deviceId": item["deviceId"],
            "cpuUsage": None,
            "memoryUsage": None,
            "networkIn": None,
            "networkOut": None
        }

        # ------------------------------------------
        # THIET BI MO PHONG
        # ------------------------------------------

        if not is_ec2_device(item):

            metric["source"] = "SIMULATED"

            for key in (
                "cpuUsage",
                "memoryUsage"
            ):

                if item.get(key) is not None:

                    metric[key] = float(
                        item[key]
                    )

        # ------------------------------------------
        # THIET BI EC2 - DU LIEU THAT
        # ------------------------------------------

        else:

            metric["source"] = "CLOUDWATCH"

            instance_id = item.get(
                "instanceId"
            )

            if instance_id:

                # Capture actual CloudWatch Timestamp for each metric separately.
                # Basic Monitoring remains 5 minutes; this does not enable Detailed Monitoring.
                samples = {
                    "cpu": latest_metric("AWS/EC2", "CPUUtilization", instance_id, with_time=True),
                    "ram": latest_metric("NetMon/EC2", "mem_used_percent", instance_id, with_time=True),
                    "networkIn": latest_metric("AWS/EC2", "NetworkIn", instance_id, "Sum", with_time=True),
                    "networkOut": latest_metric("AWS/EC2", "NetworkOut", instance_id, "Sum", with_time=True),
                }
                metric["instanceId"] = instance_id
                for field, key in (
                    ("cpuUsage", "cpu"), ("memoryUsage", "ram"),
                    ("networkIn", "networkIn"), ("networkOut", "networkOut")
                ):
                    metric[field] = samples[key]["value"] if samples[key] else None
                metric["sampleTimes"] = {
                    key: value["time"] if value else None for key, value in samples.items()
                }
                measured = [value["time"] for value in samples.values() if value]
                metric["sampleTime"] = max(measured) if measured else None
                # Stale only if all returned samples are old. Caller displays each timestamp.
                if measured:
                    newest = dt.datetime.fromisoformat(max(measured))
                    metric["stale"] = (dt.datetime.now(dt.timezone.utc) - newest).total_seconds() > 20 * 60
                else:
                    metric["stale"] = True

        result.append(metric)

    return result


# ==================================================
# 7. LAMBDA HANDLER
# ==================================================

# Luu y:
# Cac route API that phai duoc bao ve
# bang JWT Authorizer tai API Gateway.

def lambda_handler(event, context):

    event = event or {}

    try:

        method = (
            event.get("requestContext", {})
            .get("http", {})
            .get("method")

            or event.get("httpMethod")

            or "GET"
        ).upper()

        path = (
            event.get("rawPath")

            or event.get("path")

            or "/"
        )

        if method == "OPTIONS":
            return respond(204, {})

        raw_body = (
            event.get("body") or "{}"
        )

        if event.get("isBase64Encoded"):

            raw_body = base64.b64decode(
                raw_body
            ).decode("utf-8")

        body = (
            json.loads(raw_body)
            if isinstance(raw_body, str)
            else raw_body
        )

        if not isinstance(body, dict):

            return respond(
                400,
                {
                    "error":
                        "JSON body must be an object"
                }
            )

        # ==========================================
        # 8. GET /devices
        # ==========================================

        if (
            path == "/devices"
            and method == "GET"
        ):

            return respond(
                200,
                scan_all(devices)
            )

        # ==========================================
        # 9. POST /devices
        # ==========================================

        if (
            path == "/devices"
            and method == "POST"
        ):

            item = {
                "deviceId": str(
                    body.get("deviceId") or uuid.uuid4()
                ),

                "deviceName": str(
                    body.get("deviceName") or ""
                ).strip(),

                "deviceType": str(
                    body.get("deviceType") or "Other"
                ),

                "ipAddress": str(
                    body.get("ipAddress") or ""
                ),

                "location": str(
                    body.get("location") or ""
                ),

                "status": str(
                    body.get("status") or "ONLINE"
                ).upper(),

                "lastUpdated": utc_now()
            }

            if not item["deviceName"]:

                return respond(
                    400,
                    {"error": "deviceName required"}
                )

            for field in (
                "instanceId",
                "region",
                "monitoringSource",
                "vpcId"
            ):

                if body.get(field) is not None:

                    item[field] = str(
                        body[field]
                    )

            if is_ec2_device(item) or item["deviceType"].strip().upper() == "EC2" or str(body.get("metricsSource") or "").upper() == "CLOUDWATCH":
                if any(body.get(key) not in (None, "") for key in ("cpuUsage", "memoryUsage")):
                    return respond(400, {"error": "EC2 metrics come from CloudWatch"})
                register_ec2(item)

            else:

                cpu = body.get("cpuUsage")
                ram = body.get("memoryUsage")

                # Neu khong nhap CPU/RAM thi tu sinh.
                item["cpuUsage"] = (
                    random.randint(20, 65)

                    if cpu in (None, "")

                    else percentage(cpu)
                )

                item["memoryUsage"] = (
                    random.randint(30, 70)

                    if ram in (None, "")

                    else percentage(ram)
                )

                # [AUTO-SIM] Moi thiet bi khong phai EC2/CLOUDWATCH
                # deu duoc simulator cap nhat dinh ky, ke ca khi
                # nguoi dung nhap CPU/RAM luc them thiet bi.
                # Gia tri nhap ban dau la gia tri khoi tao;
                # netmon-simulator se ghi de o lan chay tiep theo.
                item["metricsSource"] = "SIMULATED"

            devices.put_item(
                Item=item,

                ConditionExpression=(
                    "attribute_not_exists(deviceId)"
                )
            )

            return respond(201, item)

        # ==========================================
        # 10. GET / PUT / DELETE /devices/{id}
        # ==========================================

        if path.startswith("/devices/"):

            device_id = path[
                len("/devices/"):
            ]

            if (
                not device_id
                or "/" in device_id
            ):

                return respond(
                    404,
                    {"error": "Invalid device path"}
                )

            # Xem chi tiet thiet bi
            if method == "GET":

                item = devices.get_item(
                    Key={
                        "deviceId": device_id
                    }
                ).get("Item")

                if not item:
                    return respond(
                        404,
                        {"error": "Device not found"}
                    )

                return respond(200, item)

            # Xoa thiet bi
            if method == "DELETE":

                devices.delete_item(
                    Key={
                        "deviceId": device_id
                    },

                    ConditionExpression=(
                        "attribute_exists(deviceId)"
                    )
                )

                return respond(
                    200,
                    {"deleted": device_id}
                )

            # Sua thiet bi
            if method == "PUT":

                allowed = (
                    "deviceName",
                    "deviceType",
                    "ipAddress",
                    "location",
                    "status",
                    "cpuUsage",
                    "memoryUsage",
                    "instanceId",
                    "region",
                    "monitoringSource",
                    "vpcId"
                )

                fields = {
                    key: body[key]

                    for key in allowed

                    if key in body
                }

                existing = devices.get_item(
                    Key={
                        "deviceId": device_id
                    }
                ).get("Item")

                if not existing:

                    return respond(
                        404,
                        {"error": "Device not found"}
                    )

                # EC2 linkage is immutable once registered. A legacy simulated EC2
                # can be repaired by entering a verified Instance ID.
                linked = bool(existing.get("instanceId"))
                candidate = {**existing, **fields}
                wants_ec2 = (is_ec2_device(candidate) or is_ec2_device(existing)
                             or str(candidate.get("deviceType") or "").strip().upper() == "EC2")
                remove_metrics = False
                if linked:
                    if any(key in fields and fields[key] != existing.get(key) for key in ("instanceId", "region", "monitoringSource")):
                        return respond(400, {"error": "EC2 linkage cannot be changed; register a new device"})
                    if "deviceType" in fields and fields["deviceType"] not in (existing.get("deviceType"), "EC2"):
                        return respond(400, {"error": "EC2 device type cannot be changed"})
                if wants_ec2:
                    if any(fields.get(key) not in (None, "") for key in ("cpuUsage", "memoryUsage")):
                        return respond(400, {"error": "EC2 metrics come from CloudWatch"})
                    for key in ("cpuUsage", "memoryUsage"):
                        fields.pop(key, None)
                    if not linked:
                        register_ec2(candidate, device_id)
                        for key in ("deviceType", "instanceId", "region", "metricsSource", "monitoringSource", "ipAddress", "vpcId"):
                            if key in candidate:
                                fields[key] = candidate[key]
                        remove_metrics = True
                else:
                    # Do not store empty instanceId on simulated records.
                    for key in ("instanceId", "region", "monitoringSource"):
                        fields.pop(key, None)
                    for key in ("cpuUsage", "memoryUsage"):
                        if key in fields:
                            if fields[key] in (None, ""):
                                del fields[key]
                            else:
                                fields[key] = percentage(fields[key])

                if not fields:

                    return respond(
                        400,
                        {"error": "No valid fields"}
                    )

                if "status" in fields:

                    fields["status"] = str(
                        fields["status"]
                    ).upper()

                fields["lastUpdated"] = utc_now()

                names = {
                    f"#f{i}": key

                    for i, key in enumerate(fields)
                }

                values = {
                    f":v{i}": value

                    for i, value in enumerate(
                        fields.values()
                    )
                }

                expression = "SET " + ", ".join(
                    f"#f{i}=:v{i}"

                    for i in range(len(fields))
                )

                if remove_metrics:
                    stale_keys = ("cpuUsage", "memoryUsage", "lastSimulatedAt", "simCpuAlarmActive", "simRamAlarmActive")
                    remove_names = {f"#old{i}": key for i, key in enumerate(stale_keys)}
                    names.update(remove_names)
                    expression += " REMOVE " + ", ".join(remove_names)

                updated = devices.update_item(
                    Key={
                        "deviceId": device_id
                    },

                    UpdateExpression=expression,

                    ExpressionAttributeNames=names,

                    ExpressionAttributeValues=values,

                    ConditionExpression=(
                        "attribute_exists(deviceId)"
                    ),

                    ReturnValues="ALL_NEW"
                )

                return respond(
                    200,
                    updated["Attributes"]
                )

        # ==========================================
        # 11. GET /alerts
        # ==========================================

        if (
            path == "/alerts"
            and method == "GET"
        ):

            rows = sorted(
                scan_all(alerts),

                key=lambda item: item.get(
                    "eventTime",
                    ""
                ),

                reverse=True
            )

            return respond(200, rows)

        # ==========================================
        # 12. PUT /alerts/{id}
        # ==========================================

        if (
            path.startswith("/alerts/")
            and method == "PUT"
        ):

            event_id = path[
                len("/alerts/"):
            ]

            status = body.get(
                "handlingStatus"
            )

            if status not in (
                "New",
                "Acknowledged",
                "Resolved"
            ):

                return respond(
                    400,
                    {
                        "error":
                            "Invalid handlingStatus"
                    }
                )

            updated = alerts.update_item(
                Key={
                    "eventId": event_id
                },

                UpdateExpression=(
                    "SET handlingStatus=:s, "
                    "updatedAt=:t"
                ),

                ExpressionAttributeValues={
                    ":s": status,
                    ":t": utc_now()
                },

                ConditionExpression=(
                    "attribute_exists(eventId)"
                ),

                ReturnValues="ALL_NEW"
            )

            return respond(
                200,
                updated["Attributes"]
            )

        # ==========================================
        # 13. GET /logs - NHAT KY AWS
        # ==========================================

        # Doc du lieu tu NetworkAuditLogs.
        # netmon-audit-writer la Lambda ghi nhat ky.
        # API nay chi doc, khong sua nhat ky.

        if (
            path == "/logs"
            and method == "GET"
        ):

            query = (
                event.get("queryStringParameters")
                or {}
            )

            try:

                limit = int(
                    query.get("limit", "100")
                )

            except (ValueError, TypeError):

                return respond(
                    400,
                    {"error": "Invalid limit"}
                )

            if not 1 <= limit <= 200:

                return respond(
                    400,
                    {
                        "error":
                            "limit must be between 1 and 200"
                    }
                )

            page = audit_logs.query(
                KeyConditionExpression=(
                    Key("logType").eq("DEVICE")
                ),

                ScanIndexForward=False,

                Limit=limit
            )

            rows = page.get(
                "Items",
                []
            )

            return respond(
                200,
                {
                    "items": rows,
                    "count": len(rows),
                    "hasMore": (
                        "LastEvaluatedKey" in page
                    )
                }
            )

        # ==========================================
        # 14. GET /settings
        # ==========================================

        # Lay nguong CPU/RAM tu NetworkSettings.

        if (
            path == "/settings"
            and method == "GET"
        ):

            item = settings.get_item(
                Key={
                    "settingKey": "thresholds"
                },

                ConsistentRead=True
            ).get("Item") or {}

            return respond(
                200,
                {
                    "cpuThreshold": int(
                        item.get("cpuThreshold", 80)
                    ),

                    "ramThreshold": int(
                        item.get("ramThreshold", 80)
                    ),

                    "updatedAt": item.get(
                        "updatedAt"
                    ),

                    "updatedBy": item.get(
                        "updatedBy"
                    ),

                    "source": "NetworkSettings"
                }
            )

        # ==========================================
        # 15. PUT /settings
        # ==========================================

        # Luu nguong CPU/RAM rieng biet.
        # Route nay phai duoc bao ve bang JWT
        # scope netmon-api/write tai API Gateway.

        if (
            path == "/settings"
            and method == "PUT"
        ):

            cpu = body.get(
                "cpuThreshold"
            )

            ram = body.get(
                "ramThreshold"
            )

            if (
                type(cpu) is not int
                or type(ram) is not int
                or not 1 <= cpu <= 99
                or not 1 <= ram <= 99
            ):

                return respond(
                    400,
                    {
                        "error":
                            "CPU/RAM thresholds must be integers 1-99"
                    }
                )

            claims = (
                event.get("requestContext", {})
                .get("authorizer", {})
                .get("jwt", {})
                .get("claims", {})
            )

            updated_at = utc_now()

            updated_by = str(
                claims.get("sub") or "Unknown"
            )[:120]

            item = {
                "settingKey": "thresholds",

                "cpuThreshold": cpu,

                "ramThreshold": ram,

                "updatedAt": updated_at,

                "updatedBy": updated_by
            }

            settings.put_item(
                Item=item
            )

            return respond(
                200,
                {
                    "cpuThreshold": cpu,

                    "ramThreshold": ram,

                    "updatedAt": updated_at,

                    "updatedBy": updated_by,

                    "source": "NetworkSettings"
                }
            )

        # ==========================================
        # 16. GET /metrics
        # ==========================================

        if path == "/metrics" and method == "GET":
            params = event.get("queryStringParameters") or {}
            # Optional history mode reuses the EXISTING authorized GET /metrics route.
            # No history calls in the normal 30/60/120-second website refresh.
            if "historyMinutes" in params:
                try:
                    minutes = int(params["historyMinutes"])
                except (TypeError, ValueError):
                    return respond(400, {"error": "historyMinutes must be an integer 15-1440"})
                if not 15 <= minutes <= 1440:
                    return respond(400, {"error": "historyMinutes must be between 15 and 1440"})
                instance_id = str(params.get("instanceId") or "").strip()
                if not instance_id:
                    return respond(400, {"error": "instanceId required"})
                # Only registered EC2 instances: avoid arbitrary public metric queries.
                valid_ids = {
                    str(item.get("instanceId")) for item in scan_all(devices)
                    if item.get("instanceId") and is_ec2_device(item)
                }
                if instance_id not in valid_ids:
                    return respond(404, {"error": "Registered EC2 instance not found"})
                return respond(200, ec2_history(instance_id, minutes))
            return respond(200, collect_metrics())

        # ==========================================
        # [SNS-STATUS] GET /sns/status (read only)
        # Dung netmon-jwt-authorizer, scope netmon-api/read o API Gateway.
        # Topic da cau hinh + >=1 email subscription Confirmed -> ready.
        # Khong hien dia chi email; khong khang dinh thu da den Gmail.
        # ==========================================
        if path == "/sns/status" and method == "GET":
            if not SNS_STATUS_TOPIC_ARN:
                return respond(200, {
                    "configured": False,
                    "topicArn": None,
                    "confirmedEmailSubscriptions": 0,
                    "deliveryVerified": False,
                    "checkedAt": utc_now(),
                    "message": "Missing SNS_TOPIC_ARN in netmon-api environment"
                })

            # SNS se bao loi neu topic khong ton tai / role chua co quyen.
            sns_status_client.get_topic_attributes(
                TopicArn=SNS_STATUS_TOPIC_ARN
            )

            confirmed = 0
            paginator = sns_status_client.get_paginator(
                "list_subscriptions_by_topic"
            )
            for page in paginator.paginate(TopicArn=SNS_STATUS_TOPIC_ARN):
                for subscription in page.get("Subscriptions", []):
                    # SNS email va email-json deu su dung email subscription.
                    protocol = str(subscription.get("Protocol", "")).lower()
                    subscription_arn = subscription.get("SubscriptionArn")
                    if protocol in ("email", "email-json") and subscription_arn not in (
                        None, "", "PendingConfirmation", "Deleted"
                    ):
                        confirmed += 1

            return respond(200, {
                "configured": True,
                "topicArn": SNS_STATUS_TOPIC_ARN,
                "confirmedEmailSubscriptions": confirmed,
                "deliveryVerified": False,
                "checkedAt": utc_now(),
                "message": (
                    "Topic ready with confirmed email subscriptions"
                    if confirmed > 0
                    else "No confirmed email subscription for this topic"
                )
            })

        # ==========================================
        # [SIMULATION-CONFIG] GET /simulation/config - Doc chu ky mo phong
        # [SIMULATION-CONFIG] PUT /simulation/config - Luu chu ky (scope write)
        # Gia tri luu rieng tai NetworkSettings: settingKey=simulation.
        # KHONG thay doi CloudWatch EC2 hoac CloudWatch Alarms.
        # ==========================================
        if path == "/simulation/config" and method == "GET":
            saved = settings.get_item(
                Key={"settingKey": "simulation"}, ConsistentRead=True
            ).get("Item") or {}
            interval = int(saved.get("intervalMinutes", 5))
            if not 1 <= interval <= 60:
                interval = 5
            return respond(200, {
                "intervalMinutes": interval,
                "updatedAt": saved.get("updatedAt"),
                "updatedBy": saved.get("updatedBy"),
                "source": "NetworkSettings",
                "schedulerRequired": "rate(1 minute)",
            })

        if path == "/simulation/config" and method == "PUT":
            interval = body.get("intervalMinutes")
            if type(interval) is not int or not 1 <= interval <= 60:
                return respond(400, {
                    "error": "intervalMinutes must be an integer 1-60"
                })
            claims = (
                event.get("requestContext", {})
                .get("authorizer", {}).get("jwt", {}).get("claims", {})
            )
            record = {
                "settingKey": "simulation",
                "intervalMinutes": interval,
                "updatedAt": utc_now(),
                "updatedBy": str(claims.get("sub") or "Unknown")[:120],
            }
            settings.put_item(Item=record)
            return respond(200, {
                "intervalMinutes": interval,
                "updatedAt": record["updatedAt"],
                "updatedBy": record["updatedBy"],
                "source": "NetworkSettings",
                "schedulerRequired": "rate(1 minute)",
            })

        # ==========================================
        # 17. KHONG TIM THAY API
        # ==========================================

        return respond(
            404,
            {"error": "Not found"}
        )

    # ==============================================
    # 18. XU LY LOI AWS / DYNAMODB
    # ==============================================

    except ClientError as error:

        code = error.response.get(
            "Error",
            {}
        ).get(
            "Code",
            "AWSClientError"
        )

        print(
            "AWS ClientError:",
            code,
            str(error)
        )

        status_code = (
            409

            if code == "ConditionalCheckFailedException"

            else 500
        )

        return respond(
            status_code,
            {"error": code}
        )

    except (ValueError, TypeError) as error:

        return respond(
            400,
            {"error": str(error)}
        )

    except Exception:

        import traceback

        traceback.print_exc()

        return respond(
            500,
            {"error": "Internal server error"}
        )
