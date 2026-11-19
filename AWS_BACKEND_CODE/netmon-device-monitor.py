"""netmon-device-monitor: DynamoDB Streams -> Alert history + SNS.

Uses NetworkSettings CPU/RAM thresholds, shared with /settings frontend.
Excludes EC2/CLOUDWATCH, ignores monitor flag updates to avoid recursion.
DynamoDB Stream view must include NEW_AND_OLD_IMAGES.
"""
import datetime as dt
import json
import os
import uuid
from decimal import Decimal, InvalidOperation

import boto3
from botocore.exceptions import ClientError

DB = boto3.resource('dynamodb')
DEVICES = DB.Table(os.getenv('DEVICES_TABLE', 'NetworkDevices'))
ALERTS = DB.Table(os.getenv('ALERTS_TABLE', 'NetworkAlerts'))
SETTINGS = DB.Table(os.getenv('SETTINGS_TABLE', 'NetworkSettings'))
SNS = boto3.client('sns')
TOPIC_ARN = os.getenv('SNS_TOPIC_ARN', '')

WATCH_FIELDS = ('cpuUsage', 'memoryUsage', 'status', 'metricsSource',
                'monitoringSource', 'instanceId', 'deviceName')


def thresholds():
    """Missing item => default 80; missing TABLE => fail rather than diverge."""
    row = SETTINGS.get_item(
        Key={'settingKey': 'thresholds'}, ConsistentRead=True
    ).get('Item') or {}
    return {
        'CPU': Decimal(str(row.get('cpuThreshold', 80))),
        'RAM': Decimal(str(row.get('ramThreshold', 80))),
    }


def stream_ids(event):
    records = event.get('Records')
    if records is None:
        return None  # Manual Lambda test / scheduled invocation.
    keys = set()
    for rec in records:
        if rec.get('eventName') not in ('INSERT', 'MODIFY'):
            continue
        d = rec.get('dynamodb') or {}
        new = d.get('NewImage') or {}
        old = d.get('OldImage') or {}
        if rec.get('eventName') == 'MODIFY' and not any(
            new.get(k) != old.get(k) for k in WATCH_FIELDS
        ):
            continue
        did = (d.get('Keys') or {}).get('deviceId', {}).get('S')
        if did:
            keys.add(did)
    return keys


def scan_devices():
    cursor = {}
    while True:
        r = DEVICES.scan(**cursor)
        yield from r.get('Items', [])
        if 'LastEvaluatedKey' not in r:
            return
        cursor = {'ExclusiveStartKey': r['LastEvaluatedKey']}


def percent(value):
    try:
        number = Decimal(str(value))
        return number if number.is_finite() and 0 <= number <= 100 else None
    except (TypeError, ValueError, InvalidOperation):
        return None


def save_alert(device, kind, state, value, threshold):
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    device_id = str(device['deviceId'])
    row = {
        'eventId': str(uuid.uuid4()),
        'eventTime': now,
        'deviceId': device_id,
        'deviceName': str(device.get('deviceName') or device_id),
        'alarmName': f'SIM-{kind}-{device_id}',
        'alarmType': kind,
        'alarmState': state,
        'metricValue': value,
        'threshold': threshold,
        'reason': f'{kind} = {value}% (ngưỡng {threshold}%)',
        'source': 'SIMULATED',
        'isTest': True,  # Explicitly demo data, still actionable for ALARM.
        'handlingStatus': 'New' if state == 'ALARM' else 'NotApplicable'
    }
    ALERTS.put_item(Item=row, ConditionExpression='attribute_not_exists(eventId)')
    return row


def lambda_handler(event, context):
    event = event or {}
    ids = stream_ids(event)
    if ids is not None and not ids:
        return {'statusCode': 200, 'message': 'No metric changes'}
    limits = thresholds()
    only = str(event.get('deviceId') or '')
    dry_run = event.get('dryRun') is True
    result = {'checked': 0, 'alertsCreated': 0, 'recovered': 0,
              'emailsRequested': 0, 'dryRun': dry_run, 'wouldAlert': []}
    for device in scan_devices():
        did = str(device['deviceId'])
        if (only and did != only) or (ids is not None and did not in ids):
            continue
        if device.get('instanceId') or str(device.get('monitoringSource') or '').upper() == 'CLOUDWATCH':
            continue
        if str(device.get('metricsSource') or '').upper() not in ('SIMULATED', 'MIXED', 'MANUAL'):
            continue
        if str(device.get('status') or '').upper() == 'OFFLINE':
            continue
        result['checked'] += 1
        for field, kind, flag in (
            ('cpuUsage', 'CPU', 'simCpuAlarmActive'),
            ('memoryUsage', 'RAM', 'simRamAlarmActive')
        ):
            number = percent(device.get(field))
            if number is None:
                continue
            high = number > limits[kind]
            was_high = device.get(flag) is True
            if high and not was_high:
                result['wouldAlert'].append(f'{kind}:{did}')
                if dry_run:
                    continue
                try:
                    DEVICES.update_item(
                        Key={'deviceId': did},
                        UpdateExpression='SET #flag=:yes',
                        ConditionExpression=(
                            'attribute_exists(deviceId) AND '
                            'attribute_not_exists(instanceId) AND '
                            '(attribute_not_exists(#flag) OR #flag=:no)'
                        ),
                        ExpressionAttributeNames={'#flag': flag},
                        ExpressionAttributeValues={':yes': True, ':no': False}
                    )
                except ClientError as exc:
                    if exc.response.get('Error', {}).get('Code') == 'ConditionalCheckFailedException':
                        continue
                    raise
                try:
                    alert = save_alert(device, kind, 'ALARM', number, limits[kind])
                except Exception:
                    DEVICES.update_item(
                        Key={'deviceId': did},
                        UpdateExpression='SET #flag=:no',
                        ExpressionAttributeNames={'#flag': flag},
                        ExpressionAttributeValues={':no': False}
                    )
                    raise
                result['alertsCreated'] += 1
                if TOPIC_ARN:
                    try:
                        SNS.publish(
                            TopicArn=TOPIC_ARN,
                            Subject=f'[NetMon SIM] {kind} cao',
                            Message=json.dumps({
                                'deviceId': did, 'deviceName': alert['deviceName'],
                                'metric': kind, 'value': float(number),
                                'threshold': float(limits[kind]),
                                'source': 'SIMULATED'
                            }, ensure_ascii=False)
                        )
                        result['emailsRequested'] += 1
                    except ClientError as exc:
                        print('SNS error:', exc.response.get('Error', {}).get('Code'))
            elif not high and was_high and not dry_run:
                try:
                    DEVICES.update_item(
                        Key={'deviceId': did},
                        UpdateExpression='SET #flag=:no',
                        ConditionExpression='#flag=:yes',
                        ExpressionAttributeNames={'#flag': flag},
                        ExpressionAttributeValues={':no': False, ':yes': True}
                    )
                except ClientError as exc:
                    if exc.response.get('Error', {}).get('Code') == 'ConditionalCheckFailedException':
                        continue
                    raise
                # Recovery is a distinct historical event; does not rewrite a prior ALARM.
                save_alert(device, kind, 'OK', number, limits[kind])
                result['recovered'] += 1
    return {'statusCode': 200, 'body': json.dumps(result, ensure_ascii=False)}
