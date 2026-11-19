"""NetMon audit writer: ghi INSERT/MODIFY/REMOVE từ NetworkDevices Streams.

AWS Lambda handler: lambda_function.lambda_handler
Bảng đích: NetworkAuditLogs (PK logType S, SK eventKey S).
Không sửa NetworkDevices, không gọi SNS; độc lập với Lambda monitor cũ.
"""

import datetime as dt
import logging
import os
from decimal import Decimal

import boto3
from boto3.dynamodb.types import TypeDeserializer
from botocore.exceptions import ClientError

TABLE_NAME = os.getenv('AUDIT_LOGS_TABLE', 'NetworkAuditLogs')
LOG_TYPE = 'DEVICE'
TABLE = boto3.resource('dynamodb').Table(TABLE_NAME)
DESERIALIZER = TypeDeserializer()
LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)

# [AUDIT-TRACKED-FIELDS] Chỉ ghi các thuộc tính nghiệp vụ; không ghi cờ monitor
# để tránh việc netmon-device-monitor tự đổi simCpuAlarmActive tạo log rác.
TRACKED_FIELDS = (
    'deviceId', 'deviceName', 'deviceType', 'ipAddress', 'location',
    'status', 'cpuUsage', 'memoryUsage', 'metricsSource',
    'monitoringSource', 'instanceId', 'region', 'vpcId'
)


def deserialize_image(image):
    """DynamoDB Streams dùng kiểu { 'S': ..., 'N': ... }, cần decode."""
    return {
        key: DESERIALIZER.deserialize(value)
        for key, value in (image or {}).items()
    }


def snapshot(image):
    """Giới hạn trường log để không lưu dữ liệu không cần thiết."""
    decoded = deserialize_image(image)
    return {name: decoded[name] for name in TRACKED_FIELDS if name in decoded}


def event_datetime(record):
    """Mốc xảy ra thay đổi xấp xỉ từ Streams; không dùng thời gian đọc trang."""
    value = (record.get('dynamodb') or {}).get('ApproximateCreationDateTime')
    try:
        if value is not None:
            return dt.datetime.fromtimestamp(float(value), dt.timezone.utc)
    except (ValueError, TypeError, OverflowError):
        pass
    return dt.datetime.now(dt.timezone.utc)


def process_record(record):
    if record.get('eventSource') != 'aws:dynamodb':
        return 'ignored'

    event_name = record.get('eventName')
    if event_name not in ('INSERT', 'MODIFY', 'REMOVE'):
        return 'ignored'

    record_id = str(record.get('eventID') or '').strip()
    if not record_id:
        raise ValueError('DynamoDB stream record has no eventID')

    data = record.get('dynamodb') or {}
    before = snapshot(data.get('OldImage'))
    after = snapshot(data.get('NewImage'))
    key_attrs = deserialize_image(data.get('Keys'))
    device_id = str(key_attrs.get('deviceId') or after.get('deviceId') or before.get('deviceId') or '')
    if not device_id:
        raise ValueError('Cannot determine deviceId from stream record')

    # [AUDIT-IGNORE-NOISE] Flag của Lambda giám sát/lastUpdated không tạo sự kiện.
    if event_name == 'MODIFY' and data.get('OldImage') and data.get('NewImage'):
        changes = [key for key in TRACKED_FIELDS if before.get(key) != after.get(key)]
        if not changes:
            return 'ignored'
    elif event_name == 'MODIFY':
        # NEW_IMAGE/KEYS_ONLY: chưa biết cũ và mới, vẫn ghi nhưng không bịa diff.
        changes = []
    else:
        changes = [key for key in TRACKED_FIELDS if key in (after if event_name == 'INSERT' else before)]

    when = event_datetime(record)
    event_time = when.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    event_key = event_time + '#' + record_id  # Có thứ tự thời gian; replay cùng key.
    device_name = str(after.get('deviceName') or before.get('deviceName') or device_id)

    item = {
        'logType': LOG_TYPE,
        'eventKey': event_key,
        'eventId': record_id,
        'eventTime': event_time,
        'recordedAt': dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'),
        'deviceId': device_id,
        'deviceName': device_name,
        'eventName': event_name,
        'action': {'INSERT': 'CREATE', 'MODIFY': 'UPDATE', 'REMOVE': 'DELETE'}[event_name],
        'source': 'DynamoDB Streams',
        # [AUDIT-TTL] 30-day retention if TTL enabled on expiresAt in DynamoDB.
        'expiresAt': int(when.timestamp()) + 30 * 24 * 3600,
        'actor': 'Unknown',  # Streams không mang IAM principal / tên người dùng.
        'changedFields': changes,
        'before': before,
        'after': after,
    }

    try:
        TABLE.put_item(
            Item=item,
            ConditionExpression='attribute_not_exists(logType) AND attribute_not_exists(eventKey)'
        )
        return 'saved'
    except ClientError as error:
        code = error.response.get('Error', {}).get('Code')
        if code == 'ConditionalCheckFailedException':
            return 'duplicate'
        raise


def lambda_handler(event, context):
    """Raise lỗi thực để Lambda retry batch; idempotency tránh ghi trùng."""
    result = {'saved': 0, 'ignored': 0, 'duplicate': 0}
    for record in (event or {}).get('Records', []):
        status = process_record(record)
        result[status] += 1
    LOGGER.info('Audit batch result: %s', result)
    return result
