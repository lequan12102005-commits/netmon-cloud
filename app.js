'use strict';

// NetMon Cloud frontend. AWS reads/writes go ONLY through API Gateway.
// Never put an AWS Access Key / Secret Access Key in frontend code.
// ================================================================
// [01 - TIEN ICH] Lấy phần tử, chống XSS, lưu cấu hình và format số
// ================================================================
const $ = id => document.getElementById(id);
const escapeHtml = value => String(value ?? '').replace(
    /[&<>"']/g,
    char => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[char]
);
const stored = (key, fallback) => {
    try {
        const data = JSON.parse(localStorage.getItem(key));
        return data == null ? fallback : data;
    }
    catch {
        return fallback;
    }
};
const persist = (key, value) => localStorage.setItem(key, JSON.stringify(value));
const valueNumber = value => {
    if (value === '' || value == null || !Number.isFinite(Number(value))) {
        return null;
    }

    return Math.max(0, Math.min(100, Number(value)));
};

const formatNumber = value => (
    Number.isFinite(Number(value)) && value != null
        ? Number(value).toLocaleString('vi-VN')
        : '—'
);
const timeText = value => {
    if (!value)
        return '—';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? escapeHtml(value) : date.toLocaleString('vi-VN');
};
// ================================================================
// [02 - CAU HINH] Invoke URL, ngưỡng cảnh báo và chế độ demo
// ĐỔI API / NGƯỠNG / CHU KỲ tại phần này hoặc trong trang Cấu hình.
// ================================================================
const DEFAULT_URL = netmonAuth.apiUrl;
const previousSettings = stored('ha-tang-v1-settings', {});
const newSettings = stored('netmon-v2-settings', null);
const settings = Object.assign(
    {
        url: location.hostname === 'lequan12102005-commits.github.io' ? '' : DEFAULT_URL,
        cpuThreshold: 80,
        ramThreshold: 80,
        interval: 60,
        simulationIntervalMinutes: 5,
        popup: true
    },
    previousSettings,
    newSettings || {}
);
settings.url = String(settings.url || '').replace(/\/+$/, '');
// [THRESHOLD-MIGRATION] Hỗ trợ cấu hình cũ dùng chung trường `threshold`.
// Khi nâng cấp, lấy lại giá trị đã lưu để không làm mất cấu hình người dùng.
// CPU và RAM có hai ngưỡng độc lập trong trình duyệt.
function validThreshold(value, fallback = 80) {
    if (value === '' || value == null) {
        return fallback;
    }

    const number = Number(value);
    return Number.isFinite(number) && number >= 1 && number <= 99
        ? number
        : fallback;
}

const legacyThreshold = validThreshold(settings.threshold, 80);
// Kiểm tra dữ liệu ĐÃ LƯU, không lấy giá trị mặc định 80 ghi đè ngưỡng cũ.
const storedCpu = newSettings?.cpuThreshold ?? previousSettings?.cpuThreshold;
const storedRam = newSettings?.ramThreshold ?? previousSettings?.ramThreshold;
settings.cpuThreshold = validThreshold(storedCpu, legacyThreshold);
settings.ramThreshold = validThreshold(storedRam, legacyThreshold);
delete settings.threshold; // Xóa trường cũ, không lưu trùng lặp.

// [THRESHOLD-HELPERS] Vượt ngưỡng = lớn hơn (>) giá trị đã cấu hình.
// Dùng cùng quy tắc cho Dashboard, danh sách thiết bị và cảnh báo demo.
function thresholdForMetric(metric) {
    const kind = String(metric ?? '').trim().toUpperCase();
    if (kind === 'CPU') return settings.cpuThreshold;
    if (kind === 'RAM' || kind === 'MEMORY') return settings.ramThreshold;
    return null;
}

function isMetricHigh(value, metric) {
    const number = valueNumber(value);
    const threshold = thresholdForMetric(metric);
    return number != null && threshold != null && number > threshold;
}
settings.interval = [0, 30, 60, 120].includes(Number(settings.interval)) ? Number(settings.interval) : 60;
settings.popup = settings.popup !== false;
settings.simulationIntervalMinutes = Number.isInteger(Number(settings.simulationIntervalMinutes)) && Number(settings.simulationIntervalMinutes) >= 1 && Number(settings.simulationIntervalMinutes) <= 60 ? Number(settings.simulationIntervalMinutes) : 5;
const DEMO_DEVICES = [
    { deviceId: 'GW-001', deviceName: 'Gateway văn phòng', deviceType: 'Router', ipAddress: '10.0.0.1', location: 'Tầng 1', status: 'ONLINE', cpuUsage: 32, memoryUsage: 47 },
    { deviceId: 'SW001', deviceName: 'Switch Tầng 1', deviceType: 'Switch', ipAddress: '10.0.0.10', location: 'Tầng 1', status: 'ONLINE', cpuUsage: 45, memoryUsage: 62 },
    { deviceId: 'SW002', deviceName: 'Switch Tầng 2', deviceType: 'Switch', ipAddress: '10.0.0.11', location: 'Tầng 2', status: 'ONLINE', cpuUsage: 28, memoryUsage: 35 },
    { deviceId: 'SRV001', deviceName: 'Máy chủ nội bộ', deviceType: 'Server', ipAddress: '10.0.1.20', location: 'Phòng máy', status: 'WARNING', cpuUsage: 91, memoryUsage: 86 },
    { deviceId: 'AP001', deviceName: 'Wi-Fi phòng họp', deviceType: 'Access Point', ipAddress: '10.0.0.31', location: 'Tầng 3', status: 'ONLINE', cpuUsage: 19, memoryUsage: 44 },
    { deviceId: 'FW001', deviceName: 'Firewall chính', deviceType: 'Firewall', ipAddress: '10.0.0.254', location: 'Phòng kỹ thuật', status: 'OFFLINE', cpuUsage: 0, memoryUsage: 0 }
];
const state = {
    devices: [],
    alerts: [],
    samples: [],
    cloudwatch: null,
    selectedHistoryInstance: '',
    ec2HistoryMinutes: 60,
    ec2HistorySelectionMade: false,
    ec2HistoryFetching: false,
    ec2HistoryError: '',
    ec2HistoryCache: new Map(),
    ec2HistoryRequestSeq: 0,
    loaded: false,
    loading: false,
    error: '',
    alertsSource: 'pending',
    metricsSource: 'pending',
    alertsError: '',
    alertsLastSync: null,
    auditLogs: [],
    auditLogsSource: 'pending',
    auditLogsError: '',
    auditLogsLastSync: null,
    lastUpdate: null,
    selectedPage: 'overview',
    historyTab: 'devices',
    diagramTab: 'aws',
    snsStatus: null,
    snsError: '',
    snsLastSync: null,
    editing: null,
    intervalId: null,
    // [AUTO-REFRESH] Nút tạm dừng dùng sessionStorage, không đụng AWS.
    // Khi F5 trong cùng tab, trạng thái tạm dừng vẫn được giữ.
    autoPaused: sessionStorage.getItem('netmon-auto-refresh-paused') === 'true',
    nextAutoAt: null,
    popupShown: new Set(),
    thresholdsSync: 'local',
    thresholdsError: '',
    simulationSync: 'pending',
    simulationError: '',
    simulationSaving: false,
    bulkProcessing: false,
    // [ALERT-SELECTION] Lua chon theo eventId, khong dua vao index/thu tu bang.
    selectedAlertIds: new Set()
};
const sourceId = () => settings.url || 'demo';
const scopedKey = name => `netmon-v2-${name}:${sourceId()}`;
const isAws = () => Boolean(settings.url);
const isCognitoApi = () => settings.url === netmonAuth.apiUrl;
const hasToken = () => Boolean(netmonAuth.token());
const isoNow = () => new Date().toISOString();
const navTitles = {
    overview: ['Tổng quan hệ thống', 'Theo dõi tình trạng hạ tầng mạng doanh nghiệp'],
    devices: ['Quản lý thiết bị', ''],
    metrics: ['Hiệu năng & Metrics', 'Giám sát CPU, RAM và tài nguyên AWS'],
    alerts: ['Cảnh báo & sự cố', 'Theo dõi và xác nhận xử lý sự cố'],
    topology: ['Sơ đồ hạ tầng', 'Kiến trúc AWS và mô hình mạng doanh nghiệp'],
    logs: ['Nhật ký lịch sử', 'Thay đổi thiết bị AWS, thao tác trình duyệt và cảnh báo'],
    settings: ['Cấu hình & kết nối', 'Thiết lập API, ngưỡng CPU/RAM và chu kỳ cập nhật']
};
function notify(message = '') {
    $('notice').textContent = message;
    $('notice').hidden = !message;
}
function setBusy(busy) {
    state.loading = busy;
    ['refresh', 'add', 'save', 'save-settings', 'sign-in', 'demo-button'].forEach(id => {
        const element = $(id);
        if (element)
            element.disabled = busy;
    });
    $('refresh').textContent = busy ? '◌' : '↻';
    $('refresh').setAttribute('aria-label', busy ? 'Đang tải dữ liệu AWS' : 'Tải lại ngay dữ liệu AWS');
    renderAutoRefreshStatus();
}
function navigate(name) {
    if (!navTitles[name])
        return;
    state.selectedPage = name;
    document.querySelectorAll('.nav button[data-page]').forEach(button => {
        if (button.dataset.page === name)
            button.setAttribute('aria-current', 'page');
        else
            button.removeAttribute('aria-current');
    });
    document.querySelectorAll('section.page').forEach(section => section.hidden = section.id !== name);
    $('page-title').textContent = navTitles[name][0];
    $('page-caption').textContent = navTitles[name][1];
    $('page-caption').hidden = !navTitles[name][1];
    if (name === 'topology') showDiagramTab(state.diagramTab);
    if (name === 'logs') showHistoryTab(state.historyTab);
    if (name === 'metrics' && state.selectedHistoryInstance) void loadEc2History();
    window.scrollTo({ top: 0, behavior: 'instant' });
}
// [HISTORY-TABS] 3 trang con trong muc Nhat ky lich su.
function showHistoryTab(tab) {
    if (!['devices', 'alerts', 'local'].includes(tab)) return;
    state.historyTab = tab;
    for (const button of document.querySelectorAll('[data-history-tab]')) {
        const active = button.dataset.historyTab === tab;
        button.classList.toggle('is-active', active);
        button.setAttribute('aria-selected', String(active));
        button.setAttribute('tabindex', active ? '0' : '-1');
    }
    for (const section of document.querySelectorAll('[id^="history-page-"]')) {
        section.hidden = section.id !== `history-page-${tab}`;
    }
}
function unpackPayload(input) {
    let result = input;
    if (result && typeof result === 'object' && 'body' in result && typeof result.body === 'string') {
        try {
            result = JSON.parse(result.body);
        }
        catch { /* leave wrapper */ }
    }
    return result;
}
function asArray(input, names) {
    const data = unpackPayload(input);
    if (Array.isArray(data))
        return data;
    for (const name of names)
        if (Array.isArray(data?.[name]))
            return data[name];
    return null;
}
function dynamoValue(value) {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
        if ('S' in value)
            return value.S;
        if ('N' in value)
            return Number(value.N);
        if ('BOOL' in value)
            return Boolean(value.BOOL);
        if ('NULL' in value)
            return null;
        if ('M' in value)
            return Object.fromEntries(Object.entries(value.M).map(([k, v]) => [k, dynamoValue(v)]));
        if ('L' in value)
            return value.L.map(dynamoValue);
    }
    return value;
}
function normalizeDevice(device) {
    if (!device || typeof device !== 'object')
        return null;
    const normalized = Object.fromEntries(Object.entries(device).map(([key, value]) => [key, dynamoValue(value)]));
    if (normalized.deviceId == null || normalized.deviceId === '')
        return null;
    normalized.deviceId = String(normalized.deviceId);
    return normalized;
}
// ================================================================
// [03 - AWS API] Gọi API Gateway. Token lấy từ Cognito trong auth.js
// Không ghi Access Key / Secret Key vào JavaScript.
// ================================================================
class HttpStatusError extends Error {
    constructor(status, endpoint) { super(`API ${endpoint} trả về HTTP ${status}.`); this.status = status; }
}
async function awsRequest(path, method = 'GET', payload, optional = false) {
    if (!settings.url)
        throw new Error('Chưa cấu hình Invoke URL.');
    const headers = new Headers({ Accept: 'application/json' });
    if (isCognitoApi()) {
        const token = netmonAuth.token();
        if (!token)
            throw new Error('Bạn cần bấm Đăng nhập AWS (Cognito) để tải dữ liệu từ tài khoản.');
        headers.set('Authorization', `Bearer ${token}`);
    }
    if (payload !== undefined)
        headers.set('Content-Type', 'application/json');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    try {
        const response = await fetch(settings.url + path, {
            method, headers, body: payload === undefined ? undefined : JSON.stringify(payload),
            signal: controller.signal, cache: 'no-store'
        });
        if (optional && [404, 405, 501].includes(response.status))
            return null;
        if (!response.ok) {
            const error = new HttpStatusError(response.status, path);
            try {
                const detail = unpackPayload(await response.json());
                if (typeof detail?.error === 'string') error.message += ' ' + detail.error;
            } catch { /* Loi HTTP van duoc hien thi */ }
            throw error;
        }
        if (response.status === 204)
            return null;
        const text = await response.text();
        if (!text.trim())
            return null;
        try {
            return unpackPayload(JSON.parse(text));
        }
        catch {
            throw new Error(`API ${path} không trả JSON hợp lệ.`);
        }
    }
    catch (error) {
        if (error.name === 'AbortError')
            throw new Error(`Quá thời gian kết nối ${path} (15 giây).`);
        if (error instanceof TypeError)
            throw new Error(`Không kết nối được ${path}. Kiểm tra CORS và Invoke URL.`);
        throw error;
    }
    finally {
        clearTimeout(timer);
    }
}
function recordOperation(action, detail = '') {
    const entries = stored(scopedKey('operations'), []);
    entries.unshift({ time: isoNow(), action, detail, origin: 'Trình duyệt' });
    persist(scopedKey('operations'), entries.slice(0, 200));
}
// ================================================================
// [04 - CANH BAO] Demo / chuẩn hóa sự kiện CloudWatch từ DynamoDB
// ================================================================
function localAlertsFromDevices() {
    const key = scopedKey('alerts');
    const entries = stored(key, []);
    const activeKeys = new Set();
    for (const device of state.devices) {
        const tests = [
            {
                kind: 'CPU',
                value: valueNumber(device.cpuUsage),
                threshold: settings.cpuThreshold,
                breach: isMetricHigh(device.cpuUsage, 'CPU')
            },
            {
                kind: 'RAM',
                value: valueNumber(device.memoryUsage),
                threshold: settings.ramThreshold,
                breach: isMetricHigh(device.memoryUsage, 'RAM')
            },
            { kind: 'OFFLINE', value: null, breach: String(device.status || '').toUpperCase() === 'OFFLINE' }
        ];
        for (const test of tests.filter(row => row.breach)) {
            const alertKey = `${device.deviceId}:${test.kind}`;
            activeKeys.add(alertKey);
            let match = entries.find(row => row.key === alertKey && row.active);
            if (!match) {
                match = { id: `browser-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`, key: alertKey,
                    deviceId: device.deviceId, deviceName: device.deviceName || device.deviceId,
                    metric: test.kind, value: test.value, threshold: test.threshold ?? null,
                    severity: test.kind === 'OFFLINE' ? 'CRITICAL' : 'WARNING',
                    time: isoNow(), handled: false, active: true, origin: 'browser' };
                entries.unshift(match);
                recordOperation('Phát hiện sự cố', `${match.deviceName} · ${match.metric}`);
            }
            else {
                match.value = test.value;
                match.threshold = test.threshold ?? null;
            }
        }
    }
    for (const entry of entries)
        if (entry.active && !activeKeys.has(entry.key))
            entry.active = false;
    persist(key, entries.slice(0, 400));
    return entries.slice(0, 400);
}
function normalizeAlert(row, index) {
    if (!row || typeof row !== 'object') {
        return null;
    }

    // [ALERT-FIELDS] DynamoDB NetworkAlerts dung khoa eventId.
    // CloudWatch: source=CloudWatch, isTest thuong la false.
    // Monitor thiet bi: source=SIMULATED, isTest=true (du lieu MO PHONG).
    // Canh bao mo phong van CAN DUOC XU LY va hien popup neu dang ALARM/New.
    const data = Object.fromEntries(
        Object.entries(row).map(([key, value]) => [key, dynamoValue(value)])
    );

    const source = String(data.source ?? '').toUpperCase();
    const isSimulated = source === 'SIMULATED';
    const alarmState = String(data.alarmState ?? '').toUpperCase();
    const handlingStatus = String(
        data.handlingStatus ?? data.status ?? ''
    ).toUpperCase();

    // Khong gop Acknowledged voi Resolved: tiep nhan != xu ly xong.
    const acknowledged = handlingStatus === 'ACKNOWLEDGED';
    const resolved =
        data.handled === true ||
        data.isHandled === true ||
        ['HANDLED', 'RESOLVED', 'CLOSED', 'DONE', 'ĐÃ XỬ LÝ', 'DA XU LY']
            .includes(handlingStatus);

    // CloudWatch OK/INSUFFICIENT_DATA va event test CloudWatch khong popup.
    // Rieng SIMULATED co isTest=true van la canh bao de demo va xu ly.
    const testOnly = !isSimulated && (
        data.isTest === true || handlingStatus === 'TEST'
    );
    const nonActionable =
        Boolean(alarmState && alarmState !== 'ALARM') ||
        handlingStatus === 'NOTAPPLICABLE' ||
        testOnly;

    const recovered = alarmState === 'OK';
    const handled = Boolean(resolved || nonActionable);

    let statusLabel = 'Chưa xử lý';
    if (recovered) {
        statusLabel = 'Đã phục hồi (OK)';
    } else if (alarmState === 'INSUFFICIENT_DATA') {
        statusLabel = 'Thiếu dữ liệu';
    } else if (testOnly) {
        statusLabel = 'Thử nghiệm CloudWatch';
    } else if (handlingStatus === 'NOTAPPLICABLE') {
        statusLabel = 'Không cần xử lý';
    } else if (resolved) {
        statusLabel = 'Đã xử lý';
    } else if (acknowledged) {
        statusLabel = 'Đã tiếp nhận';
    }

    return {
        id: String(data.eventId ?? data.alertId ?? data.id ?? `item-${index}`),
        deviceId: String(data.deviceId ?? ''),
        deviceName: String(
            data.deviceName ?? data.device ?? data.deviceId ?? 'Thiết bị'
        ),
        metric: String(
            data.alarmType ?? data.metric ?? data.name ?? data.alarmName ?? 'Cảnh báo'
        ),
        value: valueNumber(
            data.value ?? data.currentValue ?? data.metricValue
        ),
        // [AWS-ALERT-THRESHOLD] Tôn trọng ngưỡng AWS ghi lại tại thời điểm tạo cảnh báo.
        // Không dùng ngưỡng cục bộ của trình duyệt để gắn vào sự kiện AWS.
        threshold: valueNumber(data.threshold),
        severity: alarmState && alarmState !== 'ALARM'
            ? 'INFO'
            : String(data.severity ?? 'WARNING').toUpperCase(),
        time: data.eventTime ?? data.createdAt ?? data.timestamp ??
            data.time ?? data.lastUpdated ?? null,
        handled,
        acknowledged,
        resolved,
        recovered,
        nonActionable: Boolean(nonActionable),
        active: !handled,
        statusLabel,
        alarmState,
        reason: String(data.reason ?? ''),
        acknowledgedAt: data.acknowledgedAt ?? null,
        resolvedAt: data.resolvedAt ?? null,
        handledBy: String(data.handledBy ?? ''),
        isTest: data.isTest === true,
        isSimulated,
        sourceLabel: isSimulated
            ? 'Mô phỏng'
            : source === 'CLOUDWATCH' ? 'CloudWatch' : (data.source || 'Không rõ nguồn'),
        origin: 'aws',
        raw: data
    };
}
// ================================================================
// [AWS-METRICS-REAL] Chuẩn hóa API GET /metrics (một hoặc nhiều máy EC2)
// Backend mới trả: { instances:[...], ec2:{...}, history:[...] }.
// Backend cũ trả: [{deviceId, cpu}]. Giữ tương thích cả hai.
// KHÔNG sử dụng giá trị RAM mô phỏng làm metric CloudWatch thật.
// ================================================================
function parseMetrics(payload) {
    const data = unpackPayload(payload);
    if (!data || typeof data !== 'object') return null;

    // [EC2-ID-STRICT] Khong ghep hai instanceId rong; day la nguyen nhan
    // tat ca hang hien cung mot deviceName (vi du 'test003').
    const findDevice = row => {
        const id = String(row.deviceId ?? '').trim();
        const instance = String(row.instanceId ?? '').trim();
        return state.devices.find(device =>
            (id !== '' && String(device.deviceId) === id) ||
            (instance !== '' && String(device.instanceId ?? '') === instance)
        );
    };

    // Backend hien tai GET /metrics tra mot mang GOM CA SIMULATED va CLOUDWATCH.
    // Chi dua EC2 that vao bang CloudWatch va bieu do EC2.
    const isEc2Record = row => {
        const source = String(row.source ?? row.metricsSource ?? '').toUpperCase();
        if (source === 'SIMULATED' || source === 'MANUAL') return false;
        const device = findDevice(row);
        return source === 'CLOUDWATCH' ||
            Boolean(String(row.instanceId ?? device?.instanceId ?? '').trim()) ||
            String(device?.monitoringSource ?? '').toUpperCase() === 'CLOUDWATCH';
    };

    const normalizeInstance = (row = {}) => {
        const device = findDevice(row);
        const instanceId = String(row.instanceId || device?.instanceId || row.deviceId || '');
        const id = String(row.deviceId || device?.deviceId || instanceId);
        return {
            deviceId: id,
            deviceName: String(device?.deviceName || row.deviceName || instanceId || 'Máy chủ EC2'),
            instanceId,
            cpu: valueNumber(row.cpu ?? row.cpuUsage ?? row.cpuUtilization),
            // [EC2-RAM] Lambda netmon-api tra 'memoryUsage' (NetMon/EC2).
            memory: valueNumber(row.memory ?? row.memoryUsage ?? row.ram ?? row.memUsedPercent),
            networkIn: row.networkIn ?? null,
            networkOut: row.networkOut ?? null,
            sampleTime: row.sampleTime ?? row.metricSampleTime ?? row.timestamp ?? null,
            stale: row.stale === true,
            sampleTimes: row.sampleTimes ?? {},
            source: 'CloudWatch'
        };
    };

    let instances = [];
    let history = [];
    const histories = {};

    if (Array.isArray(data)) {
        instances = data.filter(row => row && typeof row === 'object' && isEc2Record(row))
            .map(normalizeInstance);
    } else if (Array.isArray(data.instances)) {
        instances = data.instances.filter(row => row && isEc2Record(row))
            .map(normalizeInstance);
    } else {
        const ec2 = data.ec2 || data.cloudwatch || data.instance || {};
        if (Object.keys(ec2).length && isEc2Record(ec2)) {
            instances = [normalizeInstance({
                ...ec2,
                instanceId: ec2.instanceId ?? data.instanceId,
                cpu: ec2.cpu ?? ec2.cpuUtilization ?? data.cpuUtilization,
                memory: ec2.memory ?? ec2.memoryUsage ?? ec2.memUsedPercent ?? data.memUsedPercent
            })];
        }
    }

    const normalizeHistory = rows => (Array.isArray(rows) ? rows : [])
        .map(row => ({
            time: row.time ?? row.timestamp ?? null,
            cpu: valueNumber(row.cpu ?? row.cpuUsage),
            ram: valueNumber(row.ram ?? row.memory ?? row.memoryUsage)
        }))
        .filter(row => row.time && (row.cpu != null || row.ram != null));

    if (!Array.isArray(data)) {
        history = normalizeHistory(asArray(data, ['history', 'samples', 'dataPoints']));
        if (data.histories && typeof data.histories === 'object') {
            for (const [instanceId, rows] of Object.entries(data.histories)) {
                histories[instanceId] = normalizeHistory(rows);
            }
        }
    }
    return {
        instances,
        ec2: instances[0] ?? null,
        history,
        histories,
        updatedAt: Array.isArray(data) ? null : (data.updatedAt ?? null),
        periodSeconds: Array.isArray(data) ? 300 : (data.periodSeconds ?? 300),
        truncatedCount: Array.isArray(data) ? 0 : (data.truncatedCount ?? 0)
    };
}

// [EC2-OVERLAY] Mỗi thiết bị có instanceId lấy CPU/RAM từ CloudWatch,
// KHÔNG lấy cpuUsage/memoryUsage cũ trong DynamoDB và gắn nhãn là 'thực'.
// CloudWatch chưa có RAM => để null (giao diện hiện dấu —).
function applyRealEc2Metrics() {
    if (!isAws()) return;
    const metrics = state.cloudwatch?.instances ?? [];
    const byId = new Map(metrics.map(item => [item.instanceId, item]));
    const byDeviceId = new Map(metrics.map(item => [item.deviceId, item]));

    state.devices = state.devices.map(original => {
        if (!original.instanceId && !registeredEc2(original)) return original;
        const record = byId.get(String(original.instanceId)) ||
            byDeviceId.get(String(original.deviceId));
        const valid = record && !record.stale && [record.cpu, record.memory].some(v => v != null);
        return {
            ...original,
            storedCpuUsage: original.cpuUsage ?? null,
            storedMemoryUsage: original.memoryUsage ?? null,
            cpuUsage: valid ? record.cpu : null,
            memoryUsage: valid ? record.memory : null,
            metricSourceLabel: valid ? 'CloudWatch EC2' :
                record?.stale ? 'CloudWatch: dữ liệu cũ' : 'Chưa có metric EC2',
            metricSampleTime: record?.sampleTime ?? null
        };
    });
}

function addSample() {
    const cpu = mean('cpuUsage');
    const ram = mean('memoryUsage');
    if (cpu == null && ram == null)
        return;
    const key = scopedKey('samples');
    const list = stored(key, []);
    const last = list[list.length - 1];
    // Keep at most one sample every 10 seconds to avoid bloating localStorage.
    if (last && Date.now() - Date.parse(last.time) < 10000)
        return;
    list.push({ time: isoNow(), cpu, ram });
    persist(key, list.slice(-36));
    state.samples = list.slice(-36);
}
// ================================================================
// [05 - TAI DU LIEU] API GET /devices, /alerts, /metrics, /logs.
// [AWS-AUDIT] GET /logs chỉ có dữ liệu sau khi triển khai Lambda audit.
// API /logs lỗi không làm hỏng việc lấy thiết bị và cảnh báo.
// Nhật ký thao tác localStorage vẫn giữ riêng để tránh nhầm nguồn.
// ================================================================
// [SNS-INTEGRATION] Chi danh dau Topic da xac nhan neu API status tra ve hop le.
// So email confirmed KHONG bao dam thu thuc su da den inbox.
function applySnsResult(result) {
    if (result.status === 'fulfilled' && result.value &&
        typeof result.value === 'object' &&
        typeof result.value.configured === 'boolean') {
        state.snsStatus = result.value;
        state.snsError = '';
        state.snsLastSync = isoNow();
    } else {
        state.snsStatus = null;
        state.snsLastSync = null;
        state.snsError = result.status === 'rejected'
            ? result.reason?.message || 'Khong doc duoc /sns/status'
            : 'Chưa có GET /sns/status trên API Gateway.';
    }
}
async function checkSnsStatus() {
    if (!isAws() || (isCognitoApi() && !hasToken())) {
        state.snsStatus = null;
        state.snsError = 'Cần đăng nhập Cognito và dùng AWS API.';
        renderSns();
        return;
    }
    const button = $('check-sns');
    button.disabled = true;
    try {
        const result = await awsRequest('/sns/status', 'GET', undefined, true);
        applySnsResult({status: 'fulfilled', value: result});
    } catch (error) {
        applySnsResult({status: 'rejected', reason: error});
    } finally {
        button.disabled = false;
        renderSns();
        renderOverview();
    }
}
function renderSns() {
    const detail = state.snsStatus;
    const configured = detail?.configured === true;
    const confirmed = Number(detail?.confirmedEmailSubscriptions ?? 0);
    const ready = configured && Number.isFinite(confirmed) && confirmed > 0;
    $('sns-status-tag').textContent = ready ? 'Hoạt động · Đã xác minh email' :
        configured ? 'Topic đã cấu hình' : 'Chưa xác minh API';
    $('sns-status-tag').className = `status-chip ${ready ? 'online' : 'unknown'}`;
    $('sns-topic-name').textContent = detail?.topicArn || 'Chưa trả về Topic ARN';
    $('sns-confirmed-count').textContent = configured ? String(confirmed) : '—';
    $('sns-last-check').textContent = timeText(detail?.checkedAt || state.snsLastSync);
    $('sns-explain').textContent = ready
        ? `SNS có ${confirmed} email subscription đã xác nhận. Đây là thông tin cấu hình, KHÔNG xác nhận email đã đến Gmail; kiểm tra bằng log Lambda và hộp thư.`
        : configured
            ? 'SNS có Topic nhưng chưa tìm thấy email subscription đã xác nhận. Kiểm tra Subscriptions trong AWS.'
            : state.snsError || 'Cần GET /sns/status + JWT scope read, IAM quyền SNS và SNS_TOPIC_ARN trên netmon-api.';
}
async function loadOptionalResources() {
    state.alertsError = '';
    state.alertsLastSync = null;

    if (!isAws()) {
        state.alerts = localAlertsFromDevices();
        state.alertsSource = 'browser';
        state.cloudwatch = null;
        state.snsStatus = null;
        state.snsError = 'Chế độ demo không gọi Amazon SNS.';
        state.snsLastSync = null;
        state.metricsSource = 'session';
        state.auditLogs = [];
        state.thresholdsSync = 'local';
        state.thresholdsError = '';
        state.simulationSync = 'demo';
        state.simulationError = '';
        state.auditLogsSource = 'demo';
        state.auditLogsError = '';
        state.auditLogsLastSync = null;
        return;
    }

    // [AUDIT-AWS-LOAD] /logs độc lập với /alerts và /metrics.
    // Dùng Promise.allSettled: /logs 404 (chưa tạo route) không làm lỗi trang.
    const [alertsResult, metricsResult, auditResult, settingsResult, snsResult, simulationResult] = await Promise.allSettled([
        awsRequest('/alerts', 'GET'),
        awsRequest('/metrics', 'GET', undefined, true),
        awsRequest('/logs?limit=100', 'GET'),
        awsRequest('/settings', 'GET', undefined, true),
        // [SNS-READ-ONLY] GET /sns/status khong phat email va khong lay dia chi.
        awsRequest('/sns/status', 'GET', undefined, true),
        awsRequest('/simulation/config', 'GET', undefined, true)
    ]);
    applySnsResult(snsResult);
    // [AWS-SIMULATION] Đọc chu kỳ thực tế từ NetworkSettings, không khẳng định đã lưu nếu API 404.
    if (simulationResult.status === 'fulfilled' && simulationResult.value &&
        Number.isInteger(Number(simulationResult.value.intervalMinutes)) &&
        Number(simulationResult.value.intervalMinutes) >= 1 &&
        Number(simulationResult.value.intervalMinutes) <= 60) {
        settings.simulationIntervalMinutes = Number(simulationResult.value.intervalMinutes);
        persist('netmon-v2-settings', settings);
        state.simulationSync = 'aws';
        state.simulationError = '';
    } else {
        state.simulationSync = 'error';
        state.simulationError = simulationResult.status === 'rejected'
            ? simulationResult.reason?.message || 'Không đọc được /simulation/config'
            : 'Chưa có GET /simulation/config trên API Gateway.';
    }

    // [AWS-SETTINGS-SYNC] Chỉ hiện 'Đồng bộ AWS' khi GET /settings thật sự hợp lệ.
    if (settingsResult.status === 'fulfilled' && settingsResult.value) {
        const remote = settingsResult.value;
        if (Number.isInteger(Number(remote.cpuThreshold)) &&
            Number.isInteger(Number(remote.ramThreshold)) &&
            Number(remote.cpuThreshold) >= 1 && Number(remote.cpuThreshold) <= 99 &&
            Number(remote.ramThreshold) >= 1 && Number(remote.ramThreshold) <= 99) {
            settings.cpuThreshold = Number(remote.cpuThreshold);
            settings.ramThreshold = Number(remote.ramThreshold);
            persist('netmon-v2-settings', settings);
            state.thresholdsSync = 'aws';
            state.thresholdsError = '';
        } else {
            state.thresholdsSync = 'error';
            state.thresholdsError = 'API /settings không trả ngưỡng hợp lệ.';
        }
    } else {
        state.thresholdsSync = 'local';
        state.thresholdsError = settingsResult.status === 'rejected'
            ? settingsResult.reason?.message || 'Không truy cập được /settings'
            : 'Chưa triển khai GET /settings trên API Gateway.';
    }

    if (auditResult.status === 'fulfilled') {
        const rows = asArray(auditResult.value, ['items', 'Items', 'logs']);
        if (rows) {
            state.auditLogs = rows;
            state.auditLogsSource = 'aws';
            state.auditLogsError = '';
            state.auditLogsLastSync = isoNow();
        } else {
            state.auditLogs = [];
            state.auditLogsSource = 'error';
            state.auditLogsError = 'GET /logs chưa trả về mảng items hợp lệ.';
        }
    } else {
        state.auditLogs = [];
        state.auditLogsSource = 'error';
        state.auditLogsError = auditResult.reason?.message || 'Không đọc được GET /logs.';
    }

    if (alertsResult.status === 'fulfilled') {
        const rows = asArray(alertsResult.value, ['alerts', 'items', 'Items']);

        if (rows) {
            state.alerts = rows.map(normalizeAlert).filter(Boolean);
            state.alertsSource = 'aws';
            state.alertsLastSync = isoNow();
        } else {
            state.alerts = localAlertsFromDevices();
            state.alertsSource = 'browser';
            state.alertsError = 'GET /alerts không trả về danh sách cảnh báo hợp lệ.';
        }
    } else {
        // Khong duoc coi canh bao tu trình duyet la du lieu AWS.
        // Giữ fallback cho Trung tâm cảnh báo, nhưng bảng AWS sẽ rỗng.
        state.alerts = localAlertsFromDevices();
        state.alertsSource = 'browser';
        state.alertsError = alertsResult.reason?.message || 'Không gọi được GET /alerts.';
    }

    state.cloudwatch = metricsResult.status === 'fulfilled' && metricsResult.value !== null
        ? parseMetrics(metricsResult.value)
        : null;
    state.metricsSource = state.cloudwatch ? 'aws' : 'session';
    // Chỉ áp dụng overlay khi có nguồn AWS, không sửa dữ liệu demo.
    applyRealEc2Metrics();
}
async function loadAll(showError = true) {
    if (state.loading)
        return;
    setBusy(true);
    if (showError)
        notify('');
    try {
        if (isAws() && isCognitoApi() && !hasToken()) {
            state.loaded = false;
            state.error = 'Chưa đăng nhập Cognito';
            state.devices = [];
            state.alerts = [];
            state.alertsSource = 'unauthorized';
            state.alertsError = 'Cần đăng nhập Cognito trước khi đọc GET /alerts.';
            state.alertsLastSync = null;
            state.auditLogs = [];
            state.auditLogsSource = 'unauthorized';
            state.auditLogsError = 'Cần đăng nhập Cognito để đọc GET /logs.';
            state.auditLogsLastSync = null;
            state.cloudwatch = null;
            state.snsStatus = null;
            state.snsLastSync = null;
            state.snsError = 'Cần đăng nhập Cognito để kiểm tra SNS.';
            if (showError)
                notify('Để xem dữ liệu AWS, hãy bấm Đăng nhập AWS ở góc trên bên phải. Bạn cũng có thể mở Cấu hình để dùng chế độ demo.');
        }
        else {
            const response = isAws() ? await awsRequest('/devices') : stored('ha-tang-v1-demo', DEMO_DEVICES);
            const rows = asArray(response, ['items', 'Items', 'devices']);
            if (!rows)
                throw new Error('API /devices phải trả về một mảng hoặc object có items / devices / Items.');
            const normalized = rows.map(normalizeDevice);
            if (normalized.some(device => !device))
                throw new Error('Dữ liệu thiết bị thiếu trường deviceId hợp lệ.');
            state.devices = normalized;
            state.loaded = true;
            state.error = '';
            state.lastUpdate = isoNow();
            state.samples = stored(scopedKey('samples'), []);
            await loadOptionalResources();
            // [SAMPLE-ORDER] Chỉ lấy mẫu sau khi EC2 đã được thay bằng CloudWatch.
            addSample();
            maybeShowAlerts();
        }
    }
    catch (error) {
        state.error = error.message;
        if (error.status === 401)
            state.error += ' Phiên có thể đã hết hạn, hãy đăng nhập lại.';
        if (showError)
            notify(state.error);
    }
    finally {
        // [AUTO-REFRESH] Đặt mốc tiếp theo sau khi tải xong (kể cả khi lỗi).
        // Tránh việc vừa bấm Tải lại đã bị vòng tự động tải tiếp ngay.
        if (settings.interval > 0) {
            state.nextAutoAt = Date.now() + settings.interval * 1000;
        }
        setBusy(false);
        renderAll();
    }
}

// ================================================================
// [AUTO-REFRESH] Cập nhật dữ liệu AWS theo chu kỳ do người dùng chọn.
// - Mỗi giây chỉ cập nhật đồng hồ trên giao diện, KHÔNG gọi API.
// - Chỉ gọi API sau chu kỳ 30/60/120 giây, tránh request chồng nhau.
// - Tạm hoãn khi tab ẩn, mất mạng, chưa đăng nhập, đang mở form/popup.
// - Khi quay lại tab hoặc đóng form, tự tiếp tục nếu đã đến hạn.
// - Không làm thay đổi lịch EventBridge của Lambda simulator (5 phút).
// ================================================================
function autoRefreshBlockReason() {
    if (document.hidden) return 'Tab đang ẩn';
    if (!navigator.onLine) return 'Đang mất kết nối mạng';
    if (state.loading) return 'Đang tải dữ liệu';
    if (isAws() && isCognitoApi() && !hasToken()) return 'Cần đăng nhập Cognito';
    if (document.querySelector('dialog[open]')) return 'Đang mở hộp thoại';

    const element = document.activeElement;
    // Chi tam hoan khi con tro dang o o nhap/chon.
    // Neu nut Luu van dang focus thi KHONG duoc dung auto refresh mai mai.
    const editingField = element && ['INPUT', 'SELECT', 'TEXTAREA'].includes(element.tagName);
    if (editingField && (
        $('settings-form')?.contains(element) ||
        $('device-form')?.contains(element)
    )) {
        return 'Đang chỉnh sửa biểu mẫu';
    }
    return '';
}

function renderAutoRefreshStatus() {
    const status = $('auto-refresh-status');
    const toggle = $('auto-refresh-toggle');
    const quick = $('quick-refresh-interval');
    if (!status || !toggle || !quick) return;
    if (quick.value !== String(settings.interval)) quick.value = String(settings.interval);

    const interval = Number(settings.interval);
    const off = interval === 0;
    const blocked = autoRefreshBlockReason();
    let message = '';
    let stateName = 'active';

    if (off) {
        message = 'Tự động: Tắt';
        stateName = 'off';
    } else if (state.autoPaused) {
        message = 'Tự động: Tạm dừng';
        stateName = 'paused';
    } else if (blocked) {
        message = `Tạm hoãn · ${blocked}`;
        stateName = 'paused';
    } else {
        const seconds = Math.max(0, Math.ceil(((state.nextAutoAt ?? Date.now()) - Date.now()) / 1000));
        message = `Tự động · còn ${seconds}s`;
    }
    status.textContent = message;
    status.dataset.state = stateName;
    toggle.textContent = off ? 'Chọn chu kỳ' : state.autoPaused ? '▶ Tiếp tục' : 'Ⅱ Tạm dừng';
    toggle.setAttribute('aria-pressed', String(!off && !state.autoPaused));
    toggle.title = off ? 'Chọn chu kỳ tải lại' : state.autoPaused ? 'Bật lại tải tự động' : 'Tạm dừng tải tự động';
    toggle.setAttribute('aria-label', toggle.title);
}

function startPolling() {
    if (state.intervalId !== null) clearInterval(state.intervalId);
    state.intervalId = null;
    state.nextAutoAt = settings.interval > 0
        ? Date.now() + settings.interval * 1000
        : null;
    if (settings.interval > 0) {
        state.intervalId = setInterval(() => {
            renderAutoRefreshStatus();
            if (state.autoPaused || Date.now() < state.nextAutoAt) return;
            if (autoRefreshBlockReason()) return;

            // Đánh dấu trước khi gọi để không gửi yêu cầu trùng.
            state.nextAutoAt = Date.now() + settings.interval * 1000;
            void loadAll(false);
        }, 1000);
    }
    renderAutoRefreshStatus();
}
function mean(field) {
    const list = state.devices.map(row => valueNumber(row[field])).filter(value => value != null);
    return list.length ? Math.round(list.reduce((sum, val) => sum + val, 0) / list.length) : null;
}
function deviceState(row) {
    const status = String(row.status ?? '').toUpperCase();
    if (status === 'OFFLINE')
        return 'OFFLINE';
    // [FRESHNESS] Dữ liệu cũ KHÔNG đồng nghĩa thiết bị mất kết nối.
    // Chỉ áp dụng với thiết bị có timestamp được thu thập thực tế/mô phỏng.
    const last = registeredEc2(row) ? row.metricSampleTime : row.lastUpdated;
    if (registeredEc2(row) && !last && row.cpuUsage == null && row.memoryUsage == null) return 'UNKNOWN';
    if (last && (row.instanceId || String(row.metricsSource).toUpperCase() === 'SIMULATED')) {
        const t = Date.parse(last);
        if (Number.isFinite(t) && Date.now() - t > 20 * 60 * 1000) return 'STALE';
    }
    if (
        status === 'WARNING' ||
        isMetricHigh(row.cpuUsage, 'CPU') ||
        isMetricHigh(row.memoryUsage, 'RAM')
    )
        return 'WARNING';
    if (status === 'ONLINE')
        return 'ONLINE';
    return 'UNKNOWN';
}
function statusChip(status) {
    const types = { ONLINE: ['online', 'Hoạt động'], WARNING: ['warning', 'Cảnh báo'], OFFLINE: ['offline', 'OFFLINE (khai báo)'], UNKNOWN: ['unknown', 'Không rõ'], STALE: ['unknown', 'Dữ liệu cũ'] };
    const [css, label] = types[status] || types.UNKNOWN;
    return `<span class="status-chip ${css}">${label}</span>`;
}
const metricLabel = val => valueNumber(val) == null ? '—' : `${valueNumber(val)}%`;
function kpi(label, count, help, icon, type = '') {
    return `<div class="kpi-card"><span>${escapeHtml(label)}</span><span class="kpi-icon ${type}">${icon}</span><strong>${escapeHtml(count)}</strong><small>${escapeHtml(help)}</small></div>`;
}
// ================================================================
// [06 - GIAO DIEN] Vẽ Dashboard, thiết bị, Metrics, cảnh báo, nhật ký
// ================================================================
function renderHeader() {
    $('connection-badge').className = 'connection-badge';
    const dot = $('side-dot');
    dot.className = 'connect-dot';
    if (!isAws()) {
        $('connection-badge').classList.add('demo');
        $('connection-badge').textContent = '● CHẾ ĐỘ DEMO';
        dot.classList.add('error');
    }
    else if (state.loaded && !state.error) {
        $('connection-badge').classList.add('connected');
        $('connection-badge').textContent = '● AWS · API HOẠT ĐỘNG';
        dot.classList.add('ok');
    }
    else {
        $('connection-badge').classList.add('error');
        $('connection-badge').textContent = state.error ? '● AWS · CHƯA KẾT NỐI' : '● AWS · CHỜ DỮ LIỆU';
    }
    $('sign-in').hidden = !isCognitoApi() || hasToken();
    $('sign-out').hidden = !isCognitoApi() || !hasToken();
    $('last-update').textContent = state.lastUpdate ? `Cập nhật lúc ${timeText(state.lastUpdate)}` : 'Chưa cập nhật';
    $('hero-source').textContent = isAws() ? 'Nguồn: API Gateway /devices' : 'Nguồn: dữ liệu demo';
    $('footer-status').textContent = state.lastUpdate ? `Lần tải cuối: ${timeText(state.lastUpdate)}` : 'Chưa tải dữ liệu';
    renderAutoRefreshStatus();
}
function renderOverview() {
    const total = state.devices.length;
    const online = state.devices.filter(d => deviceState(d) === 'ONLINE').length;
    const warning = state.devices.filter(d => deviceState(d) !== 'ONLINE').length;
    const openAlerts = state.alerts.filter(a => !a.handled).length;
    const hasData = state.loaded;
    $('stats').innerHTML = [
        kpi('Tổng thiết bị', hasData ? total : '—', 'Đang quản lý', '▤'),
        kpi('Đang hoạt động', hasData ? online : '—', 'Trạng thái khai báo ONLINE', '✓', 'blue'),
        kpi('Thiết bị bất thường', hasData ? warning : '—', 'Quá ngưỡng / dữ liệu cũ / trạng thái nhập', '⚠', 'orange'),
        kpi('Cảnh báo chưa xử lý', hasData ? openAlerts : '—', 'Cần kiểm tra', '⚑', 'red')
    ].join('');
    $('health-title').textContent = !hasData ? 'Trung tâm điều hành mạng' : openAlerts || warning ? 'Phát hiện thiết bị cần chú ý' : 'Hạ tầng đang hoạt động ổn định';
    $('health-description').textContent = !hasData ? 'Đăng nhập Cognito để kết nối với hệ thống AWS.'
        : openAlerts ? `Có ${openAlerts} cảnh báo chưa xử lý. Hãy kiểm tra Trung tâm cảnh báo.`
            : `Đang theo dõi ${total} thiết bị. ${isAws() ? 'Dữ liệu lấy từ API Gateway.' : 'Đây là dữ liệu minh họa.'}`;
    const problems = state.devices.filter(d => deviceState(d) !== 'ONLINE');
    $('attention-devices').innerHTML = problems.length ? problems.slice(0, 4).map(device => `
    <div class="device-item"><span class="device-avatar">${deviceIcon(device.deviceType)}</span><div><strong>${escapeHtml(device.deviceName || device.deviceId)}</strong><small>${escapeHtml(device.ipAddress || device.deviceId)} · CPU ${metricLabel(device.cpuUsage)} / RAM ${metricLabel(device.memoryUsage)}</small></div><div class="right">${statusChip(deviceState(device))}</div></div>`).join('')
        : `<div class="empty">${hasData ? 'Không có thiết bị bất thường.' : 'Chưa tải được danh sách thiết bị.'}</div>`;
    $('recent-alerts').innerHTML = state.alerts.length ? state.alerts.slice(0, 4).map(entry => `
    <div class="recent-row"><div><strong>${escapeHtml(entry.deviceName)} · ${escapeHtml(entry.metric)}</strong><small>${timeText(entry.time)} · ${entry.value == null ? escapeHtml(entry.alarmState || 'Chưa có giá trị') : `${entry.value}%`}</small></div>${entry.handled ? ('<span class="status-chip online">' + escapeHtml(entry.statusLabel || 'Đã xử lý') + '</span>') : '<span class="status-chip warning">Chưa xử lý</span>'}</div>`).join('')
        : `<div class="empty">${hasData ? 'Không có cảnh báo.' : 'Chưa có dữ liệu cảnh báo.'}</div>`;
    const rows = [
        ['▤', 'API Gateway / DynamoDB', hasData && isAws() ? 'Đã đọc GET /devices' : isAws() ? 'Chưa xác nhận kết nối' : 'Demo', hasData && isAws() ? 'ONLINE' : 'UNKNOWN'],
        ['⚑', 'Cảnh báo DynamoDB', state.alertsSource === 'aws' ? 'Đã đọc GET /alerts' : 'Chưa đọc được dữ liệu từ GET /alerts; tạm theo dõi trong trình duyệt', state.alertsSource === 'aws' ? 'ONLINE' : 'UNKNOWN'],
        ['⌁', 'CloudWatch Metrics', state.metricsSource === 'aws' ? 'Có phản hồi GET /metrics' : 'Chưa đọc được dữ liệu từ GET /metrics', state.metricsSource === 'aws' ? 'ONLINE' : 'UNKNOWN'],
        ['✉', 'Amazon SNS', state.snsStatus?.configured
            ? `${Number(state.snsStatus.confirmedEmailSubscriptions || 0)} email đã xác nhận · không xác minh đã nhận thư`
            : 'Chưa xác minh Topic qua GET /sns/status',
        state.snsStatus?.configured && Number(state.snsStatus.confirmedEmailSubscriptions || 0) > 0 ? 'ONLINE' : 'UNKNOWN']
    ];
    // [SNS-OVERVIEW] Kiem tra truc tiep SNS tu man hinh Tong quan.
    // Hoat dong = co Topic va email subscription Confirmed; KHONG la giao thu.
    $('integration-list').innerHTML = rows.map(([icon, label, detail, chip]) => {
        const isSnsRow = label === 'Amazon SNS';
        const text = isSnsRow && state.snsStatus?.configured === true
            ? (chip === 'ONLINE' ? 'Có đăng ký email' : 'Chưa có email xác nhận')
            : isSnsRow ? 'Chưa kiểm tra' : 'Chưa xác nhận';
        const badge = chip === 'UNKNOWN'
            ? `<span class="status-chip unknown">${text}</span>`
            : isSnsRow
                ? '<span class="status-chip online">Hoạt động</span>'
                : statusChip(chip);
        const action = isSnsRow
            ? '<button type="button" class="btn btn-outline sns-check-overview" data-check-sns-overview>Kiểm tra SNS</button>'
            : '';
        return `<div class="integration-row"><span class="integration-icon">${icon}</span><div class="integration-copy"><strong>${escapeHtml(label)}</strong><small>${escapeHtml(isSnsRow && !state.snsStatus?.configured && state.snsError ? state.snsError : detail)}</small></div>${badge}${action}</div>`;
    }).join('');
    const pending = state.alerts.filter(a => !a.handled).length;
    $('nav-alert-count').hidden = pending === 0;
    $('nav-alert-count').textContent = String(pending);
    $('overview-chart').innerHTML = chartSvg(state.samples);
    $('chart-origin').textContent = 'Mẫu trình duyệt';
}
function deviceIcon(type) {
    const label = String(type || '').toLowerCase();
    if (label.includes('server') || label.includes('máy chủ'))
        return '▣';
    if (label.includes('switch'))
        return '▦';
    if (label.includes('router') || label.includes('gateway'))
        return '⇄';
    if (label.includes('firewall'))
        return '⬡';
    return '◇';
}
function chartSvg(samples, fromAws = false) {
    // CloudWatch: timestamps thật; các khoảng mất mẫu không được tự tạo/nối.
    const width = 720, height = 252, left = 43, right = 17, top = 23, bottom = 37;
    const x1 = left, x2 = width - right, y1 = top, y2 = height - bottom;
    const grid = [0, 25, 50, 75, 100].map(v => {
        const y = y2 - (y2 - y1) * v / 100;
        return `<line x1="${x1}" y1="${y}" x2="${x2}" y2="${y}" stroke="#2a4159" stroke-dasharray="4 6"/><text x="3" y="${y + 4}" fill="#9cb2c8" font-size="12">${v}%</text>`;
    }).join('');
    if (!samples.length) return `<div class="empty">${fromAws
        ? 'Chưa có mẫu CloudWatch trong khoảng đã chọn. Kiểm tra máy EC2 và tác vụ gửi metric RAM đang hoạt động.'
        : 'Chưa có dữ liệu biểu đồ. Tải lại thiết bị để tạo mẫu trên trình duyệt.'}</div>`;
    const rows = fromAws ? samples : samples.slice(-36); // EC2: phải giữ cả 24h, không chỉ 120 điểm cuối.
    const endTime = Date.now();
    const startTime = endTime - state.ec2HistoryMinutes * 60000;
    const times = rows.map(v => Date.parse(v.time));
    const xAt = i => {
        if (fromAws && Number.isFinite(times[i])) {
            const fraction = (times[i] - startTime) / (endTime - startTime);
            return x1 + (x2 - x1) * Math.max(0, Math.min(1, fraction));
        }
        return x1 + (x2 - x1) * (rows.length === 1 ? 0.5 : i / (rows.length - 1));
    };
    const series = (name, color) => {
        const selected = rows.map((row, i) => ({ t: times[i], v: valueNumber(row[name]), x: xAt(i) }))
            .filter(p => p.v != null && (!fromAws || Number.isFinite(p.t)));
        if (!selected.length) return '';
        const diffs = selected.slice(1).map((p, i) => p.t - selected[i].t).filter(ms => ms > 0).sort((a,b) => a-b);
        const typicalGap = diffs.length ? diffs[Math.floor(diffs.length / 2)] : 300000;
        const maxGap = fromAws ? Math.max(typicalGap * 1.8, name === 'cpu' ? 480000 : 180000) : Infinity;
        let last = null, parts = [], segment = [];
        const flush = () => {if (segment.length > 1) parts.push(`<polyline points="${segment.join(' ')}" fill="none" stroke="${color}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>`); segment=[];};
        for (const point of selected) {
            const y = y2 - (y2 - y1) * Math.max(0, Math.min(100, point.v)) / 100;
            if (last && fromAws && point.t - last.t > maxGap) flush();
            segment.push(`${point.x.toFixed(2)},${y.toFixed(2)}`);
            parts.push(`<circle cx="${point.x.toFixed(2)}" cy="${y.toFixed(2)}" r="3.5" fill="${color}"><title>${name.toUpperCase()}: ${point.v}%${fromAws ? ' — ' + new Date(point.t).toLocaleString('vi-VN') : ''}</title></circle>`);
            last = point;
        }
        flush();
        return parts.join('');
    };
    const thresholdLine = (value, color) => {
        const v = Number(value);
        if (!fromAws || !Number.isFinite(v) || v < 1 || v > 99) return '';
        const y = y2 - (y2-y1) * v / 100;
        return `<line x1="${x1}" y1="${y}" x2="${x2}" y2="${y}" stroke="${color}" stroke-width="1.6" stroke-dasharray="9 6" opacity="0.86"/>`;
    };
    const ticks = fromAws ? [0, .5, 1].map(f => {
        const t = new Date(startTime + (endTime - startTime) * f);
        const label = state.ec2HistoryMinutes > 360
            ? t.toLocaleString('vi-VN',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'})
            : t.toLocaleTimeString('vi-VN',{hour:'2-digit',minute:'2-digit'});
        return `<text x="${x1 + (x2 - x1)*f}" y="${height-9}" text-anchor="${f===0?'start':f===1?'end':'middle'}" fill="#9cb2c8" font-size="12">${escapeHtml(label)}</text>`;
    }).join('') : '';
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="Biểu đồ CPU và RAM ${fromAws ? 'EC2 CloudWatch ' + formatEc2HistoryRange(state.ec2HistoryMinutes) + ' và ngưỡng cảnh báo' : 'mẫu trình duyệt'}">${grid}${thresholdLine(settings.cpuThreshold,'#f5b45c')}${thresholdLine(settings.ramThreshold,'#ee7d97')}<line x1="${x1}" y1="${y2}" x2="${x2}" y2="${y2}" stroke="#415774"/>${series('cpu','#4ee1bf')}${series('ram','#70a8ff')}${ticks}</svg>`;
}
// [METRICS-HISTORY-SELECT] Lựa chọn đồ thị EC2 thật hoặc mẫu trình duyệt.
function activeSamples() {
    // [CHART-PROVENANCE] Khong dung mau trinh duyet de gia lam lich su EC2.
    if (state.selectedHistoryInstance) {
        const series = state.ec2HistoryCache.get(`${state.selectedHistoryInstance}:${state.ec2HistoryMinutes}`)?.rows;
        return Array.isArray(series) ? series : [];
    }
    // Trang tong quan va 'Trung binh thiet bi' chi dung mau dang luu tai trinh duyet.
    return state.samples;
}

function meterRow(device) {
    const bar = (label, value, type) => {
        const number = valueNumber(value);
        const high = number != null && isMetricHigh(number, label);
        return `<div class="bar-label"><span>${label}</span><span>${metricLabel(value)}</span></div><div class="bar-track ${type} ${high ? 'high' : ''}"><span style="width:${number ?? 0}%"></span></div>`;
    };
    const isRealEc2 = Boolean(device.instanceId) ||
        String(device.metricsSource ?? device.monitoringSource ?? '').toUpperCase() === 'CLOUDWATCH';
    const source = isRealEc2 ? 'EC2 · CloudWatch' :
        String(device.metricsSource || 'Chưa rõ nguồn').toUpperCase() === 'SIMULATED' ? 'Mô phỏng' : 'Nhập tay / DynamoDB';
    return `<div class="meter-row">
        <div class="meter-row-header">
            <div><strong>${escapeHtml(device.deviceName || device.deviceId)}</strong>
                <small class="meter-source">${escapeHtml(device.deviceId)} · ${escapeHtml(source)}</small></div>
            ${statusChip(deviceState(device))}
        </div>
        <div class="bar-pair">${bar('CPU', device.cpuUsage, 'cpu')}${bar('RAM', device.memoryUsage, 'ram')}</div>
    </div>`;
}
function formatBytes(value) {
    // [METRICS-NETWORK] Đọc NetworkIn/NetworkOut khi API cung cấp các trường này.
    // null la CHUA CO DU LIEU, khong duoc hien thanh 0 B.
    if (value === null || value === undefined || value === '') {
        return '—';
    }

    const n = Number(value);
    if (!Number.isFinite(n) || n < 0) {
        return '—';
    }
    if (n >= 1073741824)
        return `${(n / 1073741824).toFixed(2)} GB`;
    if (n >= 1048576)
        return `${(n / 1048576).toFixed(2)} MB`;
    if (n >= 1024)
        return `${(n / 1024).toFixed(1)} KB`;
    return `${n.toFixed(0)} B`;
}
// [EC2-HISTORY-RANGE] Định dạng khoảng xem lịch sử CloudWatch (không phải chu kỳ lấy mẫu).
const ec2HistoryPresets = new Set([15, 30, 60, 180, 360, 720, 1440]);
function formatEc2HistoryRange(minutes) {
    if (minutes < 60) return `${minutes} phút`;
    const hours = Math.floor(minutes / 60);
    const rem = minutes % 60;
    return `${hours} giờ${rem ? ` ${rem} phút` : ''}`;
}
// [EC2-HISTORY] EC2 CloudWatch history: only fetched when the user opens/changes the chart.
// Separate from the automatic /metrics refresh, limiting additional AWS API requests.
async function loadEc2History(force = false) {
    const instanceId = state.selectedHistoryInstance;
    if (!instanceId || !isAws() || !hasToken()) return;
    const minutes = state.ec2HistoryMinutes;
    const key = `${instanceId}:${minutes}`;
    const cached = state.ec2HistoryCache.get(key);
    if (!force && cached && Date.now() - cached.fetchedAt < 120000) {
        renderMetrics();
        return;
    }
    const requestId = ++state.ec2HistoryRequestSeq;
    state.ec2HistoryFetching = true;
    state.ec2HistoryError = '';
    renderMetrics();
    try {
        const query = `/metrics?historyMinutes=${minutes}&instanceId=${encodeURIComponent(instanceId)}`;
        const payload = await awsRequest(query, 'GET');
        if (requestId !== state.ec2HistoryRequestSeq) return;
        if (!payload || !Array.isArray(payload.history) || payload.instanceId !== instanceId)
            throw new Error('API chưa hỗ trợ lịch sử EC2 cho khoảng thời gian này.');
        const rows = payload.history.map(row => ({
            time: row.time ?? null,
            cpu: valueNumber(row.cpu),
            ram: valueNumber(row.ram)
        })).filter(row => row.time && (row.cpu != null || row.ram != null));
        state.ec2HistoryCache.set(key, {
            rows, fetchedAt: Date.now(), samples: payload.samples || {}
        });
        // Bound local cache, don't accumulate history indefinitely.
        if (state.ec2HistoryCache.size > 15)
            state.ec2HistoryCache.delete(state.ec2HistoryCache.keys().next().value);
    } catch (error) {
        if (requestId === state.ec2HistoryRequestSeq)
            state.ec2HistoryError = error.message || 'Không đọc được lịch sử EC2.';
    } finally {
        if (requestId === state.ec2HistoryRequestSeq) {
            state.ec2HistoryFetching = false;
            renderMetrics();
        }
    }
}
function fmtMetricSampleTime(value) {
    if (!value) return 'Chưa có mẫu';
    return timeText(value);
}
function ec2AlarmSummary(records) {
    const ec2Ids = new Set(records.flatMap(row => [row.deviceId, row.instanceId]).filter(Boolean).map(String));
    const cloudwatchEvents = state.alerts.filter(row =>
        row.origin === 'aws' && String(row.sourceLabel || '').toUpperCase() === 'CLOUDWATCH' &&
        ec2Ids.has(String(row.deviceId))
    );
    const active = cloudwatchEvents.filter(row => row.alarmState === 'ALARM' && !row.resolved);
    const tag = $('ec2-alert-summary');
    if (!tag) return;
    tag.textContent = cloudwatchEvents.length
        ? `NetworkAlerts: ${active.length} sự kiện ALARM chưa hoàn tất / ${cloudwatchEvents.length} sự kiện EC2 đã ghi`
        : 'Chưa có sự kiện EC2 trong NetworkAlerts; xem trạng thái Alarm trực tiếp tại AWS CloudWatch.';
}

function renderMetrics() {
    const records = state.cloudwatch?.instances || [];
    const first = records.find(row => !row.stale && (row.cpu != null || row.memory != null)) || records[0] || null;
    const measured = state.devices.filter(d => valueNumber(d.cpuUsage) != null || valueNumber(d.memoryUsage) != null);
    const simulatedCount = state.devices.filter(d => !d.instanceId &&
        String(d.metricsSource || '').toUpperCase() === 'SIMULATED').length;
    $('metric-stats').innerHTML = [
        kpi('CPU TB thiết bị', state.loaded ? metricLabel(mean('cpuUsage')) : '—', 'Từ thiết bị đã có số đo · gồm mô phỏng', '⌁'),
        kpi('RAM TB thiết bị', state.loaded ? metricLabel(mean('memoryUsage')) : '—', 'Chỉ tính các giá trị RAM có dữ liệu', '≋', 'blue'),
        kpi('Thiết bị có dữ liệu', state.loaded ? measured.length : '—', 'CPU hoặc RAM có giá trị', '▣'),
        kpi('Thiết bị mô phỏng', state.loaded ? simulatedCount : '—', 'Nguồn SIMULATED trong NetworkDevices', '◷', 'orange')
    ].join('');

    // [METRICS-SELECT] Ten EC2 lay theo deviceId/instanceId dung, khong lap ten.
    // Select trong dark mode dung color-scheme dark (CSS), ke ca dropdown native.
    const selector = $('history-instance-select');
    const options = ['<option value="">Tổng quan CPU/RAM thiết bị</option>']
        .concat(records.map(item =>
            `<option value="${escapeHtml(item.instanceId)}">EC2 CloudWatch · ${escapeHtml(item.deviceName)}</option>`
        ));
    selector.innerHTML = options.join('');
    if (!state.ec2HistorySelectionMade && records.length) {
        state.selectedHistoryInstance = records[0].instanceId;
        state.ec2HistorySelectionMade = true;
    }
    if (state.selectedHistoryInstance && records.some(x => x.instanceId === state.selectedHistoryInstance)) {
        selector.value = state.selectedHistoryInstance;
    } else {
        state.selectedHistoryInstance = '';
        selector.value = '';
    }

    if (document.activeElement !== $('ec2-history-minutes')) {
        $('ec2-history-minutes').value = String(state.ec2HistoryMinutes);
        $('ec2-history-preset').value = ec2HistoryPresets.has(state.ec2HistoryMinutes)
            ? String(state.ec2HistoryMinutes) : 'custom';
    }
    const showAws = Boolean(state.selectedHistoryInstance);
    $('ec2-history-controls').hidden = !showAws;
    $('ec2-custom-range').hidden = $('ec2-history-preset').value !== 'custom';
    $('metrics-chart-subtitle').textContent = showAws ? 'CloudWatch · 15 phút – 24 giờ' : 'Tối đa 36 mẫu trung bình gần nhất';
    const chartData = activeSamples();
    $('metrics-chart').innerHTML = chartSvg(chartData, showAws);
    const cached = state.ec2HistoryCache.get(`${state.selectedHistoryInstance}:${state.ec2HistoryMinutes}`);
    $('history-source-detail').textContent = showAws
        ? state.ec2HistoryFetching ? 'Đang đọc lịch sử thật từ CloudWatch…'
            : state.ec2HistoryError ? `Không đọc được lịch sử: ${state.ec2HistoryError}`
            : cached ? (chartData.length
                ? `CloudWatch · ${formatEc2HistoryRange(state.ec2HistoryMinutes)} gần nhất · CPU ${cached.samples.cpu ?? 0} mẫu / RAM ${cached.samples.ram ?? 0} mẫu · tải lúc ${timeText(new Date(cached.fetchedAt).toISOString())}`
                : `Không có điểm đo trong ${formatEc2HistoryRange(state.ec2HistoryMinutes)} vừa qua. Hãy thử khoảng xem dài hơn và kiểm tra CloudWatch.`)
            : 'Chọn khoảng thời gian xem.'
        : `Trình duyệt · ${chartData.length}/36 mẫu tổng hợp`;
    const thresholdHint = $('ec2-threshold-hint');
    if (thresholdHint) thresholdHint.textContent = showAws ? `Ngưỡng tham chiếu NetMon: CPU ${settings.cpuThreshold}% · RAM ${settings.ramThreshold}%` : '';

    $('meters').innerHTML = state.devices.length
        ? state.devices.slice(0, 30).map(meterRow).join('')
        : '<div class="empty">Chưa có chỉ số thiết bị.</div>';

    $('cloudwatch-stats').innerHTML = [
        kpi('CPU EC2 thực tế', metricLabel(first?.cpu), first?.instanceId || 'Chưa có EC2', '⌁'),
        kpi('RAM EC2 thực tế', metricLabel(first?.memory), first?.memory != null ? 'NetMon/EC2 · mem_used_percent' : 'Chưa nhận được RAM thật', '▣', 'blue'),
        kpi('Network In', formatBytes(first?.networkIn), 'AWS/EC2 · Sum theo kỳ đo', '↓'),
        kpi('Network Out', formatBytes(first?.networkOut), 'AWS/EC2 · Sum theo kỳ đo', '↑', 'blue')
    ].join('');

    const hasValue = records.some(row => !row.stale &&
        (row.cpu != null || row.memory != null || row.networkIn != null || row.networkOut != null));
    const anyRecord = records.length > 0;
    $('cloudwatch-tag').textContent = hasValue
        ? `CloudWatch · ${records.length} EC2`
        : anyRecord ? 'EC2 · Chưa có số liệu' : 'Chưa nhận EC2';
    $('cloudwatch-tag').className = `status-chip ${hasValue ? 'online' : 'unknown'}`;
    $('metrics-updated').textContent = hasValue
        ? (first?.sampleTime ? '' : 'Chưa có thời gian đo')
        : 'Chưa có dữ liệu EC2';
    $('metrics-updated').hidden = Boolean(hasValue && first?.sampleTime);

    $('cloudwatch-instance-rows').innerHTML = records.length
        ? records.map(row => `
            <tr>
                <td><strong>${escapeHtml(row.deviceName)}</strong>
                    <small class="metric-source-caption">${escapeHtml(row.instanceId || row.deviceId || 'Không rõ instance')}</small></td>
                <td>${metricLabel(row.cpu)}</td>
                <td>${metricLabel(row.memory)}</td>
                <td>${formatBytes(row.networkIn)}</td>
                <td>${formatBytes(row.networkOut)}</td>
                <td>${row.stale ? '<span class="status-chip warning">Dữ liệu cũ</span>' :
                    (row.cpu == null && row.memory == null && row.networkIn == null && row.networkOut == null)
                        ? '<span class="status-chip unknown">Chưa có metric</span>'
                        : '<span class="status-chip online">CloudWatch EC2</span>'}</td>
                <td><strong>${row.sampleTime ? timeText(row.sampleTime) : 'Chưa có mẫu'}</strong>
                    <small class="metric-source-caption">CPU: ${fmtMetricSampleTime(row.sampleTimes?.cpu)}</small>
                    <small class="metric-source-caption">RAM: ${fmtMetricSampleTime(row.sampleTimes?.ram)}</small></td>
            </tr>
        `).join('')
        : '<tr><td colspan="7" class="empty">Không thấy EC2 trong GET /metrics. Đọc từ CloudWatch, không dùng số SIMULATED thay thế.</td></tr>';

    const note = state.cloudwatch?.truncatedCount > 0
        ? ` API có giới hạn; còn ${state.cloudwatch.truncatedCount} máy EC2 chưa lấy số liệu.`
        : '';
    $('cloudwatch-note').textContent =
        '—: Chưa có dữ liệu.' + note;
    ec2AlarmSummary(records);
}

// Phân trang phía giao diện: giữ bộ lọc, vị trí và lựa chọn khi tải lại AWS.
const tablePages = new Map();
function tablePageState(id) {
    if (!tablePages.has(id)) tablePages.set(id, { page: 1, size: 10 });
    return tablePages.get(id);
}
function pageSlice(id, rows) {
    const pagination = tablePageState(id);
    const pages = Math.max(1, Math.ceil(rows.length / pagination.size));
    pagination.page = Math.max(1, Math.min(pagination.page, pages));
    const start = (pagination.page - 1) * pagination.size;
    return { rows: rows.slice(start, start + pagination.size), pages, start, total: rows.length };
}
function paginatedRows(id, rows, render) {
    const data = pageSlice(id, rows);
    const p = tablePageState(id);
    const body = $(id);
    let bar = $(id + '-pagination');
    if (!bar) {
        bar = document.createElement('div');
        bar.id = id + '-pagination';
        bar.className = 'table-pagination';
        body.closest('.table-scroll').after(bar);
        bar.addEventListener('click', e => {
            const button = e.target.closest('button[data-page-step]');
            if (!button || button.disabled) return;
            p.page += Number(button.dataset.pageStep);
            render();
        });
        bar.addEventListener('change', e => {
            if (!e.target.matches('[data-page-size]')) return;
            const size = Number(e.target.value);
            if (![10, 20, 50].includes(size)) return;
            p.size = size;
            p.page = 1;
            render();
        });
    }
    // Chỉ cập nhật nội dung, không đăng ký listener trùng mỗi lần AWS đồng bộ.
    bar.innerHTML = `<span class="pagination-range" aria-live="polite">${data.total ? data.start + 1 : 0}–${Math.min(data.start + p.size, data.total)} / ${data.total} bản ghi</span>
        <div class="pagination-controls"><label>Số dòng <select data-page-size aria-label="Số dòng mỗi trang">${[10,20,50].map(size => `<option value="${size}" ${size === p.size ? 'selected' : ''}>${size}</option>`).join('')}</select></label>
        <button class="btn btn-outline btn-sm" type="button" data-page-step="${1-p.page}" ${p.page === 1 ? 'disabled' : ''} aria-label="Trang đầu">«</button>
        <button class="btn btn-outline btn-sm" type="button" data-page-step="-1" ${p.page === 1 ? 'disabled' : ''} aria-label="Trang trước">‹</button>
        <span class="pagination-position">Trang ${p.page} / ${data.pages}</span>
        <button class="btn btn-outline btn-sm" type="button" data-page-step="1" ${p.page >= data.pages ? 'disabled' : ''} aria-label="Trang tiếp">›</button>
        <button class="btn btn-outline btn-sm" type="button" data-page-step="${data.pages-p.page}" ${p.page >= data.pages ? 'disabled' : ''} aria-label="Trang cuối">»</button></div>`;
    return data.rows;
}
function resetTablePage(id, render) {
    tablePageState(id).page = 1;
    render();
}
function renderDevices() {
    const search = $('search').value.trim().toLowerCase();
    const filter = $('status-filter').value;
    const filtered = state.devices.map((d, i) => ({ d, i })).filter(({ d }) => {
        const text = [d.deviceName, d.deviceId, d.ipAddress, d.location, d.deviceType].join(' ').toLowerCase();
        return text.includes(search) && (filter === 'all' || deviceState(d) === filter);
    });
    $('device-counter').textContent = `${filtered.length} / ${state.devices.length} thiết bị`;
    const meter = (value, metric) => {
        const v = valueNumber(value);
        const high = isMetricHigh(v, metric);
        return `${metricLabel(value)}<span class="mini-meter"><i class="${high ? 'high' : ''}" style="width:${v ?? 0}%"></i></span>`;
    };
    $('device-rows').innerHTML = paginatedRows('device-rows', filtered, renderDevices).map(({ d, i }) => `
    <tr><td><div class="device-name"><span class="device-avatar">${deviceIcon(d.deviceType)}</span><div><strong>${escapeHtml(d.deviceName || d.deviceId)}</strong><small>${escapeHtml(d.deviceId)} · ${escapeHtml(d.deviceType || 'Khác')}</small><small class="metric-source-caption">${escapeHtml(d.metricSourceLabel || (d.instanceId ? 'EC2 cần CloudWatch' : String(d.metricsSource || 'Chưa rõ nguồn'))) + ' · ' + escapeHtml(d.metricSampleTime || d.lastUpdated ? 'Mẫu: ' + timeText(d.metricSampleTime || d.lastUpdated) : 'Chưa có thời gian mẫu')}</small></div></div></td>
    <td>${escapeHtml(d.ipAddress || '—')}</td><td>${escapeHtml(d.location || '—')}</td><td>${statusChip(deviceState(d))}</td><td>${meter(d.cpuUsage, 'CPU')}</td><td>${meter(d.memoryUsage, 'RAM')}</td>
    <td><div class="action-buttons"><button type="button" data-action="view" data-index="${i}">Xem</button><button type="button" data-action="edit" data-index="${i}">Sửa</button><button type="button" class="delete" data-action="delete" data-index="${i}">Xóa</button></div></td></tr>`).join('') || '<tr><td colspan="7" class="empty">Không tìm thấy thiết bị phù hợp.</td></tr>';
}
// [ALERT-SELECTION] Chi chon nhung canh bao con mo; bo loc khong xoa lua chon cu,
// nhung API dong bo co the dong mot canh bao va khi do lua chon tu huy.
function actionableAlert(entry) {
    return Boolean(entry && entry.id && !entry.handled && !entry.nonActionable);
}
function visibleAlerts() {
    const filter = $('alert-filter').value;
    return state.alerts.map((entry, index) => ({ entry, index })).filter(({ entry }) =>
        filter === 'all' || (filter === 'done' ? entry.handled : !entry.handled)
    );
}
function selectedActionableAlerts() {
    return state.alerts.filter(entry =>
        actionableAlert(entry) && state.selectedAlertIds.has(entry.id)
    );
}
function pruneAlertSelection() {
    const allowed = new Set(state.alerts.filter(actionableAlert).map(entry => entry.id));
    for (const id of state.selectedAlertIds) {
        if (!allowed.has(id)) state.selectedAlertIds.delete(id);
    }
}
function selectVisibleAlerts() {
    if (state.loading || state.bulkProcessing || (isAws() && state.alertsSource !== 'aws')) return;
    for (const { entry } of pageSlice('alert-rows', visibleAlerts()).rows) {
        if (actionableAlert(entry)) state.selectedAlertIds.add(entry.id);
    }
    renderAlerts();
}
function clearSelectedAlerts() {
    if (state.loading || state.bulkProcessing) return;
    state.selectedAlertIds.clear();
    renderAlerts();
}
function renderAlerts() {
    $('alerts-source').textContent = state.alertsSource === 'aws'
        ? ''
        : 'Chưa đồng bộ AWS · Dữ liệu trình duyệt';
    $('alerts-source').hidden = state.alertsSource === 'aws';

    $('alert-note').textContent = state.alertsSource === 'aws'
        ? ''
        : 'Cảnh báo trình duyệt chưa đồng bộ với AWS/SNS.';
    $('alert-note').hidden = state.alertsSource === 'aws';

    const newCount = state.alerts.filter(entry => actionableAlert(entry) && !entry.acknowledged).length;
    const acknowledgedCount = state.alerts.filter(entry => actionableAlert(entry) && entry.acknowledged).length;
    const resolvedCount = state.alerts.filter(entry => entry.handled && !entry.nonActionable && !entry.recovered).length;
    const recoveredCount = state.alerts.filter(entry => entry.recovered).length;
    $('alert-summary').innerHTML = `
        <div class="alert-summary-item"><strong>${state.alerts.length}</strong><span>Tổng sự kiện</span><i>⚑</i></div>
        <div class="alert-summary-item"><strong>${newCount}</strong><span>Chưa tiếp nhận (New)</span><i>!</i></div>
        <div class="alert-summary-item"><strong>${acknowledgedCount}</strong><span>Đã tiếp nhận (Acknowledged)</span><i>◷</i></div>
        <div class="alert-summary-item handled"><strong>${resolvedCount}</strong><span>Đã xử lý (Resolved)</span><i>✓</i></div>
        <div class="alert-summary-item handled"><strong>${recoveredCount}</strong><span>Đã phục hồi (Recovered)</span><i>↺</i></div>
    `;

    pruneAlertSelection();
    const bulkReady = !state.loading && !state.bulkProcessing &&
        (!isAws() || state.alertsSource === 'aws');
    const ackCount = bulkAlertCandidates('Acknowledged').length;
    const selectedCount = selectedActionableAlerts().length;
    const pageAlerts = paginatedRows('alert-rows', visibleAlerts(), renderAlerts);
    const visibleEligibleCount = pageAlerts.filter(({ entry }) => actionableAlert(entry)).length;
    const ackAll = $('alert-ack-all');
    const selectAll = $('alert-select-visible');
    const clear = $('alert-clear-selection');
    const resolveSelected = $('alert-resolve-selected');
    ackAll.disabled = !bulkReady || ackCount === 0;
    selectAll.disabled = !bulkReady || visibleEligibleCount === 0;
    clear.disabled = !bulkReady || selectedCount === 0;
    resolveSelected.disabled = !bulkReady || selectedCount === 0;
    ackAll.textContent = `✓ Tiếp nhận tất cả (${ackCount})`;
    resolveSelected.textContent = `✓ Hoàn tất đã chọn (${selectedCount})`;
    $('alert-selection-count').textContent =
        `Đã chọn: ${selectedCount}`;

    $('alert-rows').innerHTML = pageAlerts.map(({ entry, index }) => {
        const metricValue = entry.value == null
            ? (entry.alarmState ? ` · ${escapeHtml(entry.alarmState)}` : '')
            : ` · ${entry.value}%`;
        const severityChip = entry.severity === 'INFO'
            ? '<span class="status-chip online">Thông tin</span>'
            : entry.severity === 'CRITICAL'
                ? '<span class="status-chip offline">Nghiêm trọng</span>'
                : '<span class="status-chip warning">Cảnh báo</span>';
        const statusChipHtml = entry.handled
            ? `<span class="status-chip online">${escapeHtml(entry.statusLabel)}</span>`
            : entry.acknowledged
                ? '<span class="status-chip unknown">Đã tiếp nhận</span>'
                : '<span class="status-chip warning">Chưa tiếp nhận</span>';
        const actionHtml = entry.handled
            ? `<span class="muted">${entry.nonActionable ? 'Sự kiện lịch sử' : 'Đã xác nhận'}</span>`
            : `${entry.acknowledged ? '' : `<button type="button" class="btn btn-sm btn-outline" data-handle="${index}" data-status="Acknowledged" ${!bulkReady ? 'disabled' : ''}>Tiếp nhận</button>`}<button type="button" class="btn btn-sm btn-outline" data-handle="${index}" data-status="Resolved" ${!bulkReady ? 'disabled' : ''}>Hoàn tất xử lý</button>`;
        const sourceLabel = entry.origin === 'aws' ? entry.sourceLabel : 'Trình duyệt';
        const selectable = actionableAlert(entry);
        return `
            <tr class="${state.selectedAlertIds.has(entry.id) && selectable ? 'alert-row-selected' : ''}">
                <td class="alert-select-col"><input type="checkbox" class="alert-row-checkbox" data-alert-select="${index}"
                    aria-label="Chọn cảnh báo ${escapeHtml(entry.id)} của ${escapeHtml(entry.deviceName)}"
                    ${state.selectedAlertIds.has(entry.id) && selectable ? 'checked' : ''}
                    ${!selectable || !bulkReady ? 'disabled' : ''}></td>
                <td>${timeText(entry.time)}</td>
                <td><strong>${escapeHtml(entry.deviceName)}</strong><small>${escapeHtml(entry.deviceId)}</small></td>
                <td>${escapeHtml(entry.metric)}${metricValue}<small>${escapeHtml(sourceLabel)}</small></td>
                <td>${severityChip}</td>
                <td>${statusChipHtml}</td>
                <td>${actionHtml}</td>
            </tr>
        `;
    }).join('') || '<tr><td colspan="7" class="empty">Không có cảnh báo phù hợp.</td></tr>';
}
// Sơ đồ chỉ dựa trên danh sách thiết bị đã tải; không suy ra dây/cổng thật.
function topologyGroup(device) {
    const type = String(device.deviceType || '').toLowerCase();
    const sources = [device.metricsSource, device.monitoringSource].map(value => String(value || '').toUpperCase());
    if (device.instanceId || sources.includes('CLOUDWATCH') || type === 'ec2') return 'ec2';
    if (/router|gateway|firewall|tường lửa/.test(type)) return 'edge';
    if (/switch|access point|wi-?fi|wireless/.test(type)) return 'access';
    if (/server|máy chủ|pc|workstation|printer|client/.test(type)) return 'endpoint';
    return 'other';
}
let topologyZoom = null; // null = tự căn vừa khung
let topologySize = {width: 0, height: 0};
function sizeTopology() {
    const viewport = $('topology-viewport');
    const graph = $('topology-graph');
    const stage = $('topology-stage');
    if (!graph || !stage || !viewport.clientWidth) return;
    const fit = Math.max(.5, Math.min(1, (viewport.clientWidth - 16) / topologySize.width));
    const zoom = topologyZoom ?? fit;
    graph.style.transform = `scale(${zoom})`;
    stage.style.width = `${Math.ceil(topologySize.width * zoom)}px`;
    stage.style.height = `${Math.ceil(topologySize.height * zoom)}px`;
    $('topology-zoom-value').textContent = `${Math.round(zoom * 100)}%`;
}
function topologyGlyph(type) {
    const glyph = {
      internet: '<circle cx="32" cy="22" r="17"/><ellipse cx="32" cy="22" rx="8" ry="17"/><path d="M15 22h34M19 12h26M19 32h26"/>',
      router: '<rect x="6" y="10" width="52" height="25" rx="12"/><path d="M15 18h32l-5-5m5 5-5 5M49 27H17l5-5m-5 5 5 5"/>',
      firewall: '<path d="M9 9h46v27H9zM9 18h46M9 27h46M22 9v9m22-9v9M32 18v9m-10 0v9m22-9v9"/>',
      switch: '<rect x="4" y="10" width="56" height="25" rx="5"/><path d="M11 27h42"/><g fill="currentColor" stroke="none"><rect x="10" y="15" width="7" height="7" rx="1"/><rect x="19" y="15" width="7" height="7" rx="1"/><rect x="28" y="15" width="7" height="7" rx="1"/><rect x="37" y="15" width="7" height="7" rx="1"/><rect x="46" y="15" width="7" height="7" rx="1"/></g>',
      server: '<rect x="19" y="3" width="26" height="38" rx="4"/><path d="M23 15h18M23 26h18M27 10h1m-1 11h1m-1 11h1M33 10h7m-7 11h7m-7 11h7"/>',
      pc: '<rect x="9" y="5" width="46" height="28" rx="4"/><path d="M32 33v7M21 40h22"/>',
      wifi: '<path d="M7 14q25-20 50 0M15 23q17-14 34 0M23 31q9-8 18 0"/><circle cx="32" cy="38" r="2" fill="currentColor"/>',
      cloud: '<path d="M17 34a11 11 0 0 1-1-22A15 15 0 0 1 45 10a12 12 0 0 1 2 24Z"/>',
      other: '<path d="M32 3 56 22 32 41 8 22Z"/><circle cx="32" cy="22" r="4"/>'
    };
    return `<svg viewBox="0 0 64 44" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${glyph[type] || glyph.other}</svg>`;
}
function renderTopology() {
    const groups = [
        { key: 'edge', name: 'Thiết bị biên', desc: 'Router / Firewall', icon: '⇄' },
        { key: 'access', name: 'Thiết bị truy cập', desc: 'Switch / Wi-Fi', icon: '▦' },
        { key: 'endpoint', name: 'Thiết bị đầu cuối', desc: 'Server / Máy trạm', icon: '▣' },
        { key: 'other', name: 'Thiết bị khác', desc: 'Chưa xác định tầng mạng', icon: '◇' },
        { key: 'ec2', name: 'Máy chủ AWS EC2', desc: 'Dữ liệu CloudWatch nếu được API xác minh', icon: '☁' }
    ];
    const counts = { ONLINE: 0, WARNING: 0, OFFLINE: 0, STALE: 0, UNKNOWN: 0 };
    const query = $('topology-search').value.trim().toLowerCase();
    const filter = $('topology-status').value;
    const allItems = state.devices.map((device, index) => {
        const group = topologyGroup(device);
        const cloudwatchVerified = group === 'ec2' && isAws() && device.metricSourceLabel === 'CloudWatch EC2';
        const status = deviceState(device);
        const safeStatus = group === 'ec2' && !cloudwatchVerified && status !== 'OFFLINE' && status !== 'STALE' ? 'UNKNOWN' : status;
        counts[safeStatus] = (counts[safeStatus] || 0) + 1;
        return { device, index, status: safeStatus, group, cloudwatchVerified };
    });
    const items = allItems.filter(({device,status}) => (filter === 'all' || status === filter) &&
        [device.deviceName, device.deviceId, device.ipAddress, device.location, device.deviceType, device.instanceId].join(' ').toLowerCase().includes(query));
    $('topology-summary').innerHTML = `<span class="topology-total"><strong>${state.devices.length}</strong> thiết bị</span>` +
        Object.entries(counts).map(([status,count]) => `<span class="topology-count">${statusChip(status)} <strong>${count}</strong></span>`).join('');
    $('topology-match').textContent = `${items.length} / ${state.devices.length} thiết bị`;
    if (!items.length) {
        $('topology-stage').innerHTML = '<div class="empty">Không có thiết bị phù hợp. Sơ đồ sẽ cập nhật khi danh sách thiết bị thay đổi.</div>';
        $('topology-stage').removeAttribute('style');
        $('topology-zoom-value').textContent = '—';
        return;
    }
    const groupItems = key => items.filter(item => item.group === key);
    const viewport = $('topology-viewport');
    const oldLeft = viewport.scrollLeft, oldTop = viewport.scrollTop;
    const width = 1020, lan = {x:16,w:632}, cloud = {x:714,w:290};
    const nodes = [], links = [], labels = [];
    const coords = (area, n, i) => area.x + 34 + (area.w - 68) * (i + .5) / n;
    const path = (d, dashed=false) => links.push(`<path d="${d}" class="net-link${dashed ? ' net-link-dashed' : ''}"/>`);
    function fixedNode(x,y,type,title,sub) {
        nodes.push(`<div class="net-fixed" style="left:${x}px;top:${y}px"><span class="net-glyph">${topologyGlyph(type)}</span><strong>${title}</strong><small>${sub}</small></div>`);
    }
    function deviceNode(item,x,y) {
        const {device,index,status,group,cloudwatchVerified} = item;
        const type = String(device.deviceType || '').toLowerCase();
        const symbol = group === 'ec2' ? 'server' : /firewall|tường lửa/.test(type) ? 'firewall' : group === 'edge' ? 'router' : /wi-?fi|access point|wireless/.test(type) ? 'wifi' : group === 'access' ? 'switch' : /server|máy chủ/.test(type) ? 'server' : group === 'endpoint' ? 'pc' : 'other';
        const cpu = group === 'ec2' && !cloudwatchVerified ? null : device.cpuUsage;
        const ram = group === 'ec2' && !cloudwatchVerified ? null : device.memoryUsage;
        const rawSource = String(device.metricsSource || device.monitoringSource || '').toUpperCase();
        const source = !isAws() ? 'DEMO' : group === 'ec2' ? (cloudwatchVerified ? 'CloudWatch EC2' : 'EC2 · Chưa xác minh') : rawSource === 'SIMULATED' ? 'Mô phỏng' : rawSource === 'MANUAL' ? 'Nhập thủ công' : 'Chưa rõ nguồn';
        const name = escapeHtml(device.deviceName || device.deviceId || 'Thiết bị');
        const statusName = {ONLINE:'Hoạt động',WARNING:'Cảnh báo',OFFLINE:'Ngoại tuyến',STALE:'Dữ liệu cũ',UNKNOWN:'Không rõ'}[status] || 'Không rõ';
        const tip = escapeHtml(`${device.deviceName || device.deviceId} · ${device.ipAddress || 'Chưa có IP'} · ${device.location || 'Chưa có vị trí'} · ${statusName} · ${source}`);
        nodes.push(`<button type="button" class="net-node topology-${status.toLowerCase()}" style="left:${x}px;top:${y}px" data-device="${index}" title="${tip}" aria-label="Xem ${name}, ${statusName}"><span class="net-glyph">${topologyGlyph(symbol)}<i class="topology-dot"></i></span><strong>${name}</strong><small class="net-metric">CPU ${metricLabel(cpu)} · RAM ${metricLabel(ram)}</small><small class="net-source">${escapeHtml(source)}</small></button>`);
    }
    let y = 64;
    let prior = [];
    const local = items.filter(item=>item.group!=='ec2');
    if (local.length) {
        const center = lan.x + lan.w/2;
        fixedNode(center,y,'internet','Internet','');
        prior = [{x:center,y:y+74}];
        y += 112;
        for (const group of groups.slice(0,3)) {
            const list = groupItems(group.key);
            if (!list.length) continue;
            for (let offset=0;offset<list.length;offset+=4) {
                const row = list.slice(offset,offset+4);
                const positions = row.map((_,i)=>coords(lan,row.length,i));
                const bus = y-19;
                const ends = [...prior.map(n=>n.x),...positions];
                path(`M${Math.min(...ends)} ${bus}H${Math.max(...ends)}`);
                prior.forEach(n=>path(`M${n.x} ${n.y}V${bus}`));
                positions.forEach((x,i)=>{path(`M${x} ${bus}V${y}`);deviceNode(row[i],x,y);});
                labels.push(`<div class="net-layer-label" style="left:${lan.x+12}px;top:${y-42}px">${group.name}${offset ? ' · tiếp' : ''}</div>`);
                prior = positions.map(x=>({x,y:y+90}));
                y+=145;
            }
        }
        const other = groupItems('other');
        for(let offset=0;offset<other.length;offset+=4) {
            const row=other.slice(offset,offset+4);
            labels.push(`<div class="net-layer-label" style="left:${lan.x+12}px;top:${y-30}px">Thiết bị khác · chưa phân tầng</div>`);
            row.forEach((item,i)=>deviceNode(item,coords(lan,row.length,i),y));
            y+=130;
        }
    } else labels.push(`<div class="net-empty" style="left:${lan.x+20}px;top:95px;width:${lan.w-40}px">Không có thiết bị nội bộ.</div>`);
    const cloudX=cloud.x+cloud.w/2;
    fixedNode(cloudX,64,'cloud','NetMon Cloud','AWS Serverless');
    const ec2=groupItems('ec2');
    let cloudY=195;
    if (ec2.length) {
        labels.push(`<div class="net-cloud-caption" style="left:${cloudX}px;top:158px">CloudWatch</div>`);
        let parents=[{x:cloudX,y:145}];
        for(let offset=0;offset<ec2.length;offset+=2) {
            const row=ec2.slice(offset,offset+2), positions=row.map((_,i)=>cloud.x+cloud.w*(i+.5)/row.length), bus=cloudY-12;
            const ends=[...parents.map(n=>n.x),...positions];
            path(`M${Math.min(...ends)} ${bus}H${Math.max(...ends)}`,true);
            parents.forEach(n=>path(`M${n.x} ${n.y}V${bus}`,true));
            positions.forEach((x,i)=>{path(`M${x} ${bus}V${cloudY}`,true);deviceNode(row[i],x,cloudY);});
            parents=positions.map(x=>({x,y:cloudY+90})); cloudY+=132;
        }
    } else labels.push(`<div class="net-empty" style="left:${cloud.x+15}px;top:195px;width:${cloud.w-30}px">Không có EC2 phù hợp.</div>`);
    if(local.length) {
        path(`M${lan.x+lan.w/2+36} 90H${cloudX-36}`,true);
        labels.push(`<div class="net-connection-label" style="left:${(lan.x+lan.w/2+cloudX)/2}px;top:74px">Giám sát</div>`);
    }
    const height=Math.max(360,y-20,cloudY-15);
    topologySize={width,height};
    $('topology-stage').innerHTML=`<div id="topology-graph" style="width:${width}px;height:${height}px"><div class="net-zone" style="left:${lan.x}px;width:${lan.w}px;height:${height-28}px"><header>MẠNG DOANH NGHIỆP <span>${local.length} thiết bị</span></header></div><div class="net-zone net-zone-aws" style="left:${cloud.x}px;width:${cloud.w}px;height:${height-28}px"><header>AWS CLOUD <span>${ec2.length} EC2</span></header></div><svg class="net-wires" viewBox="0 0 ${width} ${height}" aria-hidden="true">${links.join('')}</svg>${labels.join('')}${nodes.join('')}</div>`;
    sizeTopology(); viewport.scrollLeft=oldLeft; viewport.scrollTop=oldTop;
}

// ================================================================
// [07A - AUDIT AWS] GET /logs -> DynamoDB Streams -> NetworkAuditLogs.
// Đây là sự kiện thay đổi bản ghi, KHÔNG xác nhận người IAM cụ thể.
// ================================================================
const auditFieldLabels = {
    deviceName: 'Tên',
    deviceType: 'Loại',
    ipAddress: 'IP',
    location: 'Vị trí',
    status: 'Trạng thái',
    cpuUsage: 'CPU',
    memoryUsage: 'RAM',
    instanceId: 'EC2',
    metricsSource: 'Nguồn metrics',
    monitoringSource: 'Nguồn giám sát'
};

function auditChangeSummary(row) {
    const action = String(row.eventName || row.action || '').toUpperCase();
    const names = Array.isArray(row.changedFields) ? row.changedFields : [];
    if (action === 'INSERT' || action === 'CREATE') {
        return 'Thiết bị đã được thêm vào NetworkDevices';
    }
    if (action === 'REMOVE' || action === 'DELETE') {
        return 'Thiết bị đã bị xóa khỏi NetworkDevices';
    }
    if (!names.length) {
        return 'Dữ liệu thiết bị được cập nhật (chưa có ảnh cũ để so sánh)';
    }
    return names.slice(0, 5).map(name => {
        const title = auditFieldLabels[name] || name;
        const oldValue = row.before?.[name];
        const newValue = row.after?.[name];
        const label = value => value == null || value === '' ? '—' : String(value);
        return `${title}: ${label(oldValue)} → ${label(newValue)}`;
    }).join(' · ') + (names.length > 5 ? ` · +${names.length - 5} trường` : '');
}

function renderDeviceAudit() {
    const status = $('device-audit-status');
    const info = $('device-audit-info');
    if (!status || !info) return;

    const connected = isAws() && state.auditLogsSource === 'aws';
    let reason = '';
    if (!isAws()) {
        reason = 'Chế độ Demo không có lịch sử thiết bị AWS.';
    } else if (isCognitoApi() && !hasToken()) {
        reason = 'Hãy đăng nhập Cognito để xem lịch sử thay đổi thiết bị từ AWS.';
    } else if (!connected) {
        reason = state.auditLogsError || 'Chưa đọc được GET /logs. Kiểm tra kết nối API và quyền đọc nhật ký AWS.';
    }

    status.className = `status-chip ${connected ? 'online' : 'unknown'}`;
    status.textContent = connected ? 'Đã đọc từ AWS' : 'Chưa kết nối';
    if (!connected) {
        info.textContent = reason;
        $('device-audit-count').textContent = '0 sự kiện';
        paginatedRows('device-audit-rows', [], renderDeviceAudit);
        $('device-audit-rows').innerHTML = `<tr><td colspan="5" class="empty">${escapeHtml(reason)}</td></tr>`;
        return;
    }

    info.textContent = `NetworkAuditLogs · Đồng bộ ${timeText(state.auditLogsLastSync)}`;
    const query = $('device-audit-search').value.trim().toLowerCase();
    const actionFilter = $('device-audit-filter').value;
    const rows = state.auditLogs
        .filter(row => {
            const action = String(row.eventName || '').toUpperCase();
            if (actionFilter !== 'all' && action !== actionFilter) return false;
            const summary = auditChangeSummary(row);
            return [row.deviceId, row.deviceName, row.eventName, summary, row.eventTime]
                .join(' ').toLowerCase().includes(query);
        })
        .sort((a, b) => new Date(b.eventTime || 0) - new Date(a.eventTime || 0));
    $('device-audit-count').textContent = `${rows.length} / ${state.auditLogs.length} thay đổi`;
    $('device-audit-rows').innerHTML = paginatedRows('device-audit-rows', rows, renderDeviceAudit).map(row => {
        const action = String(row.eventName || row.action || '').toUpperCase();
        const labels = {
            INSERT: ['online', 'Thêm thiết bị'],
            MODIFY: ['warning', 'Sửa thiết bị'],
            REMOVE: ['offline', 'Xóa thiết bị']
        };
        const [klass, text] = labels[action] || ['unknown', action || 'Không rõ'];
        return `<tr>
            <td>${timeText(row.eventTime)}</td>
            <td><span class="status-chip ${klass}">${escapeHtml(text)}</span></td>
            <td><strong>${escapeHtml(row.deviceName || row.deviceId || '—')}</strong>
                <small>${escapeHtml(row.deviceId || '')}</small></td>
            <td class="history-detail-cell">${escapeHtml(auditChangeSummary(row))}</td>
            <td><span class="history-source">DynamoDB Streams</span></td>
        </tr>`;
    }).join('') || '<tr><td colspan="5" class="empty">Không có thay đổi phù hợp bộ lọc.</td></tr>';
}

// ================================================================
// [07B - NHAT KY THAO TAC] localStorage tren trinh duyet hien tai.
// Luu y: thanh cong cua thao tac AWS khong dong nghia da co audit log AWS.
// De dong bo nhat ky thao tac giua cac may, can backend /logs rieng.
// ================================================================
function renderLogs() {
    const query = $('log-search').value.trim().toLowerCase();
    const entries = stored(scopedKey('operations'), []);

    entries.sort((a, b) =>
        new Date(b.time || 0).getTime() - new Date(a.time || 0).getTime()
    );

    const rows = entries
        .filter(entry =>
            [entry.action, entry.detail, entry.origin]
                .join(' ')
                .toLowerCase()
                .includes(query)
        )
        .slice(0, 200);

    $('operation-count').textContent = `${rows.length} thao tác`;
    $('operation-rows').innerHTML = paginatedRows('operation-rows', rows, renderLogs).map(entry => `
        <tr>
            <td>${timeText(entry.time)}</td>
            <td>${escapeHtml(entry.action)}</td>
            <td class="history-detail-cell">${escapeHtml(entry.detail)}</td>
            <td><span class="history-source history-source-local">Trình duyệt</span></td>
        </tr>
    `).join('') || `
        <tr>
            <td colspan="4" class="empty">Chưa có thao tác phù hợp trên trình duyệt này.</td>
        </tr>
    `;

    renderDeviceAudit();
    renderAwsHistory();
}

// ================================================================
// [07C - LICH SU CANH BAO AWS] API GET /alerts -> NetworkAlerts.
// Khong tron nhat ky trinh duyet vao day, khong gia lap du lieu AWS.
// [ALERT-FIELDS] eventId, eventTime, alarmState, handlingStatus,
// source, alarmType, metricValue, threshold, deviceId, deviceName.
// ================================================================
function renderAwsHistory() {
    const status = $('aws-history-status');
    const info = $('aws-history-info');
    const awsReady = isAws() && state.alertsSource === 'aws';
    let unavailableReason = '';

    if (!isAws()) {
        unavailableReason = 'Bạn đang dùng chế độ demo. Chuyển sang API AWS và đăng nhập để xem lịch sử thật.';
        status.textContent = 'Chế độ demo';
    } else if (isCognitoApi() && !hasToken()) {
        unavailableReason = 'Bạn chưa đăng nhập Cognito. Nhấn Đăng nhập AWS để lấy lịch sử từ DynamoDB.';
        status.textContent = 'Chưa đăng nhập';
    } else if (!awsReady) {
        unavailableReason = state.alertsError || 'Chưa đọc được API GET /alerts. Bấm Tải lại để thử lại.';
        status.textContent = 'Không kết nối';
    } else {
        status.textContent = 'Đã đọc từ AWS';
    }

    status.className = `status-chip ${awsReady ? 'online' : 'unknown'}`;

    if (!awsReady) {
        info.textContent = unavailableReason;
        $('aws-history-count').textContent = '0 sự kiện AWS';
        paginatedRows('aws-alert-history-rows', [], renderAwsHistory);
        $('aws-alert-history-rows').innerHTML = `
            <tr>
                <td colspan="7" class="empty">${escapeHtml(unavailableReason)}</td>
            </tr>
        `;
        return;
    }

    info.textContent = `NetworkAlerts qua GET /alerts · Đồng bộ ${timeText(state.alertsLastSync)}`;

    const search = $('aws-alert-search').value.trim().toLowerCase();
    const sourceFilter = $('aws-alert-source-filter').value;
    const statusFilter = $('aws-alert-status-filter').value;

    const rows = state.alerts
        .filter(alert => alert.origin === 'aws')
        .filter(alert => {
            const source = String(alert.raw?.source || '').toUpperCase();
            if (sourceFilter === 'simulated' && source !== 'SIMULATED') return false;
            if (sourceFilter === 'cloudwatch' && source !== 'CLOUDWATCH') return false;

            const alarmState = String(alert.alarmState || '').toUpperCase();
            const handling = String(alert.raw?.handlingStatus || '').toUpperCase();
            const isResolved = handling === 'RESOLVED';
            const isAcknowledged = handling === 'ACKNOWLEDGED';
            const isNew = alarmState === 'ALARM' && !alert.nonActionable && !isResolved && !isAcknowledged;

            if (statusFilter === 'new' && !isNew) return false;
            if (statusFilter === 'acknowledged' && !isAcknowledged) return false;
            if (statusFilter === 'resolved' && !isResolved) return false;
            if (statusFilter === 'ok' && alarmState !== 'OK') return false;
            if (statusFilter === 'other' && (isNew || isAcknowledged || isResolved || alarmState === 'OK')) return false;

            const haystack = [
                alert.id,
                alert.deviceId,
                alert.deviceName,
                alert.metric,
                alert.sourceLabel,
                alert.alarmState,
                alert.statusLabel,
                alert.raw?.alarmName,
                alert.reason
            ].join(' ').toLowerCase();

            return haystack.includes(search);
        })
        .sort((a, b) => new Date(b.time || 0).getTime() - new Date(a.time || 0).getTime());

    $('aws-history-count').textContent = `${rows.length} / ${state.alerts.length} sự kiện`;
    $('aws-alert-history-rows').innerHTML = paginatedRows('aws-alert-history-rows', rows, renderAwsHistory).map(alert => {
        const value = alert.value == null ? '—' : `${formatNumber(alert.value)}%`;
        const threshold = alert.threshold == null ? '—' : `${formatNumber(alert.threshold)}%`;
        const alarm = alert.alarmState || '—';
        const alarmClass = alarm === 'ALARM' ? 'warning' : alarm === 'OK' ? 'online' : 'unknown';
        const handlingClass = alert.nonActionable || alert.handled
            ? 'online'
            : alert.acknowledged ? 'unknown' : 'warning';

        return `
            <tr>
                <td>${timeText(alert.time)}</td>
                <td>
                    <strong>${escapeHtml(alert.deviceName)}</strong>
                    <small>${escapeHtml(alert.deviceId)}</small>
                </td>
                <td>
                    <strong>${escapeHtml(alert.metric)}</strong>
                    <small class="history-reason">${escapeHtml(alert.raw?.alarmName || alert.reason || '—')}</small>
                </td>
                <td>${escapeHtml(value)} / ${escapeHtml(threshold)}</td>
                <td><span class="history-source">${escapeHtml(alert.sourceLabel)}</span></td>
                <td><span class="status-chip ${alarmClass}">${escapeHtml(alarm)}</span></td>
                <td><span class="status-chip ${handlingClass}">${escapeHtml(alert.statusLabel)}</span></td>
            </tr>
        `;
    }).join('') || `
        <tr>
            <td colspan="7" class="empty">Không có cảnh báo AWS phù hợp bộ lọc.</td>
        </tr>
    `;
}
// [SIMULATION-CONFIG] Chu kỳ mô phỏng được lưu lên AWS, KHÔNG ghi vào localStorage trước khi API xác nhận.
function renderSimulationSync() {
    const box = $('simulation-sync');
    const button = $('save-simulation-interval');
    if (!box || !button) return;
    button.disabled = state.simulationSaving;
    box.className = 'simulation-sync ' + (state.simulationSync === 'aws' ? 'sync-ok' : 'sync-warning');
    if (state.simulationSaving) box.textContent = 'Đang lưu chu kỳ mô phỏng lên AWS...';
    else if (!isAws()) box.textContent = 'Chế độ demo: không thay đổi CPU/RAM trên AWS.';
    else if (state.simulationSync === 'aws') box.textContent = `AWS đã đồng bộ: CPU/RAM mô phỏng cập nhật tối thiểu mỗi ${settings.simulationIntervalMinutes} phút (Scheduler cần chạy mỗi phút).`;
    else box.textContent = 'Chưa đồng bộ chu kỳ AWS — ' + (state.simulationError || 'Cần triển khai /simulation/config');
}
async function saveSimulationInterval() {
    if (state.simulationSaving || state.loading) return;
    const field = $('simulation-interval');
    const requested = Number(field.value);
    if (!Number.isInteger(requested) || requested < 1 || requested > 60) {
        notify('Chu kỳ CPU/RAM mô phỏng phải là số nguyên từ 1 đến 60 phút.');
        field.focus();
        return;
    }
    if (!isAws() || (isCognitoApi() && !hasToken())) {
        notify('Bạn cần đăng nhập AWS Cognito trước khi đổi chu kỳ CPU/RAM mô phỏng.');
        return;
    }
    state.simulationSaving = true;
    renderSimulationSync();
    try {
        const response = await awsRequest('/simulation/config', 'PUT', { intervalMinutes: requested });
        if (Number(response?.intervalMinutes) !== requested || response?.source !== 'NetworkSettings') {
            throw new Error('API không xác nhận lưu chu kỳ mô phỏng.');
        }
        settings.simulationIntervalMinutes = requested;
        persist('netmon-v2-settings', settings);
        state.simulationSync = 'aws';
        state.simulationError = '';
        recordOperation('Đổi chu kỳ CPU/RAM mô phỏng', `${requested} phút · AWS NetworkSettings`);
        notify(`Đã lưu chu kỳ mô phỏng ${requested} phút trên AWS. Kiểm tra Scheduler đang chạy rate(1 minute).`);
    } catch (error) {
        state.simulationSync = 'error';
        state.simulationError = error.message;
        notify('CHƯA LƯU CHU KỲ AWS: ' + error.message);
    } finally {
        state.simulationSaving = false;
        renderSimulationSync();
    }
}
function renderSettings() {
    const form = $('settings-form');
    // Keep typed values intact until Save is clicked.
    const typing = document.activeElement && form.contains(document.activeElement);
    if (!typing) {
        form.elements.url.value = settings.url;
        form.elements.cpuThreshold.value = settings.cpuThreshold;
        form.elements.ramThreshold.value = settings.ramThreshold;
        form.elements.interval.value = String(settings.interval);
        form.elements.popup.checked = settings.popup;
    }
    if (document.activeElement !== $('simulation-interval')) {
        $('simulation-interval').value = String(settings.simulationIntervalMinutes);
    }
    renderSimulationSync();
    $('connection-url').textContent = settings.url || '(Đang dùng demo)';
    $('threshold-preview').textContent =
        `Giao diện cảnh báo khi CPU > ${settings.cpuThreshold}% hoặc RAM > ${settings.ramThreshold}%.`;
    $('settings-sync').textContent = !isAws()
        ? 'DEMO — ngưỡng chỉ lưu ở trình duyệt'
        : state.thresholdsSync === 'aws'
            ? 'AWS ĐÃ ĐỒNG BỘ — cả API và Lambda monitor dùng chung NetworkSettings'
            : 'CHƯA ĐỒNG BỘ AWS — ' + (state.thresholdsError || 'Cần triển khai GET/PUT /settings');
    $('settings-sync').className = state.thresholdsSync === 'aws' ? 'sync-ok' : 'sync-warning';
    $('alerts-route').textContent = state.alertsSource === 'aws' ? 'GET /alerts · Đã đọc' : 'Chưa xác nhận';
    $('metrics-route').textContent = state.metricsSource === 'aws' ? 'GET /metrics · Đã đọc' : 'Chưa xác nhận';
    $('demo-button').textContent = settings.url ? 'Dùng chế độ demo' : 'Trở lại API AWS đã có';
}
function renderAll() {
    renderHeader();
    renderOverview();
    renderDevices();
    renderMetrics();
    renderAlerts();
    renderTopology();
    renderLogs();
    renderSettings();
    renderSns();
    showHistoryTab(state.historyTab);
}
// ================================================================
// [07 - THIET BI] Thêm / xem / sửa / xóa trên giao diện
// ================================================================
function registeredEc2(device) {
    return Boolean(device && (device.instanceId || [device.metricsSource, device.monitoringSource].some(x => String(x || '').toUpperCase() === 'CLOUDWATCH')));
}
function updateDeviceSourceForm() {
    const form = $('device-form');
    const readonly = $('save').hidden;
    const locked = Boolean(state.editing && state.editing.instanceId);
    const real = form.elements.deviceType.value === 'EC2';
    form.elements.deviceType.disabled = readonly || locked;
    for (const [id, name] of [['ec2-instance-field','instanceId'], ['ec2-region-field','region']]) {
        $(id).hidden = !real;
        form.elements[name].disabled = readonly || !real || locked;
    }
    form.elements.instanceId.required = real && !locked && !readonly;
    form.elements.region.value = 'us-east-1';
    form.elements.region.readOnly = true;
    for (const [id, name] of [['device-cpu-field','cpuUsage'], ['device-ram-field','memoryUsage']]) {
        $(id).hidden = real && !readonly;
        form.elements[name].disabled = real || readonly;
    }
    form.elements.ipAddress.required = !real;
    form.elements.ipAddress.placeholder = real ? 'IP riêng (tự lấy nếu để trống)' : '10.0.0.10';
    $('device-source-help').textContent = readonly && real && !form.elements.instanceId.value
        ? 'EC2 chưa liên kết AWS; cần sửa và nhập Instance ID để lấy dữ liệu CloudWatch.'
        : real
        ? (readonly ? 'Nguồn: CloudWatch. Chỉ số thiếu mẫu sẽ không được mô phỏng.' : 'CloudWatch · EC2 có sẵn tại us-east-1. RAM cần metric NetMon/EC2; không nhập số liệu thủ công.')
        : 'CPU/RAM mô phỏng tự cập nhật theo chu kỳ AWS.';
}
function showDevice(device = null, readonly = false) {
    if (state.loading)
        return;
    state.editing = readonly ? null : device;
    const form = $('device-form');
    form.reset();
    const type = form.elements.deviceType;
    for (const option of [...type.options]) if (option.dataset.custom) option.remove();
    const currentType = registeredEc2(device) ? 'EC2' : String(device?.deviceType || 'Switch');
    if (![...type.options].some(option => option.value === currentType)) {
        const option = new Option(currentType, currentType);
        option.dataset.custom = '1'; type.add(option);
    }
    $('dialog-title').textContent = readonly ? 'Chi tiết thiết bị' : device ? 'Chỉnh sửa thiết bị' : 'Thêm thiết bị mới';
    $('form-error').hidden = true;
    for (const field of form.querySelectorAll('[name]')) {
        field.disabled = readonly;
        field.readOnly = Boolean(!readonly && device && field.name === 'deviceId');
        if (device)
            field.value = device[field.name] ?? '';
    }
    type.value = currentType;
    $('save').hidden = readonly;
    updateDeviceSourceForm();
    $('cancel-device').textContent = readonly ? 'Đóng' : 'Hủy';
    $('device-dialog').showModal();
}
async function removeDevice(device) {
    if (!device || !window.confirm(`Xóa thiết bị "${device.deviceName || device.deviceId}"?`))
        return;
    if (state.loading)
        return;
    setBusy(true);
    try {
        if (isAws())
            await awsRequest(`/devices/${encodeURIComponent(device.deviceId)}`, 'DELETE');
        else
            persist('ha-tang-v1-demo', state.devices.filter(d => d.deviceId !== device.deviceId));
        recordOperation('Xóa thiết bị', `${device.deviceId} · ${device.deviceName || ''}`);
    }
    catch (error) {
        notify(`Xóa thất bại: ${error.message}`);
        setBusy(false);
        return;
    }
    setBusy(false);
    await loadAll();
}
async function saveDevice(event) {
    event.preventDefault();
    if (state.loading || $('save').hidden)
        return;
    const form = $('device-form');
    const input = Object.fromEntries(new FormData(form));
    for (const key of Object.keys(input))
        if (typeof input[key] === 'string')
            input[key] = input[key].trim();
    const real = form.elements.deviceType.value === 'EC2';
    if (!input.deviceId || !input.deviceName || (!real && !input.ipAddress)) {
        $('form-error').textContent = real ? 'Bạn phải nhập mã và tên thiết bị.' : 'Bạn phải nhập mã, tên và địa chỉ IP.';
        $('form-error').hidden = false;
        return;
    }
    if (!state.editing && state.devices.some(d => d.deviceId === input.deviceId)) {
        $('form-error').textContent = 'Mã thiết bị này đã tồn tại.';
        $('form-error').hidden = false;
        return;
    }
    if (real) {
        if (!isAws()) {
            $('form-error').textContent = 'Cần kết nối AWS để đăng ký EC2 thực tế.';
            $('form-error').hidden = false; return;
        }
        const instance = state.editing?.instanceId || input.instanceId;
        if (!/^i-(?:[0-9a-f]{8}|[0-9a-f]{17})$/.test(instance || '')) {
            $('form-error').textContent = 'Instance ID EC2 không hợp lệ.';
            $('form-error').hidden = false; return;
        }
        if (state.devices.some(d => d.deviceId !== input.deviceId && d.instanceId === instance)) {
            $('form-error').textContent = 'EC2 này đã được đăng ký trong NetMon.';
            $('form-error').hidden = false; return;
        }
        delete input.cpuUsage; delete input.memoryUsage;
        // Khong doi Instance ID cua EC2 da lien ket.
        if (!state.editing?.instanceId) {
            input.deviceType = 'EC2'; input.instanceId = instance;
            input.region = 'us-east-1'; input.monitoringSource = 'CLOUDWATCH';
        } else {
            delete input.instanceId; delete input.region;
        }
    } else {
        delete input.instanceId; delete input.region;
        for (const field of ['cpuUsage','memoryUsage']) {
            if (input[field] == null || input[field] === '') {
                delete input[field];
                if (!isAws() && !state.editing) {
                    const [minimum, maximum] = field === 'cpuUsage' ? [20, 65] : [30, 70];
                    input[field] = Math.floor(Math.random() * (maximum - minimum + 1)) + minimum;
                }
            } else input[field] = valueNumber(input[field]);
        }
    }
    // [AWS-DEVICE-PUT] Khi sua, Lambda chi can cac truong thay doi.
    // Khong gui lai thong tin cu la key phu (instanceId/vpcId...) neu khong sua.
    const payload = {
        ...(state.editing || {}),
        ...input,
        lastUpdated: isoNow()
    };

    setBusy(true);
    try {
        if (isAws()) {
            const path = state.editing ? `/devices/${encodeURIComponent(state.editing.deviceId)}` : '/devices';
            // POST bo qua chi so trong, Lambda tu sinh gia tri CPU/RAM.
            // PUT chi gui FormData, de Lambda giu field khong sua.
            await awsRequest(path, state.editing ? 'PUT' : 'POST', input);
        }
        else {
            const list = state.editing ? state.devices.map(d => d.deviceId === state.editing.deviceId ? payload : d) : [...state.devices, payload];
            persist('ha-tang-v1-demo', list);
        }
        recordOperation(state.editing ? 'Sửa thiết bị' : 'Thêm thiết bị', `${input.deviceId} · ${input.deviceName}`);
        $('device-dialog').close();
        state.editing = null;
        setBusy(false);
        await loadAll();
    }
    catch (error) {
        $('form-error').textContent = `Lưu thất bại: ${error.message}`;
        $('form-error').hidden = false;
        setBusy(false);
    }
}
// [ALERT-SELECTION] Acknowledged: tat ca New. Resolved: CHI dong canh bao da tich chon.
// Backend giu PUT /alerts/{eventId}; toi da 3 request song song.
function bulkAlertCandidates(status) {
    return state.alerts.filter(entry =>
        actionableAlert(entry) && (status === 'Resolved' || !entry.acknowledged)
    );
}
function bulkStatus(message, visible = true) {
    const element = $('alert-bulk-status');
    element.textContent = message;
    element.hidden = !visible;
}
async function handleAllAlerts(status) {
    if (state.loading || state.bulkProcessing) return;
    if (!['Acknowledged', 'Resolved'].includes(status)) return;
    if (isAws() && state.alertsSource !== 'aws') {
        bulkStatus('Không thể xử lý: chưa đọc được GET /alerts từ AWS. Hãy tải lại.');
        return;
    }
    const items = (status === 'Resolved'
        ? selectedActionableAlerts() : bulkAlertCandidates('Acknowledged')).slice();
    if (!items.length) {
        bulkStatus(status === 'Resolved'
            ? 'Hãy tích chọn ít nhất một cảnh báo chưa xử lý trước khi bấm Hoàn tất đã chọn.'
            : 'Không còn cảnh báo mới cần tiếp nhận.');
        return;
    }
    const isResolve = status === 'Resolved';
    const action = isResolve ? 'Hoàn tất xử lý' : 'Tiếp nhận';
    const examples = items.slice(0, 4).map(entry => `• ${entry.deviceName} – ${entry.metric}`).join('\n');
    const question = isResolve
        ? `Hoàn tất xử lý ${items.length} cảnh báo ĐÃ CHỌN?\n\n${examples}${items.length > 4 ? '\n• ...' : ''}\n\n` +
          'Bạn đã kiểm tra các sự cố này? Hành động chỉ ghi trạng thái Resolved, KHÔNG xác nhận CPU/RAM đã phục hồi và KHÔNG dừng giám sát.\n' +
          (isAws() ? 'Trạng thái sẽ ghi vào DynamoDB.' : 'Chế độ demo: chỉ lưu trong trình duyệt.')
        : `Tiếp nhận TẤT CẢ ${items.length} cảnh báo mới, kể cả các dòng đang ẩn bởi bộ lọc?\n\n` +
          (isAws() ? 'Trạng thái Acknowledged sẽ lưu vào DynamoDB.' : 'Chế độ demo: chỉ lưu trong trình duyệt.');
    if (!window.confirm(question)) return;

    state.bulkProcessing = true;
    setBusy(true);
    renderAlerts();
    let completed = 0;
    let success = 0;
    const failures = [];
    const succeededIds = new Set();
    bulkStatus(`Đang ${action.toLowerCase()}: 0/${items.length} cảnh báo...`);
    try {
        if (isAws()) {
            let cursor = 0;
            const worker = async () => {
                while (cursor < items.length) {
                    const entry = items[cursor++];
                    try {
                        await awsRequest(`/alerts/${encodeURIComponent(entry.id)}`, 'PUT', { handlingStatus: status });
                        success++;
                        succeededIds.add(entry.id);
                    } catch (error) {
                        failures.push({ id: entry.id, reason: String(error.message || error) });
                    }
                    completed++;
                    bulkStatus(`Đang ${action.toLowerCase()}: ${completed}/${items.length} · Thành công ${success} · Lỗi ${failures.length}`);
                }
            };
            await Promise.all(Array.from({ length: Math.min(3, items.length) }, () => worker()));
        } else {
            const key = scopedKey('alerts');
            const rows = stored(key, []);
            const ids = new Set(items.map(entry => entry.id));
            for (const row of rows) {
                if (!ids.has(row.id)) continue;
                row.acknowledged = status === 'Acknowledged';
                row.handled = status === 'Resolved';
                if (row.handled) row.handledAt = isoNow();
                succeededIds.add(row.id);
                success++;
            }
            persist(key, rows);
            for (const entry of items) {
                if (!succeededIds.has(entry.id)) continue;
                entry.acknowledged = status === 'Acknowledged';
                entry.handled = status === 'Resolved';
                entry.resolved = status === 'Resolved';
                entry.statusLabel = status === 'Resolved' ? 'Đã xử lý' : 'Đã tiếp nhận';
            }
        }
        if (success) recordOperation(`${action} hàng loạt`, `${success}/${items.length} cảnh báo`);
        if (isResolve) {
            for (const id of succeededIds) state.selectedAlertIds.delete(id);
        }
    } finally {
        state.bulkProcessing = false;
        setBusy(false);
        if (isAws()) await loadAll(false);
        else renderAll();
        const result = `Đã ${action.toLowerCase()} ${success}/${items.length} cảnh báo.`;
        if (failures.length) {
            const examples = failures.slice(0, 3).map(f => `${f.id}: ${f.reason}`).join(' · ');
            bulkStatus(`${result} Thất bại ${failures.length}: ${examples}. Các cảnh báo lỗi vẫn giữ lựa chọn để thử lại.`);
        } else {
            const syncMessage = !isAws() ? 'Đã lưu trong trình duyệt.'
                : state.alertsSource === 'aws' ? 'Đã đọc lại trạng thái từ DynamoDB.'
                : 'Chưa xác minh được trạng thái sau khi ghi; hãy bấm Tải lại.';
            bulkStatus(`${result} ${syncMessage}`);
        }
    }
}

// ================================================================
// [08 - XU LY CANH BAO] Acknowledged / Resolved qua PUT /alerts/{eventId} trên AWS
// ================================================================
async function handleAlert(index, nextStatus = 'Resolved') {
    if (state.loading || state.bulkProcessing)
        return;
    const entry = state.alerts[index];
    if (!entry || entry.handled)
        return;
    if (nextStatus === 'Resolved' && !window.confirm(
        `Xác nhận đã kiểm tra sự cố của ${entry.deviceName} (${entry.metric}) và hoàn tất xử lý?\n\n` +
        'Thao tác chỉ chuyển trạng thái sang Resolved, KHÔNG có nghĩa CPU/RAM đã phục hồi.'
    )) return;
    setBusy(true);
    try {
        if (entry.origin === 'aws') {
            // [AWS-ALERT-STATUS] Lambda chỉ chấp nhận New / Acknowledged / Resolved.
            // Không dùng "Handled" vì backend sẽ trả HTTP 400.
            await awsRequest(`/alerts/${encodeURIComponent(entry.id)}`, 'PUT', { handlingStatus: nextStatus });
        }
        else {
            const key = scopedKey('alerts');
            const alerts = stored(key, []);
            const match = alerts.find(row => row.id === entry.id);
            if (!match)
                throw new Error('Không tìm thấy bản ghi cảnh báo trên trình duyệt.');
            match.handled = nextStatus === 'Resolved';
            match.acknowledged = nextStatus === 'Acknowledged';
            if (match.handled) match.handledAt = isoNow();
            persist(key, alerts);
            entry.handled = nextStatus === 'Resolved';
            entry.acknowledged = nextStatus === 'Acknowledged';
            entry.resolved = nextStatus === 'Resolved';
            entry.statusLabel = nextStatus === 'Resolved' ? 'Đã xử lý' : 'Đã tiếp nhận';
        }
        state.selectedAlertIds.delete(entry.id);
        recordOperation(nextStatus === 'Acknowledged' ? 'Tiếp nhận cảnh báo' : 'Hoàn tất cảnh báo', `${entry.deviceName} · ${entry.metric}`);
        setBusy(false);
        if (entry.origin === 'aws')
            await loadAll();
        else
            renderAll();
    }
    catch (error) {
        notify(`Không xử lý được cảnh báo: ${error.message} Kiểm tra PUT /alerts/{id}, tích hợp Lambda và quyền dynamodb:UpdateItem.`);
        setBusy(false);
    }
}
function maybeShowAlerts() {
    // [ALERT-POPUP] Chi hien ALARM moi chua tiep nhan/xu ly.
    // netmon-device-monitor luu isTest=true cho du lieu SIMULATED:
    // van hien popup, NHUNG gan nhan MO PHONG trong noi dung.
    if (!settings.popup || !state.loaded) {
        return;
    }

    const unseen = state.alerts.filter(alert =>
        !alert.handled &&
        !alert.acknowledged &&
        !state.popupShown.has(`${sourceId()}/${alert.id}`)
    );

    if (!unseen.length) {
        return;
    }

    for (const alert of unseen) {
        state.popupShown.add(`${sourceId()}/${alert.id}`);
    }

    $('popup-alert-list').innerHTML = unseen.slice(0, 5).map(alert => {
        const description = alert.value == null
            ? (alert.alarmState === 'ALARM' ? 'CloudWatch: ALARM' : 'Trạng thái bất thường')
            : (() => {
                // Alert AWS dùng ngưỡng do backend ghi nhận; demo dùng cấu hình trình duyệt.
                // Nếu AWS không trả ngưỡng, chỉ hiển thị giá trị thực tế.
                const threshold = alert.origin === 'aws'
                    ? alert.threshold
                    : alert.threshold ?? thresholdForMetric(alert.metric);

                return threshold == null
                    ? `Giá trị ${alert.value}%`
                    : `Giá trị ${alert.value}% · ngưỡng ${threshold}%`;
            })();

        const sourceLabel = alert.isSimulated ? ' · MÔ PHỎNG' : '';
        const severity = alert.severity === 'CRITICAL' ? 'OFFLINE' : 'WARNING';

        return `
            <div class="popup-alert-entry">
                <div>
                    <strong>${escapeHtml(alert.deviceName)} · ${escapeHtml(alert.metric)}${sourceLabel}</strong>
                    <small>${description} · ${timeText(alert.time)}</small>
                </div>
                <span>${statusChip(severity)}</span>
            </div>
        `;
    }).join('');

    if (!$('alert-popup').open) {
        $('alert-popup').showModal();
    }
}
// ================================================================
// [09 - TUY CHINH] Lưu Invoke URL, 2 ngưỡng CPU/RAM và thời gian tự làm mới
// ================================================================
async function saveSettings(event) {
    if (event) event.preventDefault();
    if (state.loading) return;
    const form = $('settings-form');
    let url = form.elements.url.value.trim();
    if (url) {
        try {
            const parsed = new URL(url);
            if (parsed.protocol !== 'https:' || parsed.username || parsed.password ||
                parsed.search || parsed.hash || /\/devices\/?$/.test(parsed.pathname)) {
                throw new Error('Invoke URL không hợp lệ');
            }
            url = parsed.href.replace(/\/+$/, '');
        } catch {
            notify('Chỉ nhập Invoke URL HTTPS hợp lệ, không kèm /devices.');
            return;
        }
    }
    const cpu = Number(form.elements.cpuThreshold.value);
    const ram = Number(form.elements.ramThreshold.value);
    if (![cpu, ram].every(v => Number.isInteger(v) && v >= 1 && v <= 99)) {
        notify('Ngưỡng CPU và RAM phải là số nguyên 1–99%.');
        return;
    }
    settings.url = url;
    settings.interval = Number(form.elements.interval.value);
    settings.popup = form.elements.popup.checked;
    // [SETTINGS-SECURITY] Không đưa bí mật AWS vào trình duyệt.
    // PUT /settings được JWT authorizer bảo vệ bằng scope netmon-api/write.
    let syncError = '';
    if (isAws()) {
        try {
            const result = await awsRequest('/settings', 'PUT', {
                cpuThreshold: cpu, ramThreshold: ram
            });
            if (!result || Number(result.cpuThreshold) !== cpu ||
                Number(result.ramThreshold) !== ram) {
                throw new Error('API trả về cấu hình không trùng với yêu cầu.');
            }
            state.thresholdsSync = 'aws';
            state.thresholdsError = '';
        } catch (error) {
            syncError = error.message;
            state.thresholdsSync = 'local';
            state.thresholdsError = syncError;
        }
    } else {
        state.thresholdsSync = 'local';
        state.thresholdsError = '';
    }
    settings.cpuThreshold = cpu;
    settings.ramThreshold = ram;
    persist('netmon-v2-settings', settings);
    recordOperation('Lưu cấu hình', `CPU > ${cpu}% · RAM > ${ram}% · ${settings.interval}s`);
    state.loaded = false;
    state.devices = [];
    state.alerts = [];
    state.cloudwatch = null;
    state.samples = stored(scopedKey('samples'), []);
    startPolling();
    renderAll();
    await loadAll(false);
    if (syncError) {
        notify('CHƯA LƯU AWS: ' + syncError + '. Các ngưỡng có thể bị thay bằng giá trị AWS khi tải lại.');
    } else {
        notify(isAws() ? 'Đã gửi cấu hình ngưỡng lên AWS.' : 'Đã lưu cấu hình demo trong trình duyệt.');
    }
}
// ================================================================
// [10 - SU KIEN] Liên kết các nút và form HTML với hàm JavaScript
// ================================================================
// Events
for (const button of document.querySelectorAll('.nav button[data-page]')) {
    button.addEventListener('click', () => navigate(button.dataset.page));
}
for (const button of document.querySelectorAll('[data-goto]')) {
    button.addEventListener('click', () => navigate(button.dataset.goto));
}
$('quick-refresh-interval').addEventListener('change', event => {
    const next = Number(event.target.value);
    if (![0, 30, 60, 120].includes(next)) return;
    settings.interval = next;
    state.autoPaused = false;
    sessionStorage.setItem('netmon-auto-refresh-paused', 'false');
    persist('netmon-v2-settings', settings);
    event.target.blur();
    startPolling();
    // Khong ghi de cac truong cau hinh khac dang chinh sua.
    notify(next === 0 ? 'Đã tắt tự tải website. Nút ↻ vẫn dùng được.' : `Website tự đọc lại AWS mỗi ${next} giây; chu kỳ tạo CPU/RAM mô phỏng không đổi.`);
});
$('simulation-config-link').addEventListener('click', () => {
    navigate('settings');
    $('simulation-interval').focus();
});
$('save-simulation-interval').addEventListener('click', () => void saveSimulationInterval());
$('refresh').addEventListener('click', () => void loadAll());
// [AUTO-REFRESH] Tạm dừng không ngăn nút Tải lại thủ công.
$('auto-refresh-toggle').addEventListener('click', () => {
    if (settings.interval === 0) {
        navigate('settings');
        $('settings-form').elements.interval.focus();
        return;
    }
    state.autoPaused = !state.autoPaused;
    sessionStorage.setItem('netmon-auto-refresh-paused', String(state.autoPaused));
    if (!state.autoPaused) {
        state.nextAutoAt = Date.now() + settings.interval * 1000;
    }
    renderAutoRefreshStatus();
});
// Khi quay lại tab/mạng được phục hồi, timer sẽ tải ngay nếu đã đến hạn.
document.addEventListener('visibilitychange', renderAutoRefreshStatus);
window.addEventListener('online', renderAutoRefreshStatus);
window.addEventListener('offline', renderAutoRefreshStatus);
$('history-instance-select').addEventListener('change', event => {
    state.selectedHistoryInstance = event.target.value;
    state.ec2HistorySelectionMade = true;
    ++state.ec2HistoryRequestSeq;
    state.ec2HistoryFetching = false;
    state.ec2HistoryError = '';
    renderMetrics();
    if (state.selectedHistoryInstance) void loadEc2History();
});
$('ec2-history-preset').addEventListener('change', event => {
    if (event.target.value === 'custom') {
        $('ec2-custom-range').hidden = false;
        $('ec2-history-minutes').focus();
        return;
    }
    const minutes = Number(event.target.value);
    if (!Number.isInteger(minutes) || minutes < 15 || minutes > 1440) return;
    state.ec2HistoryMinutes = minutes;
    ++state.ec2HistoryRequestSeq;
    state.ec2HistoryError = '';
    renderMetrics();
    if (state.selectedHistoryInstance) void loadEc2History();
});
$('ec2-history-minutes').addEventListener('change', event => {
    const minutes = Number(event.target.value);
    if (!Number.isInteger(minutes) || minutes < 15 || minutes > 1440) {
        event.target.value = String(state.ec2HistoryMinutes);
        notify('Chọn khoảng xem lịch sử từ 15 phút đến 24 giờ (1440 phút).');
        return;
    }
    state.ec2HistoryMinutes = minutes;
    ++state.ec2HistoryRequestSeq;
    state.ec2HistoryError = '';
    renderMetrics();
    if (state.selectedHistoryInstance) void loadEc2History();
});
$('ec2-history-load').addEventListener('click', () => void loadEc2History(true));
$('sign-in').addEventListener('click', async () => {
    try {
        await netmonAuth.signIn();
    }
    catch (error) {
        notify(error.message);
    }
});
$('sign-out').addEventListener('click', () => {
    netmonAuth.clear();
    state.loaded = false;
    state.devices = [];
    state.alerts = [];
    state.auditLogs = [];
    state.auditLogsSource = 'unauthorized';
    state.auditLogsError = 'Chưa đăng nhập Cognito.';
    state.auditLogsLastSync = null;
    state.cloudwatch = null;
    state.ec2HistoryCache.clear();
    state.snsStatus = null;
    state.snsLastSync = null;
    state.snsError = 'Đã thoát phiên.';
    state.error = 'Đã thoát phiên dashboard';
    renderAll();
    notify('Đã xóa phiên truy cập trong tab này. Phiên SSO Cognito trên trình duyệt có thể vẫn còn.');
});
$('search').addEventListener('input', () => resetTablePage('device-rows', renderDevices));
$('status-filter').addEventListener('change', () => resetTablePage('device-rows', renderDevices));
$('alert-filter').addEventListener('change', () => {
    // Tranh thao tac nham voi lua chon da bi an sau khi doi bo loc.
    state.selectedAlertIds.clear();
    resetTablePage('alert-rows', renderAlerts);
});
$('log-search').addEventListener('input', () => resetTablePage('operation-rows', renderLogs));
$('device-audit-search').addEventListener('input', () => resetTablePage('device-audit-rows', renderDeviceAudit));
$('device-audit-filter').addEventListener('change', () => resetTablePage('device-audit-rows', renderDeviceAudit));
$('aws-alert-search').addEventListener('input', () => resetTablePage('aws-alert-history-rows', renderAwsHistory));
$('aws-alert-source-filter').addEventListener('change', () => resetTablePage('aws-alert-history-rows', renderAwsHistory));
$('aws-alert-status-filter').addEventListener('change', () => resetTablePage('aws-alert-history-rows', renderAwsHistory));
$('refresh-history').addEventListener('click', () => void loadAll());
$('check-sns').addEventListener('click', () => void checkSnsStatus());
// [SNS-OVERVIEW] Nhan kiem tra SNS ngay tai Tong quan, khong phai vao Cau hinh.
$('integration-list').addEventListener('click', event => {
    if (event.target.closest('[data-check-sns-overview]')) {
        void checkSnsStatus();
    }
});
for (const button of document.querySelectorAll('[data-history-tab]')) {
    button.addEventListener('click', () => showHistoryTab(button.dataset.historyTab));
    button.addEventListener('keydown', event => {
        if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
        event.preventDefault();
        const names = ['devices', 'alerts', 'local'];
        const i = names.indexOf(state.historyTab);
        const next = names[(i + (event.key === 'ArrowRight' ? 1 : 2)) % names.length];
        showHistoryTab(next);
        $('history-tab-' + next).focus();
    });
}
$('add').addEventListener('click', () => showDevice());
$('close').addEventListener('click', () => $('device-dialog').close());
$('cancel-device').addEventListener('click', () => $('device-dialog').close());
$('device-form').elements.deviceType.addEventListener('change', updateDeviceSourceForm);
$('device-form').addEventListener('submit', event => void saveDevice(event));
$('device-rows').addEventListener('click', event => {
    const button = event.target.closest('button[data-action]');
    if (!button || state.loading)
        return;
    const device = state.devices[Number(button.dataset.index)];
    if (!device)
        return;
    if (button.dataset.action === 'delete')
        void removeDevice(device);
    else
        showDevice(device, button.dataset.action === 'view');
});
$('alert-rows').addEventListener('click', event => {
    const button = event.target.closest('button[data-handle]');
    if (button && !state.bulkProcessing)
        void handleAlert(Number(button.dataset.handle), button.dataset.status || 'Resolved');
});
$('alert-rows').addEventListener('change', event => {
    const checkbox = event.target.closest('input[data-alert-select]');
    if (!checkbox || state.loading || state.bulkProcessing) return;
    if (isAws() && state.alertsSource !== 'aws') return;
    const entry = state.alerts[Number(checkbox.dataset.alertSelect)];
    if (!actionableAlert(entry)) return;
    if (checkbox.checked) state.selectedAlertIds.add(entry.id);
    else state.selectedAlertIds.delete(entry.id);
    renderAlerts();
});
$('alert-ack-all').addEventListener('click', () => void handleAllAlerts('Acknowledged'));
$('alert-select-visible').addEventListener('click', selectVisibleAlerts);
$('alert-clear-selection').addEventListener('click', clearSelectedAlerts);
$('alert-resolve-selected').addEventListener('click', () => void handleAllAlerts('Resolved'));
$('topology-zoom-in').addEventListener('click', () => {
    if (!$('topology-graph')) return; topologyZoom=Math.min(1.8,(topologyZoom ?? Number.parseInt($('topology-zoom-value').textContent)/100)+.15); sizeTopology();
});
$('topology-zoom-out').addEventListener('click', () => {
    if (!$('topology-graph')) return; topologyZoom=Math.max(.5,(topologyZoom ?? Number.parseInt($('topology-zoom-value').textContent)/100)-.15); sizeTopology();
});
$('topology-fit').addEventListener('click', () => {topologyZoom=null;sizeTopology();});
window.addEventListener('resize', sizeTopology);
const networkViewport=$('topology-viewport');
let networkDrag=null;
networkViewport.addEventListener('pointerdown', event=>{
    if(event.pointerType!=='mouse'||event.button!==0||event.target.closest('button')) return;
    networkDrag={x:event.clientX,y:event.clientY,left:networkViewport.scrollLeft,top:networkViewport.scrollTop};
    networkViewport.setPointerCapture(event.pointerId);networkViewport.classList.add('is-dragging');
});
networkViewport.addEventListener('pointermove',event=>{
    if(!networkDrag)return;
    networkViewport.scrollLeft=networkDrag.left+networkDrag.x-event.clientX;
    networkViewport.scrollTop=networkDrag.top+networkDrag.y-event.clientY;
});
for(const type of ['pointerup','pointercancel','lostpointercapture'])networkViewport.addEventListener(type,()=>{networkDrag=null;networkViewport.classList.remove('is-dragging');});
// Hai tab độc lập; sơ đồ mạng chỉ căn kích thước khi hiện.
function showDiagramTab(tab) {
    if (!['aws', 'network'].includes(tab)) return;
    state.diagramTab = tab;
    document.querySelectorAll('[data-diagram-tab]').forEach(button => {
        const active = button.dataset.diagramTab === tab;
        button.classList.toggle('is-active', active);
        button.setAttribute('aria-selected', String(active));
        button.tabIndex = active ? 0 : -1;
    });
    $('aws-architecture').hidden = tab !== 'aws';
    $('network-diagram').hidden = tab !== 'network';
    if (tab === 'network') sizeTopology();
}
document.querySelectorAll('[data-diagram-tab]').forEach(button => {
    button.addEventListener('click', () => showDiagramTab(button.dataset.diagramTab));
    button.addEventListener('keydown', event => {
        if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
        event.preventDefault();
        const next = state.diagramTab === 'aws' ? 'network' : 'aws';
        showDiagramTab(next);
        $('diagram-tab-' + next).focus();
    });
});
$('topology-search').addEventListener('input', renderTopology);
$('topology-status').addEventListener('change', renderTopology);
$('topology-viewport').addEventListener('click', event => {
    const button = event.target.closest('button[data-device]');
    if (button)
        showDevice(state.devices[Number(button.dataset.device)], true);
});
$('settings-form').addEventListener('submit', event => void saveSettings(event));
$('demo-button').addEventListener('click', () => {
    const form = $('settings-form');
    form.elements.url.value = settings.url ? '' : DEFAULT_URL;
    void saveSettings();
});
$('close-alert-popup').addEventListener('click', () => $('alert-popup').close());
$('dismiss-alert-popup').addEventListener('click', () => $('alert-popup').close());
$('open-alerts').addEventListener('click', () => { $('alert-popup').close(); navigate('alerts'); });
$('device-dialog').addEventListener('cancel', event => { if (state.loading)
    event.preventDefault(); });
async function startup() {
    navigate('overview');
    state.samples = stored(scopedKey('samples'), []);
    renderAll();
    try {
        if (await netmonAuth.complete()) {
            // OAuth callback always resumes with the configured Cognito API.
            settings.url = netmonAuth.apiUrl;
            persist('netmon-v2-settings', settings);
        }
    }
    catch (error) {
        notify(`Đăng nhập Cognito thất bại: ${error.message}`);
    }
    startPolling();
    await loadAll(false);
    if (state.error && !hasToken())
        notify('Chưa đăng nhập Cognito. Bấm Đăng nhập AWS để đọc dữ liệu thật từ API Gateway.');
}
void startup();
