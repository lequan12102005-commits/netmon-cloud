// ================================================================
// [COGNITO - DANG NHAP]
// Các giá trị dưới đây lấy từ User Pool / App Client của dự án AWS.
// Đổi redirectUri chỉ khi bạn cũng sửa Callback URL trong Cognito.
// Client ID là ID công khai; KHÔNG đặt Client Secret / AWS Access Key ở đây.
// ================================================================
const netmonAuth = (() => {
    const apiUrl = 'https://573phy2mgl.execute-api.us-east-1.amazonaws.com';
    const domain = 'https://us-east-1nnd1hokra.auth.us-east-1.amazoncognito.com';
    const clientId = '3k80hv8n2qasinqndct65a0lqh';
    // [COGNITO-REDIRECT] Dashboard chạy ngay tại root (không thư mục con).
    // Callback URL trong Cognito và địa chỉ Go Live phải cùng là
    // http://localhost:5500/ . Không đổi nếu chưa cập nhật Cognito.
    const redirectUri = 'http://localhost:5500/';
    const pendingKey = 'netmon-pkce';
    const sessionKey = 'netmon-cognito-session';
    // [COGNITO-SESSION] Giữ access token trong sessionStorage của tab hiện tại.
    // F5 không làm mất phiên; đóng tab / đăng xuất / token hết hạn => không có token.
    // Không lưu mật khẩu, client secret, AWS Access Key hoặc JWT trong localStorage.
    let accessToken = '';
    let expiresAt = 0;
    try {
        const saved = JSON.parse(sessionStorage.getItem(sessionKey) || 'null');
        if (saved?.accessToken && Number(saved.expiresAt) > Date.now()) {
            accessToken = saved.accessToken;
            expiresAt = Number(saved.expiresAt);
        } else {
            sessionStorage.removeItem(sessionKey);
        }
    } catch {
        sessionStorage.removeItem(sessionKey);
    }
    function base64url(bytes) {
        return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    // [COGNITO-LOGIN] OAuth 2.0 Authorization Code + PKCE.
    async function signIn() {
        // [GO-LIVE-ROOT] Không cho đăng nhập từ thư mục con.
        // Nếu đăng nhập từ /NetMon-Cloud/index.html, Cognito vẫn trả về /,
        // dẫn tới trang listing directory như lỗi người dùng đã gặp.
        if (!['/', '/index.html'].includes(location.pathname)) {
            throw new Error(
                'Hãy mở đúng thư mục chứa index.html trong VS Code rồi truy cập http://localhost:5500/ trước khi đăng nhập.'
            );
        }
        if (location.origin !== new URL(redirectUri).origin) {
            location.assign(redirectUri);
            return;
        }
        const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
        const state = base64url(crypto.getRandomValues(new Uint8Array(32)));
        const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
        sessionStorage.setItem(pendingKey, JSON.stringify({ verifier, state }));
        const authorize = new URL('/oauth2/authorize', domain);
        authorize.search = new URLSearchParams({
            client_id: clientId,
            redirect_uri: redirectUri,
            response_type: 'code',
            scope: 'openid email netmon-api/read netmon-api/write',
            code_challenge_method: 'S256',
            code_challenge: base64url(new Uint8Array(digest)),
            state
        });
        location.assign(authorize);
    }
    // [COGNITO-CALLBACK] Nhận code, đối chiếu state, đổi lấy access token.
    async function complete() {
        if (location.origin !== new URL(redirectUri).origin)
            return false;
        const params = new URLSearchParams(location.search);
        if (!params.has('code') && !params.has('error'))
            return false;
        history.replaceState(null, '', location.pathname);
        const pending = JSON.parse(sessionStorage.getItem(pendingKey) || 'null');
        sessionStorage.removeItem(pendingKey);
        if (!pending || pending.state !== params.get('state')) {
            throw new Error('Phiên đăng nhập không hợp lệ. Hãy bấm Đăng nhập và thử lại.');
        }
        if (params.has('error'))
            throw new Error('Cognito từ chối đăng nhập: ' + params.get('error'));
        const response = await fetch(new URL('/oauth2/token', domain), {
            method: 'POST',
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: clientId,
                redirect_uri: redirectUri,
                code_verifier: pending.verifier,
                code: params.get('code')
            })
        });
        const result = await response.json();
        if (!response.ok || !result.access_token || !(result.expires_in > 0)) {
            throw new Error('Cognito không cấp access token. Mã lỗi: ' + (result.error || response.status));
        }
        accessToken = result.access_token;
        expiresAt = Date.now() + Number(result.expires_in) * 1000;
        sessionStorage.setItem(sessionKey, JSON.stringify({ accessToken, expiresAt }));
        return true;
    }
    return {
        apiUrl,
        signIn,
        complete,
        token: () => Date.now() < expiresAt ? accessToken : '',
        clear: () => {
            accessToken = '';
            expiresAt = 0;
            sessionStorage.removeItem(sessionKey);
        }
    };
})();
