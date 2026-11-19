# NetMon Cloud

Hệ thống quản lý và giám sát hạ tầng mạng doanh nghiệp vừa và nhỏ trên AWS tích hợp dịch vụ Serverless.

## Chạy hệ thống

1. Giải nén và mở thư mục chứa `index.html` bằng VS Code.
2. Chạy `index.html` bằng Live Server tại `http://localhost:5500/`.
3. Đăng nhập Cognito bằng tài khoản đã được cấp quyền.

## Chức năng

- Quản lý thiết bị mạng, theo dõi CPU/RAM mô phỏng và điều chỉnh chu kỳ cập nhật.
- Giám sát EC2 qua CloudWatch; xem lịch sử từ 15 phút đến 24 giờ.
- Quản lý cảnh báo, tiếp nhận hàng loạt, xử lý cảnh báo đã chọn và kiểm tra SNS.
- Nhật ký thiết bị, cảnh báo và thao tác; sơ đồ hạ tầng và cấu hình hệ thống.

## Cấu trúc

- `index.html`, `style.css`, `app.js`, `auth.js`, `favicon.svg`: giao diện và kết nối API.
- `.vscode/`: cấu hình Live Server.
- `AWS_BACKEND_CODE/`: mã nguồn Lambda, hai gói triển khai ZIP tương ứng với API và simulator, policy IAM mẫu và cấu hình tham khảo.

## Lưu ý vận hành

- Chạy website không triển khai hay thay đổi Lambda, IAM, Scheduler hoặc CloudWatch trên AWS. Nếu backend hiện đang chạy đúng, không cần upload lại vì thay đổi tên giao diện.
- Giữ địa chỉ callback Cognito `http://localhost:5500/`. Các thiết bị mô phỏng phụ thuộc vào cấu hình Lambda và EventBridge; EC2 thật sử dụng dữ liệu CloudWatch.
- Các policy IAM và file CloudWatch Agent là mẫu tham khảo, không áp dụng nguyên trạng khi hệ thống đã cấu hình. Cần đối chiếu ARN, quyền đọc GetMetricStatistics/ListMetrics và namespace RAM thực tế `NetMon/EC2` trước khi triển khai lại. Giữ nguyên cấu hình thu thập RAM đang hoạt động trên EC2.
- Trạng thái tạm dừng cảnh báo và gửi email được điều khiển ở AWS; việc đổi giao diện không bật lại các trigger hoặc Alarm actions.
- AWS có thể phát sinh chi phí tùy tài nguyên và mức sử dụng.

## Sơ đồ và phân trang

- Sơ đồ mạng tự phân tầng theo loại thiết bị có trong danh sách đã tải (Router/Firewall → Switch/Wi-Fi → Server/máy trạm), tách thiết bị chưa phân loại và khu vực EC2 AWS riêng. Các nút mạng nhỏ gọn có biểu tượng riêng, CPU/RAM và chấm trạng thái; bấm thiết bị để xem IP, vị trí và chi tiết. Có phóng to, thu nhỏ, vừa khung và kéo khu vực sơ đồ. Không sinh thiết bị giả; Internet chỉ là điểm tham chiếu. Đường nối tầng là giả định, đường đứt là quan hệ quản lý logic, không phát hiện dây/cổng thật. Bộ lọc có thể ẩn tầng; sơ đồ cập nhật cùng dữ liệu toàn hệ thống.
- Phân trang 10/20/50 dòng cho Quản lý thiết bị, Cảnh báo & sự cố và ba tab Nhật ký. Các bảng phân trang phía trình duyệt trên dữ liệu đã tải; GET /logs hiện lấy tối đa 100 bản ghi, nhật ký thao tác tối đa 200 bản ghi.
- Chọn cả trang chỉ tích cảnh báo trên trang đang xem. Lựa chọn được giữ khi chuyển trang, đổi bộ lọc sẽ bỏ chọn. Tiếp nhận tất cả vẫn áp dụng cho tất cả cảnh báo mới đã tải.
- Không thay đổi backend AWS.

- Tab Sơ đồ hạ tầng gồm hai khu vực: kiến trúc AWS (luồng truy cập, mô phỏng, cảnh báo/nhật ký và giám sát EC2) và sơ đồ mạng động. Hai tab con độc lập, chỉ hiển thị sơ đồ đang chọn; hỗ trợ phím mũi tên. Sơ đồ kiến trúc mô tả thiết kế, không xác nhận trigger hay Alarm actions đang bật.

## Đăng ký EC2 thật

1. Sao lưu code Lambda `netmon-api` đang hoạt động, giữ nguyên biến môi trường, role và trigger.
2. Lambda → netmon-api → Configuration → Permissions → Execution role → Add permissions → Create inline policy → JSON. Dán nội dung `AWS_BACKEND_CODE/IAM-netmon-api-EC2-READ.json`, đặt tên `NetMonApi-VerifyEC2`, lưu lại. Đây chỉ là quyền đọc DescribeInstances tại us-east-1. Không thay thế các policy cũ.
3. Lambda → netmon-api → Code → Upload from → .zip file → chọn `AWS_BACKEND_CODE/netmon-api-deploy.zip` → Save. Handler `lambda_function.lambda_handler`. Không cần thêm route, sửa Cognito, EventBridge hay các Lambda khác. Giữ quyền CloudWatch GetMetricStatistics đang dùng.
4. Chạy website bằng Go Live. Vào Quản lý thiết bị → Thêm thiết bị → chọn EC2 (AWS thực tế). Nhập mã, tên và Instance ID của EC2 đang có trong AWS EC2 Console (N. Virginia). Có thể để trống IP để API đọc IP riêng. Không nhập CPU/RAM cho EC2.
5. API xác minh Instance ID trên EC2 trong tài khoản/region của Lambda trước khi lưu, chống trùng ID đã đăng ký trong danh sách. EC2 đã liên kết không cho đổi loại/Instance ID khi sửa. Có thể sửa bản ghi EC2 mô phỏng cũ để liên kết ID hợp lệ; API bỏ các chỉ số mô phỏng cũ.
6. Xem Hiệu năng & Metrics. CPU/Network là CloudWatch AWS/EC2; RAM chỉ xuất hiện khi máy đã gửi metric `NetMon/EC2`, `mem_used_percent`, dimension `InstanceId` đúng. Không có mẫu thì hiện dấu —. Trạng thái khai báo của thiết bị không phải kết quả truy vấn trạng thái EC2 liên tục.

Không tạo hoặc khởi động EC2 mới khi đăng ký; xóa thiết bị trong NetMon chỉ xóa bản ghi DynamoDB, không terminate máy AWS. Mỗi EC2 mới cần tự cấu hình thu thập RAM và CloudWatch Alarm nếu muốn cảnh báo thực tế của riêng máy đó. Basic Monitoring giữ nguyên. Không tự bật các cảnh báo đã tạm tắt.

Kiểm tra cục bộ: Python/JavaScript hợp lệ; kiểm thử API và form bằng phản hồi AWS giả lập, chưa triển khai hoặc kiểm thử trên tài khoản thật. Nếu đã tự sửa Lambda sau khi nhận bản trước, đối chiếu mã để giữ các thay đổi riêng trước khi upload.
