# VulScan AutoGen 🛡️🤖

VulScan AutoGen là một hệ thống tự động hóa đánh giá và phân tích lỗ hổng bảo mật web, kết hợp sức mạnh của công cụ quét phổ biến **Nikto** và nền tảng Multi-Agent **AutoGen** (với mô hình LLM DeepSeek). 

Hệ thống tự động hóa toàn bộ quy trình: từ việc lên kịch bản quét, thực thi lệnh quét, phân tích sâu kết quả rà quét, cho đến việc xuất ra một báo cáo đánh giá lỗ hổng hoàn chỉnh (dưới định dạng DOCX).

## 🌟 Tính năng nổi bật

Dự án này sử dụng kiến trúc Multi-Agent, trong đó mỗi Agent đảm nhiệm một vai trò chuyên biệt:
*   **ScannerAgent:** Đề xuất và tối ưu hóa các tham số dòng lệnh cho Nikto dựa trên mục tiêu (IP/Hostname).
*   **AnalyzerAgent:** Hoạt động như một Chuyên gia phân tích An ninh mạng cấp cao, đánh giá kết quả quét thô của Nikto, loại bỏ cảnh báo giả (false positives) và đánh giá mức độ rủi ro, đưa ra hướng khắc phục.
*   **ReporterAgent:** Chuyên gia truyền thông kỹ thuật, tổng hợp các phân tích kỹ thuật thành báo cáo Markdown chuyên nghiệp.
*   **UserProxyControl:** Điều phối tự động việc thực thi mã nguồn (chạy Nikto) và lưu báo cáo cuối cùng sang định dạng `.docx`.

## 🛠️ Yêu cầu hệ thống (Prerequisites)

Để chạy được dự án này, hệ thống của bạn cần cài đặt:
1.  **Python 3.8+**
2.  **Perl:** Bắt buộc để chạy Nikto.
3.  **Nikto Vulnerability Scanner:** Tải và giải nén trên máy tính của bạn.
4.  **DeepSeek API Key:** Đăng ký tại nền tảng DeepSeek để sử dụng LLM.

## 🚀 Cài đặt

**1. Clone kho lưu trữ này về máy:**
```bash
git clone https://github.com/yourusername/vulscan-autogen.git
cd vulscan-autogen
```

**2. Cài đặt các thư viện Python:**
```bash
pip install -r requirements.txt
```

**3. Cấu hình biến môi trường (`.env`):**
Tạo một file có tên `.env` tại thư mục gốc của dự án. **Không chia sẻ file này lên Git.**
Mở file `.env` và thêm các nội dung sau:

```env
# Điền API Key của bạn (KHÔNG BAO GIỜ COMMIT KEY THẬT LÊN GITHUB)
DEEPSEEK_API_KEY=your_deepseek_api_key_here

# Đường dẫn tuyệt đối đến file thực thi nikto.pl trên máy của bạn
# Ví dụ trên Windows:
NIKTO_PATH="C:\\tools\\nikto\\nikto-master\\program\\nikto.pl"
# Ví dụ trên Linux/macOS:
# NIKTO_PATH="/usr/local/bin/nikto.pl"
```

## 🎯 Hướng dẫn sử dụng

Chạy file `main.py` để khởi động chương trình:

```bash
python main.py
```

Hệ thống sẽ yêu cầu bạn nhập mục tiêu cần quét:
```text
Nhập địa chỉ IP hoặc hostname của mục tiêu (ví dụ: https://example.com:443): 
```

**Quy trình thực thi diễn ra hoàn toàn tự động:**
1.  Hệ thống chuẩn hóa URL/IP đầu vào.
2.  Tạo và chạy kịch bản Nikto.
3.  Phân tích kết quả (nếu có lỗ hổng hoặc cấu hình yếu).
4.  Tự động tạo file báo cáo chi tiết.
5.  File báo cáo cuối cùng sẽ được lưu trong thư mục `reports/` dưới dạng `.docx` (ví dụ: `vulnerability_report_20261026_153000.docx`).

## 📁 Cấu trúc thư mục

```text
├── analyzer_agent.py         # Chứa logic của Agent phân tích lỗ hổng
├── config.py                 # Xử lý biến môi trường và cấu hình LLM
├── main.py                   # Điểm neo chạy chương trình chính
├── report_generator_docx.py  # Script xuất từ markdown sang DOCX
├── reporter_agent.py         # Chứa logic của Agent viết báo cáo
├── scanner_agent.py          # Chứa logic của Agent chuẩn bị lệnh quét
├── user_proxy_agent.py       # Tương tác với HĐH để chạy Nikto (tự bổ sung)
├── requirements.txt          # Danh sách thư viện phụ thuộc
├── .env                      # [BẠN TỰ TẠO] Cấu hình khóa API và đường dẫn
└── reports/                  # Thư mục lưu báo cáo (tự động tạo)
```

## ⚠️ Khuyến cáo và Đạo đức Nghề nghiệp (Disclaimer)

*   Công cụ này **CHỈ** được sử dụng cho mục đích giáo dục và kiểm thử an toàn thông tin trên các hệ thống mà bạn **có thẩm quyền hợp pháp**.
*   Tác giả không chịu trách nhiệm cho bất kỳ hành vi lạm dụng nào nhắm vào hệ thống chưa được cấp phép. Hành vi quét một hệ thống công khai khi chưa được phép là vi phạm pháp luật.

## 🤝 Đóng góp (Contributing)
Mọi đóng góp nhằm tối ưu hóa prompt, thêm các công cụ quét mới (như Nmap, OWASP ZAP) hay cải thiện định dạng báo cáo đều được hoan nghênh. Vui lòng tạo Pull Request!