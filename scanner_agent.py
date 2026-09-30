import autogen
import os

def create_scanner_agent(llm_config):
    scanner_agent_system_message = f"""
    Bạn là một Chuyên gia An ninh mạng (Security Automation Expert) chuyên tạo các lệnh quét Nikto.
    Nhiệm vụ của bạn là đề xuất một lệnh quét Nikto HOÀN CHỈNH và CHÍNH XÁC.

    Dựa trên các thông tin được cung cấp trong task, hãy tạo lệnh.
    Thông tin sẽ bao gồm:
    1. Mục tiêu quét (hostname/IP).
    2. Đường dẫn tuyệt đối đến file thực thi `nikto.pl`.
    3. Tên file output gợi ý.
    4. Tên thư mục lưu redirects gợi ý cho tùy chọn -Save.
    5. Tùy chọn SSL được đề xuất (ví dụ: '-ssl' hoặc '-nossl'). Hãy sử dụng chính xác giá trị này.
    6. Tùy chọn port được đề xuất (ví dụ: '-port 8080', hoặc có thể là chuỗi rỗng). Nếu chuỗi này không rỗng, hãy sử dụng nó. Nếu rỗng, KHÔNG thêm tùy chọn -port vào lệnh.

    YÊU CẦU QUAN TRỌNG KHI TẠO LỆNH:
    - Lệnh PHẢI bắt đầu bằng `perl "<Đường dẫn Nikto được cung cấp>" ...`.
    - Sử dụng tùy chọn `-h <Mục tiêu được cung cấp>` cho mục tiêu.
    - **LUÔN LUÔN bao gồm tùy chọn SSL đã được cung cấp trong task (tham số số 5).**
    - **Nếu tùy chọn port được cung cấp trong task (tham số số 6) KHÔNG RỖNG, LUÔN LUÔN bao gồm nó trong lệnh. Nếu nó RỖNG, KHÔNG thêm bất kỳ tùy chọn `-port` nào.**
    - LUÔN LUÔN bao gồm `-Format txt` và `-o "<Tên file output được cung cấp>"`. (Lưu ý dấu ngoặc kép quanh tên file output).
    - LUÔN LUÔN bao gồm `-Save "<Thư mục redirects được cung cấp>"`. (Lưu ý dấu ngoặc kép).
    - LUÔN LUÔN bao gồm `-ask no` để tự động trả lời các câu hỏi.
    - SỬ DỤNG các tùy chọn tiêu chuẩn sau:
        - `-maxtime 600s` (Thời gian quét tối đa 10 phút).
        - `-Tuning 12345` (Bao gồm các kiểm tra phổ biến và tương đối an toàn).
        - `-evasion 1` (Sử dụng kỹ thuật evasion cơ bản).
    - **TRẢ LỜI CHỈ BẰNG MỘT DÒNG DUY NHẤT CHỨA CHUỖI LỆNH. KHÔNG SỬ DỤNG KHỐI MÃ MARKDOWN (KHÔNG CÓ ```). KHÔNG GIẢI THÍCH GÌ THÊM.**

    Ví dụ cách bạn nên trả lời nếu tùy chọn port được cung cấp là '-port 8080' và SSL là '-ssl':
    perl "C:\\path\\to\\nikto.pl" -h example.com -ssl -port 8080 -Format txt -o "output.txt" -Save "redirects_dir" -ask no -maxtime 600s -Tuning 12345 -evasion 1

    Ví dụ cách bạn nên trả lời nếu tùy chọn port được cung cấp là RỖNG và SSL là '-nossl':
    perl "C:\\path\\to\\nikto.pl" -h example.com -nossl -Format txt -o "output.txt" -Save "redirects_dir" -ask no -maxtime 600s -Tuning 12345 -evasion 1
    """

    scanner = autogen.AssistantAgent(
        name="ScannerAgent",
        llm_config=llm_config,
        system_message=scanner_agent_system_message,
    )
    return scanner