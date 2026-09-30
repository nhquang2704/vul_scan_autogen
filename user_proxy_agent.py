from urllib.parse import urlparse
import autogen
import os
from tool_executor import run_nikto_scan
from report_generator_docx import generate_docx_report # Import hàm tạo docx
import re # Thêm import re

class MyUserProxyAgent(autogen.UserProxyAgent):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.target_host = None
        self.nikto_command_proposal = None
        self.nikto_scan_results = None
        self.analysis_from_analyzer = None
        self.report_from_reporter = None

    def set_target(self, target_host):
        self.target_host = target_host
        # print(f"[UserProxy] Đã đặt mục tiêu quét (hostname/IP): {self.target_host}") # Giảm log

    def receive_nikto_command_proposal(self, command):
        self.nikto_command_proposal = command
        # print(f"[UserProxy] Nhận được đề xuất lệnh Nikto: {self.nikto_command_proposal}") # Giảm log

    def execute_scans(self):
        if not self.nikto_command_proposal:
            error_msg = "[UserProxy] Lỗi: Không có lệnh Nikto nào được đề xuất để thực thi."
            print(error_msg)
            return error_msg # Trả về lỗi để main.py xử lý

        print(f"[UserProxy] Bắt đầu quét Nikto với lệnh: {self.nikto_command_proposal}")
        # Gọi hàm run_nikto_scan từ tool_executor
        scan_output, scan_error = run_nikto_scan(self.nikto_command_proposal)

        if scan_output == "COMMAND_TIMEOUT":
            self.nikto_scan_results = f"LỖI QUÉT: {scan_error}\n{scan_output}"
            print(f"[UserProxy] Lỗi: Quét Nikto bị timeout. {scan_error}")
            return self.nikto_scan_results # Trả về lỗi để main.py xử lý

        if scan_error:
            self.nikto_scan_results = f"KẾT QUẢ QUÉT (CÓ THỂ CÓ LỖI):\n{scan_output}\n\nLỖI/STDERR TỪ NIKTO:\n{scan_error}"
            print(f"[UserProxy] Quét Nikto hoàn thành với lỗi hoặc cảnh báo trên stderr.")
        else:
            self.nikto_scan_results = scan_output
            print(f"[UserProxy] Quét Nikto hoàn thành.")
        
        if not self.nikto_scan_results.strip():
             self.nikto_scan_results = "Không có kết quả nào từ Nikto hoặc kết quả rỗng."
             print("[UserProxy] Cảnh báo: Kết quả quét Nikto rỗng.")
        
        return self.nikto_scan_results


    def receive_analysis(self, analysis):
        self.analysis_from_analyzer = analysis
        # print("[UserProxy] Đã nhận phân tích từ AnalyzerAgent.") # Giảm log

    def receive_report_content(self, report_content):
        self.report_from_reporter = report_content
        # print("[UserProxy] Đã nhận nội dung báo cáo từ ReporterAgent.") # Giảm log

    def generate_and_save_docx_report(self, original_target_url=None): # Thêm tham số original_target_url
        if not self.report_from_reporter:
            error_msg = "[UserProxy] Lỗi: Không có nội dung báo cáo để tạo file DOCX."
            print(error_msg)
            return error_msg
        if not self.target_host: # self.target_host là hostname/IP đã làm sạch
            error_msg = "[UserProxy] Lỗi: Không có thông tin mục tiêu (đã làm sạch) để đặt tên file DOCX."
            print(error_msg)
            return error_msg

        # Sử dụng self.target_host (đã làm sạch) cho tên file prefix
        safe_filename_target_component = re.sub(r'[^\w\.-]', '_', self.target_host)
        
        # Lấy port từ original_target_url để thêm vào tên file nếu có
        port_str_for_filename = ""
        if original_target_url:
            parsed_original_url = urlparse(original_target_url.strip().lower())
            if parsed_original_url.port:
                port_str_for_filename = f"_{parsed_original_url.port}"
        
        safe_filename_target_component += port_str_for_filename
        safe_filename_target_component = safe_filename_target_component[:50] # Giới hạn độ dài
        docx_filename_prefix = f"VulnReport_{safe_filename_target_component}"
        target_to_display_in_report = original_target_url if original_target_url else self.target_host

        status_msg = generate_docx_report(
            target_host=target_to_display_in_report, # HOẶC self.target_host tùy bạn
            report_markdown_content=self.report_from_reporter,
            filename_prefix=docx_filename_prefix
        )
        print(f"[UserProxy] {status_msg}")
        return status_msg

