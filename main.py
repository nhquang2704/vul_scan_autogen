import autogen
import os
from urllib.parse import urlparse
import re

from user_proxy_agent import MyUserProxyAgent # Đảm bảo file này tồn tại và đúng
from scanner_agent import create_scanner_agent
from analyzer_agent import create_analyzer_agent # Đảm bảo file này tồn tại và đúng
from reporter_agent import create_reporter_agent # Đảm bảo file này tồn tại và đúng
from config import get_llm_config, get_nikto_path # Đảm bảo file này tồn tại và đúng

def main():
    llm_config = get_llm_config()
    nikto_path_env = get_nikto_path()

    if not llm_config:
        print("Lỗi: Không thể lấy cấu hình LLM.")
        return
    if not nikto_path_env:
        print("Lỗi: Không thể lấy đường dẫn Nikto.")
        return

    # KHỞI TẠO AGENTS 
    user_proxy = MyUserProxyAgent(
       name="UserProxyControl",
       human_input_mode="NEVER",
       max_consecutive_auto_reply=10,
       code_execution_config=False,
    )

    scanner_agent = create_scanner_agent(llm_config)
    analyzer_agent = create_analyzer_agent(llm_config)
    reporter_agent = create_reporter_agent(llm_config)

    # ĐỊNH NGHĨA MỤC TIÊU 
    target_input_raw = input("Nhập địa chỉ IP hoặc hostname của mục tiêu (ví dụ: https://example.com:443): ")
    if not target_input_raw.strip():
        print("Mục tiêu không được để trống.")
        return

    parsed_url = urlparse(target_input_raw.strip().lower())
    target_host_for_scan = ""

    if parsed_url.hostname:
        target_host_for_scan = parsed_url.hostname
    elif parsed_url.path:
        path_parts = parsed_url.path.split('/')
        if path_parts and path_parts[0]:
            target_host_for_scan = path_parts[0]
        else: # Trường hợp path rỗng hoặc chỉ có /
             target_host_for_scan = target_input_raw.strip().split('/')[0] # Fallback
    else: # Fallback cuối cùng
        target_host_for_scan = target_input_raw.strip().split('/')[0]

    # Kiểm tra tính hợp lệ của hostname/IP sau khi trích xuất
    hostname_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"
    # Mở rộng IPv4 pattern để chấp nhận các giá trị hợp lệ hơn một chút
    ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

    if not (re.fullmatch(hostname_pattern, target_host_for_scan) or re.fullmatch(ipv4_pattern, target_host_for_scan)):
        print(f"Hostname/IP '{target_host_for_scan}' có vẻ không hợp lệ sau khi parse từ '{target_input_raw}'. Vui lòng kiểm tra lại.")
        return

    # XÁC ĐỊNH PORT VÀ TÙY CHỌN SSL CHO NIKTO 
    port_for_scan_str = None
    use_ssl = False

    if parsed_url.scheme == "https":
        use_ssl = True
        if parsed_url.port:
            port_for_scan_str = str(parsed_url.port)
        else:
            port_for_scan_str = "443" # Mặc định cho https
    elif parsed_url.scheme == "http":
        use_ssl = False
        if parsed_url.port:
            port_for_scan_str = str(parsed_url.port)
        else:
            port_for_scan_str = "80" # Mặc định cho http
    elif parsed_url.port: # Không có scheme nhưng có port
        port_for_scan_str = str(parsed_url.port)
        if port_for_scan_str in ["443", "8443"]: # Có thể mở rộng danh sách này
            use_ssl = True
        else:
            use_ssl = False # Mặc định không SSL nếu port khác
    # Nếu không có scheme và không có port, Nikto sẽ mặc định port 80 và không SSL

    nikto_ssl_option_str = "-ssl" if use_ssl else "-nossl"
    # Chỉ thêm -port nếu port_for_scan_str được xác định. Nếu không, Nikto sẽ tự dùng port mặc định.
    nikto_port_option_str = f"-port {port_for_scan_str}" if port_for_scan_str else ""

    print(f"[Main] Mục tiêu quét (hostname/IP): {target_host_for_scan}")
    print(f"[Main] Tùy chọn SSL dự kiến cho Nikto: {nikto_ssl_option_str}")
    if nikto_port_option_str:
        print(f"[Main] Tùy chọn Port dự kiến cho Nikto: {nikto_port_option_str}")
    else:
        print(f"[Main] Tùy chọn Port dự kiến cho Nikto: Sẽ sử dụng port mặc định của Nikto dựa trên SSL/nossl.")
    user_proxy.set_target(target_host_for_scan)


    # BƯỚC 1: ScannerAgent đề xuất lệnh Nikto 
    print(f"\n--- BƯỚC 1: ScannerAgent đề xuất lệnh Nikto cho {target_host_for_scan} ---")
    
    safe_target_for_nikto_output = re.sub(r'[^\w\.-]', '_', target_host_for_scan)
    if port_for_scan_str: # Thêm port vào tên file nếu có để phân biệt
        safe_target_for_nikto_output += f"_{port_for_scan_str}"
    suggested_nikto_output_file = f"nikto_output_{safe_target_for_nikto_output}.txt"
    redirect_save_dir = f"redirects_{safe_target_for_nikto_output}"

    # CẬP NHẬT SCANNER_TASK 
    scanner_task = (
        f"Dựa trên các thông tin sau, hãy đề xuất một lệnh quét Nikto HOÀN CHỈNH và CHÍNH XÁC:\n"
        f"1. Mục tiêu quét (hostname/IP): '{target_host_for_scan}'\n"
        f"2. Đường dẫn Nikto trên hệ thống: \"{nikto_path_env}\"\n"
        f"3. Tên file output gợi ý: '{suggested_nikto_output_file}'\n"
        f"4. Tên thư mục lưu redirects gợi ý cho tùy chọn -Save: '{redirect_save_dir}'.\n"
        f"5. Sử dụng tùy chọn SSL sau: '{nikto_ssl_option_str}'.\n"
        f"6. Sử dụng tùy chọn port sau (nếu có): '{nikto_port_option_str}'. Nếu chuỗi này rỗng, không thêm tùy chọn -port vào lệnh, Nikto sẽ dùng port mặc định.\n\n"
        f"LƯU Ý QUAN TRỌNG:\n"
        f"- Lệnh phải bắt đầu bằng 'perl \"{nikto_path_env}\" ...'.\n"
        f"- Sử dụng tùy chọn '-h {target_host_for_scan}' cho mục tiêu.\n"
        f"- Luôn bao gồm '{nikto_ssl_option_str}' trong lệnh của bạn.\n"
        f"- Nếu '{nikto_port_option_str}' không rỗng, hãy bao gồm nó trong lệnh. Nếu rỗng, KHÔNG thêm tùy chọn '-port'.\n"
        f"- Luôn bao gồm '-Format txt' và '-o \"{suggested_nikto_output_file}\"'. Đảm bảo đường dẫn file output được đặt trong dấu ngoặc kép nếu nó có thể chứa khoảng trắng hoặc ký tự đặc biệt (mặc dù tên file gợi ý đã được làm sạch).\n"
        f"- Sử dụng các tùy chọn tiêu chuẩn như đã định nghĩa trong system prompt của bạn (ví dụ: -maxtime 600s, -Tuning 12345, -ask no, -evasion).\n"
        f"TRẢ LỜI CHỈ BẰNG MỘT DÒNG DUY NHẤT CHỨA CHUỖI LỆNH. KHÔNG SỬ DỤNG KHỐI MÃ MARKDOWN (KHÔNG CÓ ```). KHÔNG GIẢI THÍCH GÌ THÊM."
    )
    
    user_proxy.initiate_chat(
        recipient=scanner_agent,
        message=scanner_task,
        max_turns=1, 
        summary_method="last_msg"
    )
    
    # Xử lý output từ ScannerAgent để loại bỏ Markdown (đã hoạt động tốt ở lần trước)
    raw_proposal = ""
    last_msg_from_scanner = scanner_agent.last_message(user_proxy)
    if last_msg_from_scanner:
        raw_proposal = last_msg_from_scanner.get("content", "").strip()
    else:
        raw_proposal = user_proxy.last_message(scanner_agent).get("content","").strip()

    nikto_command_proposal = raw_proposal
    # Đoạn code xử lý Markdown ``` phòng trường hợp LLM đôi khi vẫn trả về Markdown
    if nikto_command_proposal.startswith("```") and nikto_command_proposal.endswith("```"):
        lines = nikto_command_proposal.splitlines()
        if len(lines) > 2:
            nikto_command_proposal = "\n".join(lines[1:-1]).strip()
        elif len(lines) == 1 and lines[0].count("```") == 2:
            nikto_command_proposal = lines[0].replace("```", "").strip()
        if nikto_command_proposal.lower().startswith("perl ") and not nikto_command_proposal.startswith("perl "): # LLM có thể thêm "perl " sau ```perl
            nikto_command_proposal = nikto_command_proposal[nikto_command_proposal.lower().find("perl "):]
    
    if not nikto_command_proposal or not nikto_command_proposal.lower().startswith("perl"): # Chuyển sang lower() để linh hoạt hơn
        print(f"Lỗi: ScannerAgent không trả về lệnh Nikto hợp lệ. Nhận được (thô):\n'{raw_proposal}'\nĐã xử lý thành:\n'{nikto_command_proposal}'")
        return
    
    user_proxy.receive_nikto_command_proposal(nikto_command_proposal)
    print(f"[Main] Lệnh Nikto đề xuất: {user_proxy.nikto_command_proposal}")

    # BƯỚC 2: UserProxy thực hiện quét Nikto 
    print("\n--- BƯỚC 2: UserProxy thực hiện quét Nikto ---")
    nikto_scan_results_or_error = user_proxy.execute_scans()
    
    if isinstance(nikto_scan_results_or_error, str) and (
        "[UserProxy] Lỗi:" in nikto_scan_results_or_error or
        "LỖI QUÉT:" in nikto_scan_results_or_error or
        "Không có kết quả nào từ Nikto" in nikto_scan_results_or_error
        ):
        print(f"[Main] {nikto_scan_results_or_error}")
        if "LỖI QUÉT:" in nikto_scan_results_or_error or "[UserProxy] Lỗi:" in nikto_scan_results_or_error:
            print("\n--- QUÁ TRÌNH DỪNG DO LỖI QUÉT ---")
            return

    # BƯỚC 3: AnalyzerAgent phân tích kết quả Nikto 
    print("\n--- BƯỚC 3: AnalyzerAgent phân tích kết quả Nikto ---")
    analyzer_task = (
        f"Phân tích kết quả quét lỗ hổng từ Nikto sau cho mục tiêu '{target_host_for_scan}'. "
        f"Nếu kết quả trống hoặc chỉ chứa lỗi, hãy chỉ ra điều đó.\n\n"
        f"Thông tin quét bổ sung (nếu có):\n"
        f"- URL đầu vào: {target_input_raw}\n"
        f"- Lệnh Nikto đã chạy: {user_proxy.nikto_command_proposal}\n\n"
        f"Kết quả quét:\n{user_proxy.nikto_scan_results}"
    )
    user_proxy.initiate_chat(
        recipient=analyzer_agent,
        message=analyzer_task,
        max_turns=1, 
        summary_method="last_msg"
    )
    
    last_msg_from_analyzer = analyzer_agent.last_message(user_proxy)
    if last_msg_from_analyzer:
        analysis_output = last_msg_from_analyzer.get("content","").strip()
    else:
        analysis_output = user_proxy.last_message(analyzer_agent).get("content","").strip()
        
    if not analysis_output:
        print(f"Lỗi: AnalyzerAgent không trả về phân tích.")
        analysis_output = "AnalyzerAgent không cung cấp phân tích."
    
    user_proxy.receive_analysis(analysis_output)

    # BƯỚC 4: ReporterAgent viết báo cáo 
    print("\n--- BƯỚC 4: ReporterAgent viết báo cáo ---")
    reporter_task = (
        f"Dựa trên bản phân tích lỗ hổng từ Nikto sau cho mục tiêu '{target_host_for_scan}' (URL gốc: {target_input_raw}), "
        f"hãy viết một báo cáo đánh giá lỗ hổng hoàn chỉnh theo định dạng Markdown.\n"
        f"Nếu bản phân tích chỉ ra rằng không có kết quả hoặc có lỗi, hãy phản ánh điều đó trong báo cáo.\n"
        f"Thông tin lệnh Nikto đã chạy (nếu cần tham khảo): {user_proxy.nikto_command_proposal}\n\n"
        f"Bản phân tích:\n{user_proxy.analysis_from_analyzer}"
    )
    user_proxy.initiate_chat(
        recipient=reporter_agent,
        message=reporter_task,
        max_turns=1,
        summary_method="last_msg"
    )

    last_msg_from_reporter = reporter_agent.last_message(user_proxy)
    if last_msg_from_reporter:
        report_content_markdown = last_msg_from_reporter.get("content","").strip()
    else:
        report_content_markdown = user_proxy.last_message(reporter_agent).get("content","").strip()

    if not report_content_markdown:
        print(f"Lỗi: ReporterAgent không trả về nội dung báo cáo.")
        report_content_markdown = "# Báo cáo Lỗi\n\nReporterAgent không thể tạo báo cáo."
        
    user_proxy.receive_report_content(report_content_markdown)
    
    # BƯỚC 5: UserProxy tự tạo file DOCX 
    print("\n--- BƯỚC 5: UserProxy tạo file DOCX ---")
    # Truyền thêm target_input_raw để có thể dùng trong tên file hoặc nội dung báo cáo nếu muốn
    docx_creation_status = user_proxy.generate_and_save_docx_report(original_target_url=target_input_raw)


    if "Báo cáo đã được lưu thành công vào:" in docx_creation_status:
        print("\n--- QUÁ TRÌNH HOÀN TẤT THÀNH CÔNG ---")
    else:
        print("\n--- QUÁ TRÌNH HOÀN TẤT (CÓ THỂ CÓ LỖI KHI TẠO DOCX) ---")

if __name__ == "__main__":
    main()