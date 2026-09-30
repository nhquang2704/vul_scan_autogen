import subprocess
import os
import tempfile
import threading
import queue
import re
import time
import shlex
from config import get_nikto_path

NIKTO_PATH_FALLBACK = "C:\\tools\\nikto\\nikto-master\\program\\nikto.pl" # Fallback

def _reader_thread(pipe, q, stream_name):
    try:
        for line in iter(pipe.readline, ''):
            q.put((stream_name, line))
    except ValueError:
        pass
    except Exception as e:
        q.put((stream_name, f"Lỗi khi đọc stream {stream_name}: {str(e)}\n"))
    finally:
        q.put((stream_name, None))

def run_command(command_list):
    command_str_for_log = " ".join(shlex.quote(arg) for arg in command_list)
    full_stdout_list = []
    full_stderr_list = []
    process = None
    command_timeout_seconds = 660 # 11 phút 

    try:
        process = subprocess.Popen(
            command_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace',
            bufsize=1,
            startupinfo=subprocess.STARTUPINFO(dwFlags=subprocess.STARTF_USESHOWWINDOW, wShowWindow=subprocess.SW_HIDE) if os.name == 'nt' else None
        )
        output_queue = queue.Queue()

        stdout_thread = threading.Thread(target=_reader_thread, args=(process.stdout, output_queue, "STDOUT"))
        stderr_thread = threading.Thread(target=_reader_thread, args=(process.stderr, output_queue, "STDERR"))

        stdout_thread.daemon = True
        stderr_thread.daemon = True

        stdout_thread.start()
        stderr_thread.start()

        active_streams = 2
        start_time = time.time()

        while active_streams > 0:
            if time.time() - start_time > command_timeout_seconds:
                print(f"[TOOL_EXECUTOR] Lệnh vượt quá thời gian {command_timeout_seconds}s. Gửi tín hiệu dừng...")
                raise subprocess.TimeoutExpired(command_str_for_log, command_timeout_seconds)

            try:
                stream_name, line_content = output_queue.get(timeout=1.0) # Tăng nhẹ timeout get
                if line_content is None:
                    active_streams -= 1
                    continue

                print(f"[{stream_name}_LIVE] {line_content.rstrip()}", flush=True) # Giữ lại để theo dõi Nikto
                if stream_name == "STDOUT":
                    full_stdout_list.append(line_content)
                elif stream_name == "STDERR":
                    full_stderr_list.append(line_content)

            except queue.Empty:
                if process.poll() is not None:
                    break
                continue
            except Exception as e_q:
                err_msg = f"Lỗi khi xử lý queue output: {str(e_q)}\n"
                print(f"[TOOL_EXECUTOR_ERROR] {err_msg.strip()}", flush=True)
                full_stderr_list.append(err_msg)
                active_streams = 0 # Force break
                break

        if stdout_thread.is_alive(): stdout_thread.join(timeout=10)
        if stderr_thread.is_alive(): stderr_thread.join(timeout=10)

        while not output_queue.empty():
            try:
                stream_name, line_content = output_queue.get_nowait()
                if line_content is not None:
                    if stream_name == "STDOUT": full_stdout_list.append(line_content)
                    elif stream_name == "STDERR": full_stderr_list.append(line_content)
            except queue.Empty: break
            except Exception: break # Bỏ qua lỗi ở đây

        if process.poll() is None:
            try:
                process.kill()
                process.wait(timeout=5)
            except Exception: # Bỏ qua lỗi
                pass

        final_stdout = "".join(full_stdout_list)
        final_stderr = "".join(full_stderr_list)
        return_code = process.returncode if process else -1 # Sửa lỗi process có thể là None

        if return_code is None: return_code = -1

        if return_code != 0:
            if not final_stderr.strip() and not final_stdout.strip():
                final_stderr += f"\nLệnh hoàn thành với mã lỗi (return code): {return_code}. Không có output."
            elif not final_stderr.strip():
                final_stderr += f"\nLệnh hoàn thành với mã lỗi (return code): {return_code} (stderr trống)."

        return final_stdout, final_stderr

    except subprocess.TimeoutExpired:
        if process:
            process.kill()
            try: process.wait(timeout=10)
            except Exception: pass
            if stdout_thread and stdout_thread.is_alive(): stdout_thread.join(timeout=5)
            if stderr_thread and stderr_thread.is_alive(): stderr_thread.join(timeout=5)
        return "COMMAND_TIMEOUT", f"Lệnh vượt quá thời gian {command_timeout_seconds} giây và đã bị dừng."
    except FileNotFoundError as e_fnf:
        print(f"[TOOL_EXECUTOR] Lỗi FileNotFoundError: {e_fnf}.")
        return "", f"Lỗi FileNotFoundError: {str(e_fnf)}. Đảm bảo 'perl' trong PATH và đường dẫn script chính xác."
    except Exception as e:
        print(f"[TOOL_EXECUTOR] Exception không mong muốn khi chạy lệnh: {e}")
        return "", f"Exception khi chạy lệnh: {str(e)}"


def run_nikto_scan(nikto_command_str_from_agent):    
    try:
        command_parts_from_agent = shlex.split(nikto_command_str_from_agent)
    except ValueError as e:
        error_msg = f"Lỗi khi phân tích lệnh Nikto: {e}. Lệnh: '{nikto_command_str_from_agent}'"
        print(f"[NIKTO_SCANNER] {error_msg}")
        return "", error_msg

    # nikto_exe_path_env = os.getenv("NIKTO_PATH", NIKTO_PATH_FALLBACK)
    # if not os.path.exists(nikto_exe_path_env):
    #      return "", f"NIKTO_PATH '{nikto_exe_path_env}' không tồn tại."
    nikto_exe_path_env = get_nikto_path()

    # Đảm bảo lệnh bắt đầu đúng
    if not command_parts_from_agent or "perl" not in command_parts_from_agent[0].lower():
        actual_options = []
        # Nếu phần đầu tiên là một path trỏ đến nikto.pl thì bỏ nó
        if command_parts_from_agent and "nikto.pl" in command_parts_from_agent[0]:
            actual_options = command_parts_from_agent[1:]
        else:
            actual_options = command_parts_from_agent
        
        command_parts_from_agent = ["perl", nikto_exe_path_env] + actual_options       

    output_file_path = None
    has_output_option = False
    has_format_option = False
    target_name_for_file = "unknown_target"

    try:
        h_index = command_parts_from_agent.index('-h')
        if h_index + 1 < len(command_parts_from_agent):
            target_name_for_file = re.sub(r'[^\w\.-]', '_', command_parts_from_agent[h_index+1])
    except ValueError:
        pass

    idx = 0
    while idx < len(command_parts_from_agent):
        part = command_parts_from_agent[idx]
        if part in ("-o", "-output"):
            has_output_option = True
            if idx + 1 < len(command_parts_from_agent):
                output_file_path = command_parts_from_agent[idx+1]
            idx += 1
        elif part in ("-Format", "-F"):
            has_format_option = True
            if idx + 1 < len(command_parts_from_agent):
                if command_parts_from_agent[idx+1].lower() != 'txt':
                    print(f"[NIKTO_SCANNER] Cảnh báo: Format '{command_parts_from_agent[idx+1]}' không phải 'txt'.")
            idx += 1
        idx += 1

    final_command_list_for_execution = list(command_parts_from_agent)

    if not output_file_path:
        temp_dir = os.path.join(tempfile.gettempdir(), "autogen_nikto_scans")
        os.makedirs(temp_dir, exist_ok=True)
        temp_file_obj = tempfile.NamedTemporaryFile(
            dir=temp_dir, delete=False, suffix=".txt",
            prefix=f"nikto_scan_auto_{target_name_for_file}_",
            mode='w', encoding='utf-8'
        )
        output_file_path = temp_file_obj.name
        temp_file_obj.close()
        if not has_output_option:
            final_command_list_for_execution.extend(["-o", output_file_path])
        else:
            # print(f"[NIKTO_SCANNER] Cảnh báo: Lệnh có -o nhưng không lấy được path, sẽ thêm path tạm mới.") # Giảm log
            final_command_list_for_execution.extend(["-o", output_file_path])
        # print(f"[NIKTO_SCANNER] Lệnh được cập nhật để ghi vào file tạm: \"{output_file_path}\"") # Giảm log


    if not has_format_option:
        final_command_list_for_execution.extend(["-Format", "txt"])
        # print(f"[NIKTO_SCANNER] Lệnh được cập nhật, thêm '-Format txt'") # Giảm log

    # print(f"[NIKTO_SCANNER] Lệnh Nikto cuối cùng sẽ được thực thi: {' '.join(shlex.quote(arg) for arg in final_command_list_for_execution)}") # Giảm log

    stdout_cmd, stderr_cmd = run_command(final_command_list_for_execution)

    nikto_scan_results_from_file = ""
    error_reading_file = ""
    file_successfully_read = False

    if not output_file_path:
        error_reading_file = "Không xác định được đường dẫn file output."
        # print(f"[NIKTO_SCANNER] {error_reading_file}") # Giảm log
    else:
        try:
            time.sleep(1) # Đợi file ghi xong
            if os.path.exists(output_file_path) and os.path.getsize(output_file_path) > 0:
                with open(output_file_path, 'r', encoding='utf-8', errors='replace') as f:
                    nikto_scan_results_from_file = f.read()
                # print(f"[NIKTO_SCANNER] Đã đọc thành công kết quả từ file: {output_file_path}") # Giảm log
                file_successfully_read = True
                if "nikto_scan_auto_" in os.path.basename(output_file_path) and \
                   tempfile.gettempdir() in os.path.abspath(os.path.dirname(output_file_path)):
                    try:
                        os.remove(output_file_path)
                        # print(f"[NIKTO_SCANNER] Đã xóa file tạm: {output_file_path}") # Giảm log
                    except Exception as e_remove:
                        print(f"[NIKTO_SCANNER] Không thể xóa file tạm {output_file_path}: {e_remove}")
            elif os.path.exists(output_file_path):
                error_reading_file = f"File output Nikto '{output_file_path}' rỗng."
                # print(f"[NIKTO_SCANNER] {error_reading_file}") # Giảm log
            else:
                error_reading_file = f"File output Nikto '{output_file_path}' không được tạo."
                # print(f"[NIKTO_SCANNER] {error_reading_file}") # Giảm log
        except Exception as e:
            error_reading_file = f"Lỗi khi đọc file output Nikto '{output_file_path}': {str(e)}"
            # print(f"[NIKTO_SCANNER] {error_reading_file}") # Giảm log

    if not file_successfully_read and stdout_cmd:
        # print("[NIKTO_SCANNER] Sử dụng stdout làm kết quả fallback.") # Giảm log
        nikto_scan_results_from_file = stdout_cmd
    # elif not file_successfully_read and not stdout_cmd:
        # print("[NIKTO_SCANNER] Không có output từ file lẫn stdout.") # Giảm log

    final_stderr = stderr_cmd.strip() if stderr_cmd else ""
    if error_reading_file:
        final_stderr = f"{final_stderr}\n{error_reading_file}".strip()

    if not nikto_scan_results_from_file and not final_stderr:
        final_stderr = "Nikto không tạo ra output hoặc output không thể đọc được."

    return nikto_scan_results_from_file, final_stderr


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    NIKTO_SCRIPT_PATH_TEST = os.getenv("NIKTO_PATH")

    print("--- Testing tool_executor.py (Nikto only) ---")

    if NIKTO_SCRIPT_PATH_TEST and os.path.exists(NIKTO_SCRIPT_PATH_TEST):
        print("\n[TEST] Gọi Nikto -Version...")
        version_cmd_list = ["perl", NIKTO_SCRIPT_PATH_TEST, "-Version"]
        stdout_v, stderr_v = run_command(version_cmd_list)
        print(f"--- Nikto Version STDOUT ---\n{stdout_v.strip()}")
        if stderr_v.strip(): print(f"--- Nikto Version STDERR ---\n{stderr_v.strip()}")

        print("\n[TEST] Gọi Nikto quét testphp.vulnweb.com (sẽ mất một lúc)...")
        target_for_nikto_test = "https://hoclieu.vn/"
        # Sửa đổi lệnh test cho phù hợp
        # Agent sẽ đề xuất một chuỗi lệnh như thế này:
        proposed_nikto_cmd_str_from_agent = (
            f'perl "{NIKTO_SCRIPT_PATH_TEST}" -h {target_for_nikto_test} '
            f'-Format txt -o "nikto_output_test_{target_for_nikto_test}.txt" ' # Agent tự thêm -o
            f'-Tuning x 0 6 -ask no -maxtime 60s -port 80' # maxtime ngắn để test
        )

        nikto_results, nikto_err = run_nikto_scan(proposed_nikto_cmd_str_from_agent)

        print(f"\n--- Nikto Scan Results (đọc từ file nếu có) --- (first 500 chars)\n{nikto_results[:500].strip()}...")
        if nikto_err.strip(): print(f"--- Nikto Scan Errors/Console Output ---\n{nikto_err.strip()}")

        # Xóa file output test nếu nó được tạo (nếu agent tự tạo file tạm thì nó đã tự xóa)
        # Nếu agent dùng file cố định thì ta phải xóa thủ công
        output_file_test_name = f"nikto_output_test_{target_for_nikto_test}.txt"
        if os.path.exists(output_file_test_name):
            try:
                os.remove(output_file_test_name)
                print(f"[TEST] Đã xóa file test output: {output_file_test_name}")
            except Exception as e_del:
                print(f"[TEST] Lỗi khi xóa file test output: {e_del}")
    else:
        print(f"Đường dẫn Nikto script ('{NIKTO_SCRIPT_PATH_TEST}') không hợp lệ. Bỏ qua test Nikto.")
    print("\n--- tool_executor.py test finished ---")