# config.py
import os
from dotenv import load_dotenv

load_dotenv()
def get_llm_config():
    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        print("DEEPSEEK_API_KEY không được tìm thấy trong file .env")
        return None
    
    config_list_deepseek = [
        {
            "model": "deepseek-chat",
            "api_key": api_key,
            "base_url": "https://api.deepseek.com/v1"
        }
    ]

    llm_config = {
        "config_list": config_list_deepseek,
        "cache_seed": None,  
        "temperature": 0.1,  
    }
    return llm_config

def get_nikto_path():
    nikto_path = os.getenv("NIKTO_PATH")
    if not nikto_path or not os.path.exists(nikto_path):
        print(f"Lỗi: NIKTO_PATH ('{nikto_path}') không hợp lệ hoặc file Nikto không tồn tại. Vui lòng kiểm tra .env")
        return None
    return nikto_path

DEFAULT_REPORTS_DIR = "reports"