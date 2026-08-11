import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[3]  # 项目根目录
DATA_DIR = BASE_DIR / "data"
SAMPLES_DIR = BASE_DIR / "samples"
OUTPUT_ROOT = Path(os.environ.get("REVLAB_OUTPUT_DIR", str(BASE_DIR)))  # 分析产物根目录(可配置)
REPORTS_DIR = OUTPUT_ROOT / "reports"
CAPTURES_DIR = OUTPUT_ROOT / "captures"
UNPACKED_DIR = OUTPUT_ROOT / "unpacked"
SDK_DIR = OUTPUT_ROOT / "sdk"
GHIDRA_DIR = BASE_DIR / "ghidra"
TOOLS_DIR = BASE_DIR / "tools"
WORKSPACE_DIR = BASE_DIR / "workspace"

for _d in (DATA_DIR, SAMPLES_DIR, REPORTS_DIR, CAPTURES_DIR, UNPACKED_DIR,
           GHIDRA_DIR, TOOLS_DIR, WORKSPACE_DIR, SDK_DIR):
    _d.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "revlab.db"
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"

MAX_UPLOAD_SIZE = 200 * 1024 * 1024  # 200MB 样本上限


def _apply_output_root(root: Path):
    """运行时切换分析产物输出目录。"""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    Config.REPORTS_DIR = root / "reports"
    Config.CAPTURES_DIR = root / "captures"
    Config.UNPACKED_DIR = root / "unpacked"
    Config.SDK_DIR = root / "sdk"
    Config.WORKSPACE_DIR = root / "workspace"
    for _d in (Config.REPORTS_DIR, Config.CAPTURES_DIR, Config.UNPACKED_DIR,
               Config.SDK_DIR, Config.WORKSPACE_DIR):
        _d.mkdir(parents=True, exist_ok=True)


# 分析引擎开关(可被环境变量覆盖)
class Config:
    BASE_DIR = BASE_DIR
    DATA_DIR = DATA_DIR
    SAMPLES_DIR = SAMPLES_DIR
    OUTPUT_ROOT = OUTPUT_ROOT
    REPORTS_DIR = REPORTS_DIR
    CAPTURES_DIR = CAPTURES_DIR
    UNPACKED_DIR = UNPACKED_DIR
    SDK_DIR = SDK_DIR
    GHIDRA_DIR = GHIDRA_DIR
    TOOLS_DIR = TOOLS_DIR
    WORKSPACE_DIR = WORKSPACE_DIR
    DB_PATH = DB_PATH
    MAX_UPLOAD_SIZE = MAX_UPLOAD_SIZE

    ENABLE_GHIDRA = os.environ.get("REVLAB_ENABLE_GHIDRA", "1") == "1"
    GHIDRA_HOME = os.environ.get("GHIDRA_HOME", "")
    UPX_PATH = os.environ.get("UPX_PATH", str(TOOLS_DIR / "upx" / "upx.exe"))
    PESIEVE_PATH = os.environ.get("PESIEVE_PATH", str(TOOLS_DIR / "pe-sieve" / "pe-sieve64.exe"))
    VMWARE_RUN = os.environ.get("VMWARE_RUN", r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe")
    SANDBOX_TIMEOUT = int(os.environ.get("REVLAB_SANDBOX_TIMEOUT", "90"))
    SANDBOX_RUN_ARGS = os.environ.get("REVLAB_SANDBOX_ARGS", "")
    USE_SANDBOX_VM = os.environ.get("REVLAB_SANDBOX_VM", "0") == "1"
    VM_SNAPSHOT = os.environ.get("REVLAB_VM_SNAPSHOT", "")
    VM_GUEST_PATH = os.environ.get("REVLAB_VM_GUEST_PATH", "C:\\RevLab\\sample.exe")
    CAPTURE_DURATION = int(os.environ.get("REVLAB_CAPTURE_DURATION", "30"))

config = Config()


def resolve_sample_path(p) -> Path:
    """将样本存储路径解析为绝对路径(兼容旧相对路径数据)。"""
    path = Path(p)
    return path if path.is_absolute() else BASE_DIR / path
