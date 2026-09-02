import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[3]
DATA_DIR = BASE_DIR / "data"
SAMPLES_DIR = BASE_DIR / "samples"
OUTPUT_ROOT = Path(os.environ.get("REVLAB_OUTPUT_DIR", str(BASE_DIR)))
REPORTS_DIR = OUTPUT_ROOT / "reports"
CAPTURES_DIR = OUTPUT_ROOT / "captures"
UNPACKED_DIR = OUTPUT_ROOT / "unpacked"
SDK_DIR = OUTPUT_ROOT / "sdk"
GHIDRA_DIR = BASE_DIR / "ghidra"
TOOLS_DIR = BASE_DIR / "tools"
WORKSPACE_DIR = BASE_DIR / "workspace"

for _directory in (
    DATA_DIR,
    SAMPLES_DIR,
    REPORTS_DIR,
    CAPTURES_DIR,
    UNPACKED_DIR,
    GHIDRA_DIR,
    TOOLS_DIR,
    WORKSPACE_DIR,
    SDK_DIR,
):
    _directory.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "revlab.db"
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"
MAX_UPLOAD_SIZE = 200 * 1024 * 1024


def _csv_env(name: str, default: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in os.environ.get(name, default).split(",") if item.strip())


def _apply_output_root(root: Path):
    """Switch analysis output directories at runtime."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    Config.OUTPUT_ROOT = root
    Config.REPORTS_DIR = root / "reports"
    Config.CAPTURES_DIR = root / "captures"
    Config.UNPACKED_DIR = root / "unpacked"
    Config.SDK_DIR = root / "sdk"
    Config.WORKSPACE_DIR = root / "workspace"
    for directory in (
        Config.REPORTS_DIR,
        Config.CAPTURES_DIR,
        Config.UNPACKED_DIR,
        Config.SDK_DIR,
        Config.WORKSPACE_DIR,
    ):
        directory.mkdir(parents=True, exist_ok=True)


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

    # The service is deliberately local-first. Remote API access requires a
    # token and an explicit CORS allowlist instead of inheriting a permissive
    # browser policy from the development server.
    CORS_ORIGINS = _csv_env(
        "REVLAB_CORS_ORIGINS", "http://127.0.0.1:8000,http://localhost:8000"
    )
    API_TOKEN = os.environ.get("REVLAB_API_TOKEN", "")
    ENABLE_UNSAFE_NODES = os.environ.get("REVLAB_ENABLE_UNSAFE_NODES", "0") == "1"
    ALLOW_HOST_EXECUTION = os.environ.get("REVLAB_ALLOW_HOST_EXECUTION", "0") == "1"

    ENABLE_GHIDRA = os.environ.get("REVLAB_ENABLE_GHIDRA", "1") == "1"
    # The repository installer uses this path by default; GHIDRA_HOME can
    # point to a system installation when a project-local runtime is undesired.
    GHIDRA_HOME = os.environ.get("GHIDRA_HOME", str(GHIDRA_DIR / "runtime"))
    UPX_PATH = os.environ.get("UPX_PATH", str(TOOLS_DIR / "upx" / "upx.exe"))
    PESIEVE_PATH = os.environ.get(
        "PESIEVE_PATH", str(TOOLS_DIR / "pe-sieve" / "pe-sieve64.exe")
    )
    IL2CPP_DUMPER_PATH = os.environ.get(
        "IL2CPP_DUMPER_PATH",
        str(TOOLS_DIR / "unity-recovery" / "Il2CppDumper" / "Il2CppDumper"
            / "bin" / "Release" / "net8.0" / "Il2CppDumper.exe"),
    )
    VMWARE_RUN = os.environ.get(
        "VMWARE_RUN",
        r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe",
    )
    SANDBOX_TIMEOUT = int(os.environ.get("REVLAB_SANDBOX_TIMEOUT", "90"))
    SANDBOX_RUN_ARGS = os.environ.get("REVLAB_SANDBOX_ARGS", "")
    USE_SANDBOX_VM = os.environ.get("REVLAB_SANDBOX_VM", "0") == "1"
    VM_SNAPSHOT = os.environ.get("REVLAB_VM_SNAPSHOT", "")
    VM_GUEST_PATH = os.environ.get("REVLAB_VM_GUEST_PATH", "C:\\RevLab\\sample.exe")
    CAPTURE_DURATION = int(os.environ.get("REVLAB_CAPTURE_DURATION", "30"))


config = Config()


def resolve_sample_path(path_value) -> Path:
    """Resolve a sample path while preserving absolute paths."""
    path = Path(path_value)
    return path if path.is_absolute() else BASE_DIR / path
