"""全局设置服务:分析输出目录等。存于 data/settings.json。"""
import json
from pathlib import Path

from ..core.config import DATA_DIR, _apply_output_root, Config

SETTINGS_FILE = DATA_DIR / "settings.json"

_DEFAULTS = {
    "output_dir": str(Config.OUTPUT_ROOT),   # 分析产物输出根目录
}


def load_settings() -> dict:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if SETTINGS_FILE.exists():
        try:
            return {**_DEFAULTS, **json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))}
        except Exception:
            pass
    return dict(_DEFAULTS)


def save_settings(cfg: dict) -> dict:
    cur = load_settings()
    cur.update({k: v for k, v in cfg.items() if k in _DEFAULTS})
    SETTINGS_FILE.write_text(json.dumps(cur, ensure_ascii=False, indent=2), encoding="utf-8")
    apply_settings(cur)
    return {"ok": True, "settings": cur}


def apply_settings(settings: dict = None):
    """将设置应用到运行时 config。"""
    s = settings or load_settings()
    out = s.get("output_dir")
    if out and out != str(Config.OUTPUT_ROOT):
        try:
            _apply_output_root(Path(out))
        except Exception:
            pass
    else:
        _apply_output_root(Config.OUTPUT_ROOT)
    return Config.OUTPUT_ROOT
