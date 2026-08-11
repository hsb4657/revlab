# Ghidra headless post-script:导出所有函数的反编译 C 代码为 JSON
# usage: analyzeHeadless ... -postScript export_decompile.py <out_json>
import json

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def run(out_json):
    program = currentProgram  # noqa: F821
    ifc = DecompInterface()
    ifc.toggleCCode(True)
    ifc.setSimplificationStyle("decompile")
    ifc.openProgram(program)
    monitor = ConsoleTaskMonitor()
    fm = program.getFunctionManager()
    result = {}
    count = 0
    max_funcs = 500
    for func in fm.getFunctions(True):
        if count >= max_funcs:
            break
        try:
            res = ifc.decompileFunction(func, 120, monitor)
            if res and res.decompileCompleted():
                c = res.getDecompiledFunction().getC()
                if c:
                    result[hex(func.getEntryPoint().getOffset())] = {
                        "name": func.getName() or "",
                        "signature": str(func.getSignature()) or "",
                        "c": c,
                    }
                    count += 1
        except Exception:
            continue
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1)
    return 0
