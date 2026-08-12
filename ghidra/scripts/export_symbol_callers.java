// Export callers of named symbols and one caller layer with decompilation.
// Usage: -postScript export_symbol_callers.java <output_path> <symbol>...
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Locale;

public class export_symbol_callers extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) throw new IllegalArgumentException("output path and symbols required");
        Listing listing = currentProgram.getListing();
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        Map<String, Map<Long, Function>> targets = new LinkedHashMap<>();

        for (int index = 1; index < args.length; index++) {
            String requested = args[index];
            Map<Long, Function> functions = new LinkedHashMap<>();
            SymbolIterator symbols = symbolTable.getAllSymbols(true);
            while (symbols.hasNext()) {
                Symbol symbol = symbols.next();
                if (!symbol.getName().toLowerCase(Locale.ROOT).contains(
                        requested.toLowerCase(Locale.ROOT))) continue;
                ReferenceIterator references = currentProgram.getReferenceManager()
                    .getReferencesTo(symbol.getAddress());
                while (references.hasNext()) {
                    Reference reference = references.next();
                    Function function = listing.getFunctionContaining(reference.getFromAddress());
                    if (function != null) {
                        functions.put(function.getEntryPoint().getOffset(), function);
                        continue;
                    }
                    // Import pointers are often reached through a thunk or IAT data symbol.
                    ReferenceIterator indirect = currentProgram.getReferenceManager()
                        .getReferencesTo(reference.getFromAddress());
                    while (indirect.hasNext()) {
                        Function indirectFunction = listing.getFunctionContaining(
                            indirect.next().getFromAddress());
                        if (indirectFunction != null) {
                            functions.put(indirectFunction.getEntryPoint().getOffset(), indirectFunction);
                        }
                    }
                }
            }
            targets.put(requested, functions);
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.setSimplificationStyle("decompile");
        decompiler.openProgram(currentProgram);
        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            out.printf("program=%s image_base=%s%n", currentProgram.getName(), currentProgram.getImageBase());
            for (Map.Entry<String, Map<Long, Function>> entry : targets.entrySet()) {
                out.printf("%n=== SYMBOL %s CALLERS=%d ===%n", entry.getKey(), entry.getValue().size());
                for (Function function : entry.getValue().values()) {
                    out.printf("FUNCTION %s RVA=0x%x NAME=%s SIGNATURE=%s%n",
                        function.getEntryPoint(), function.getEntryPoint().subtract(currentProgram.getImageBase()),
                        function.getName(), function.getSignature());
                    out.println("[parent_callers]");
                    ReferenceIterator parents = currentProgram.getReferenceManager()
                        .getReferencesTo(function.getEntryPoint());
                    while (parents.hasNext()) {
                        Reference reference = parents.next();
                        Function parent = listing.getFunctionContaining(reference.getFromAddress());
                        if (parent != null) {
                            out.printf("%s RVA=0x%x %s%n", parent.getEntryPoint(),
                                parent.getEntryPoint().subtract(currentProgram.getImageBase()), parent.getName());
                        }
                    }
                    DecompileResults result = decompiler.decompileFunction(function, 300, monitor);
                    if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
                        out.println(result.getDecompiledFunction().getC());
                    } else {
                        out.println("<decompile failed>");
                    }
                    out.println("----");
                }
            }
        } finally {
            decompiler.dispose();
        }
    }
}
