// Ghidra headless post-script for targeted packed-PE evidence export.
// Usage: -postScript export_targeted_analysis.java <output_path>
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Set;

public class export_targeted_analysis extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("output path required");
        }

        Listing listing = currentProgram.getListing();
        SymbolTable symbols = currentProgram.getSymbolTable();
        Set<Function> targets = new LinkedHashSet<>();
        Address entry = currentProgram.getSymbolTable().getExternalEntryPointIterator().hasNext()
            ? currentProgram.getSymbolTable().getExternalEntryPointIterator().next()
            : currentProgram.getImageBase().add(currentProgram.getExecutablePath().length());

        Function entryFunction = listing.getFunctionContaining(entry);
        if (entryFunction != null) targets.add(entryFunction);

        SymbolIterator symbolIterator = symbols.getAllSymbols(true);
        while (symbolIterator.hasNext()) {
            Symbol symbol = symbolIterator.next();
            String name = symbol.getName();
            if (name.equalsIgnoreCase("OnlineFix") ||
                name.equalsIgnoreCase("entry") ||
                name.toLowerCase().contains("getmodulefilename") ||
                name.toLowerCase().contains("messagebox")) {
                Function function = listing.getFunctionContaining(symbol.getAddress());
                if (function != null) targets.add(function);
                ReferenceIterator references = currentProgram.getReferenceManager()
                    .getReferencesTo(symbol.getAddress());
                while (references.hasNext()) {
                    Reference reference = references.next();
                    Function caller = listing.getFunctionContaining(reference.getFromAddress());
                    if (caller != null) targets.add(caller);
                }
            }
        }

        // Include functions containing the first bytes of every executable block and
        // direct call targets reached from the initial target set.
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!block.isExecute()) continue;
            Function function = listing.getFunctionContaining(block.getStart());
            if (function != null) targets.add(function);
        }
        Set<Function> expanded = new LinkedHashSet<>(targets);
        for (Function function : targets) {
            Instruction instruction = listing.getInstructionAt(function.getEntryPoint());
            int count = 0;
            while (instruction != null && function.getBody().contains(instruction.getAddress()) && count++ < 1000) {
                for (Reference reference : instruction.getReferencesFrom()) {
                    if (reference.getReferenceType().isCall()) {
                        Function callee = listing.getFunctionContaining(reference.getToAddress());
                        if (callee != null) expanded.add(callee);
                    }
                }
                instruction = instruction.getNext();
            }
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.openProgram(currentProgram);
        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            out.println("program=" + currentProgram.getName());
            out.println("image_base=" + currentProgram.getImageBase());
            out.println("entry=" + entry);
            out.println("language=" + currentProgram.getLanguageID());
            out.println();
            out.println("[memory_blocks]");
            for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
                out.printf("%s %s-%s r=%s w=%s x=%s initialized=%s%n",
                    block.getName(), block.getStart(), block.getEnd(), block.isRead(),
                    block.isWrite(), block.isExecute(), block.isInitialized());
            }
            out.println();
            out.println("[functions]");
            for (Function function : expanded) {
                out.printf("FUNCTION %s %s %s%n", function.getEntryPoint(),
                    function.getName(), function.getSignature());
                DecompileResults result = decompiler.decompileFunction(function, 180, monitor);
                if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    out.println(result.getDecompiledFunction().getC());
                } else {
                    out.println("<decompile failed>");
                }
                out.println("----");
            }
        } finally {
            decompiler.dispose();
        }
    }
}
