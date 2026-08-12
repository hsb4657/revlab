// Export all references to a data range, plus referencing functions and one parent layer.
// Usage: -postScript export_data_range_xrefs.java <output_path> <rva> <size_hex>
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public class export_data_range_xrefs extends GhidraScript {
    private long parseHex(String value) {
        String clean = value.trim().toLowerCase();
        if (clean.startsWith("0x")) clean = clean.substring(2);
        return Long.parseUnsignedLong(clean, 16);
    }

    private String describe(Function function) {
        if (function == null) return "<none>";
        return String.format("%s RVA=0x%x %s", function.getEntryPoint(),
            function.getEntryPoint().subtract(currentProgram.getImageBase()), function.getName());
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            throw new IllegalArgumentException("output path, RVA, and hexadecimal size required");
        }

        Listing listing = currentProgram.getListing();
        Address imageBase = currentProgram.getImageBase();
        Address start = imageBase.add(parseHex(args[1]));
        long size = parseHex(args[2]);
        if (size < 1 || size > 0x10000) throw new IllegalArgumentException("invalid range size");

        Map<String, Reference> references = new LinkedHashMap<>();
        Set<Function> directFunctions = new LinkedHashSet<>();
        Set<Function> parentFunctions = new LinkedHashSet<>();
        for (long offset = 0; offset < size; offset++) {
            monitor.checkCancelled();
            Address address = start.add(offset);
            ReferenceIterator iterator = currentProgram.getReferenceManager().getReferencesTo(address);
            while (iterator.hasNext()) {
                Reference reference = iterator.next();
                String key = reference.getFromAddress() + "->" + reference.getToAddress() + ":" +
                    reference.getReferenceType();
                references.putIfAbsent(key, reference);
                Function function = listing.getFunctionContaining(reference.getFromAddress());
                if (function != null) directFunctions.add(function);
            }
        }

        for (Function function : directFunctions) {
            ReferenceIterator callers = currentProgram.getReferenceManager()
                .getReferencesTo(function.getEntryPoint());
            while (callers.hasNext()) {
                Reference reference = callers.next();
                Function parent = listing.getFunctionContaining(reference.getFromAddress());
                if (parent != null && !directFunctions.contains(parent)) parentFunctions.add(parent);
            }
        }

        Set<Function> allFunctions = new LinkedHashSet<>(directFunctions);
        allFunctions.addAll(parentFunctions);
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.setSimplificationStyle("decompile");
        decompiler.openProgram(currentProgram);
        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            out.printf("program=%s image_base=%s range=%s-%s size=0x%x%n",
                currentProgram.getName(), imageBase, start, start.add(size - 1), size);
            out.printf("references=%d direct_functions=%d parent_functions=%d%n",
                references.size(), directFunctions.size(), parentFunctions.size());
            out.println("[references]");
            for (Reference reference : references.values()) {
                Function function = listing.getFunctionContaining(reference.getFromAddress());
                out.printf("from=%s from_rva=0x%x to=%s field_offset=0x%x type=%s function=%s%n",
                    reference.getFromAddress(), reference.getFromAddress().subtract(imageBase),
                    reference.getToAddress(), reference.getToAddress().subtract(start),
                    reference.getReferenceType(), describe(function));
            }

            out.println("\n[direct_functions]");
            for (Function function : directFunctions) out.println(describe(function));
            out.println("[parent_functions]");
            for (Function function : parentFunctions) out.println(describe(function));

            out.println("\n=== FUNCTION EVIDENCE ===");
            for (Function function : allFunctions) {
                monitor.checkCancelled();
                out.printf("%nFUNCTION %s relation=%s SIGNATURE=%s%n", describe(function),
                    directFunctions.contains(function) ? "DIRECT_XREF" : "PARENT",
                    function.getSignature());
                out.println("[callers]");
                ReferenceIterator callers = currentProgram.getReferenceManager()
                    .getReferencesTo(function.getEntryPoint());
                while (callers.hasNext()) {
                    Reference reference = callers.next();
                    Function caller = listing.getFunctionContaining(reference.getFromAddress());
                    out.printf("from=%s RVA=0x%x type=%s caller=%s%n", reference.getFromAddress(),
                        reference.getFromAddress().subtract(imageBase), reference.getReferenceType(),
                        describe(caller));
                }
                out.println("[instructions_referencing_range]");
                InstructionIterator instructions = listing.getInstructions(function.getBody(), true);
                while (instructions.hasNext()) {
                    Instruction instruction = instructions.next();
                    for (Reference reference : instruction.getReferencesFrom()) {
                        Address target = reference.getToAddress();
                        if (target.compareTo(start) >= 0 && target.compareTo(start.add(size - 1)) <= 0) {
                            out.printf("%s RVA=0x%x %s -> %s field_offset=0x%x type=%s%n",
                                instruction.getAddress(), instruction.getAddress().subtract(imageBase),
                                instruction, target, target.subtract(start), reference.getReferenceType());
                        }
                    }
                }
                out.println("[decompile]");
                DecompileResults result = decompiler.decompileFunction(function, 300, monitor);
                if (result != null && result.decompileCompleted() &&
                        result.getDecompiledFunction() != null) {
                    out.println(result.getDecompiledFunction().getC());
                } else {
                    out.println("<decompile failed>");
                    if (result != null) out.println(result.getErrorMessage());
                }
            }
        } finally {
            decompiler.dispose();
        }
    }
}
