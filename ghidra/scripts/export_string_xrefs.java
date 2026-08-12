// Ghidra headless post-script: find byte-string anchors and decompile referencing functions.
// Usage: -postScript export_string_xrefs.java <output_path> <needle>...
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Set;

public class export_string_xrefs extends GhidraScript {
    private Set<Function> functions = new LinkedHashSet<>();

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) throw new IllegalArgumentException("output path and needles required");
        Memory memory = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            out.printf("program=%s image_base=%s%n", currentProgram.getName(), currentProgram.getImageBase());
            for (int index = 1; index < args.length; index++) {
                String needle = args[index];
                find(out, needle, needle.getBytes(StandardCharsets.US_ASCII), "ascii", memory, listing);
                find(out, needle, needle.getBytes(StandardCharsets.UTF_16LE), "utf16le", memory, listing);
            }
            out.println("[decompiled_callers]");
            DecompInterface decompiler = new DecompInterface();
            decompiler.toggleCCode(true);
            decompiler.openProgram(currentProgram);
            try {
                for (Function function : functions) {
                    out.printf("FUNCTION %s RVA=%s %s %s%n", function.getEntryPoint(),
                        function.getEntryPoint().subtract(currentProgram.getImageBase()),
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

    private void find(PrintWriter out, String needle, byte[] bytes, String encoding,
                      Memory memory, Listing listing) throws Exception {
        out.printf("[needle] %s encoding=%s%n", needle, encoding);
        boolean found = false;
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized()) continue;
            Address cursor = block.getStart();
            while (cursor != null && cursor.compareTo(block.getEnd()) <= 0) {
                Address hit = memory.findBytes(cursor, block.getEnd(), bytes, null, true, monitor);
                if (hit == null) break;
                found = true;
                out.printf("hit=%s RVA=%s block=%s%n", hit,
                    hit.subtract(currentProgram.getImageBase()), block.getName());
                ReferenceIterator references = currentProgram.getReferenceManager().getReferencesTo(hit);
                int count = 0;
                while (references.hasNext()) {
                    Reference reference = references.next();
                    count++;
                    Function caller = listing.getFunctionContaining(reference.getFromAddress());
                    out.printf("  xref=%s type=%s caller=%s%n", reference.getFromAddress(),
                        reference.getReferenceType(), caller == null ? "<none>" : caller.getName());
                    if (caller != null) functions.add(caller);
                }
                if (count == 0) out.println("  xref=<none>");
                if (hit.equals(block.getEnd())) break;
                cursor = hit.add(1);
            }
        }
        if (!found) out.println("hit=<none>");
    }
}
