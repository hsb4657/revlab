// Export references and decompilation around an exact byte pattern.
// Usage: -postScript export_byte_pattern_xrefs.java <hex_pattern> <output_path>
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Set;

public class export_byte_pattern_xrefs extends GhidraScript {
    private byte[] decode(String hex) {
        String clean = hex.replaceAll("[^0-9A-Fa-f]", "");
        if ((clean.length() & 1) != 0) throw new IllegalArgumentException("odd hex pattern");
        byte[] output = new byte[clean.length() / 2];
        for (int index = 0; index < output.length; index++) {
            output[index] = (byte)Integer.parseInt(clean.substring(index * 2, index * 2 + 2), 16);
        }
        return output;
    }

    private void addFunction(Set<Function> targets, Address address) {
        Function function = currentProgram.getListing().getFunctionContaining(address);
        if (function != null) targets.add(function);
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("hex pattern and output path required");
        byte[] pattern = decode(args[0]);
        Memory memory = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        Set<Address> hits = new LinkedHashSet<>();
        Set<Function> targets = new LinkedHashSet<>();

        Address cursor = memory.getMinAddress();
        while (cursor != null) {
            Address hit = memory.findBytes(cursor, pattern, null, true, monitor);
            if (hit == null) break;
            hits.add(hit);
            ReferenceIterator references = currentProgram.getReferenceManager().getReferencesTo(hit);
            while (references.hasNext()) addFunction(targets, references.next().getFromAddress());
            cursor = hit.next();
        }

        // Include one direct caller/callee layer around every referencing function.
        Set<Function> expanded = new LinkedHashSet<>(targets);
        for (Function function : targets) {
            ReferenceIterator callers = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint());
            while (callers.hasNext()) addFunction(expanded, callers.next().getFromAddress());
            AddressSetView body = function.getBody();
            for (Instruction instruction : listing.getInstructions(body, true)) {
                for (Reference reference : instruction.getReferencesFrom()) {
                    if (reference.getReferenceType().isCall()) addFunction(expanded, reference.getToAddress());
                }
            }
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.openProgram(currentProgram);
        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(args[1]), StandardCharsets.UTF_8))) {
            out.println("program=" + currentProgram.getName());
            out.println("image_base=" + currentProgram.getImageBase());
            out.println("pattern=" + args[0]);
            out.println("hits=" + hits.size());
            for (Address hit : hits) {
                out.println("PATTERN " + hit + " RVA=" + hit.subtract(currentProgram.getImageBase()));
                ReferenceIterator references = currentProgram.getReferenceManager().getReferencesTo(hit);
                while (references.hasNext()) {
                    Reference reference = references.next();
                    Function caller = listing.getFunctionContaining(reference.getFromAddress());
                    out.println("  XREF " + reference.getFromAddress() + " type=" + reference.getReferenceType()
                        + " function=" + (caller == null ? "<none>" : caller.getName()));
                }
            }
            out.println("[functions]");
            for (Function function : expanded) {
                out.printf("FUNCTION %s %s %s%n", function.getEntryPoint(), function.getName(), function.getSignature());
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
