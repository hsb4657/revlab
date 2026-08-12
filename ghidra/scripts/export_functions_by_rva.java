// Export decompilation, instructions, callers, and direct callees for selected RVAs.
// Usage: -postScript export_functions_by_rva.java <output_path> <rva>...
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
import java.util.Map;

public class export_functions_by_rva extends GhidraScript {
    private long parseRva(String value) {
        String clean = value.trim().toLowerCase();
        if (clean.startsWith("0x")) clean = clean.substring(2);
        return Long.parseUnsignedLong(clean, 16);
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("output path and at least one RVA required");
        }

        Listing listing = currentProgram.getListing();
        Map<Address, Function> functions = new LinkedHashMap<>();
        for (int index = 1; index < args.length; index++) {
            Address address = currentProgram.getImageBase().add(parseRva(args[index]));
            Function function = listing.getFunctionContaining(address);
            if (function == null) {
                function = createFunction(address, null);
            }
            if (function != null) functions.put(function.getEntryPoint(), function);
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.setSimplificationStyle("decompile");
        decompiler.openProgram(currentProgram);
        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            out.printf("program=%s image_base=%s language=%s%n", currentProgram.getName(),
                currentProgram.getImageBase(), currentProgram.getLanguageID());
            for (int index = 1; index < args.length; index++) {
                long rva = parseRva(args[index]);
                Address requested = currentProgram.getImageBase().add(rva);
                Function function = listing.getFunctionContaining(requested);
                out.printf("%n=== REQUEST RVA=0x%x ADDRESS=%s ===%n", rva, requested);
                if (function == null) {
                    out.println("FUNCTION=<none>");
                    continue;
                }
                out.printf("FUNCTION %s RVA=0x%x NAME=%s SIGNATURE=%s%n",
                    function.getEntryPoint(), function.getEntryPoint().subtract(currentProgram.getImageBase()),
                    function.getName(), function.getSignature());

                out.println("[callers]");
                ReferenceIterator callers = currentProgram.getReferenceManager()
                    .getReferencesTo(function.getEntryPoint());
                while (callers.hasNext()) {
                    Reference reference = callers.next();
                    Function caller = listing.getFunctionContaining(reference.getFromAddress());
                    boolean memoryReference = reference.getFromAddress().getAddressSpace().equals(
                        currentProgram.getImageBase().getAddressSpace());
                    String referenceRva = memoryReference
                        ? "0x" + Long.toHexString(reference.getFromAddress().subtract(currentProgram.getImageBase()))
                        : "<external>";
                    out.printf("%s RVA=%s type=%s caller=%s caller_rva=%s%n",
                        reference.getFromAddress(), referenceRva,
                        reference.getReferenceType(), caller == null ? "<none>" : caller.getName(),
                        caller == null ? "<none>" : "0x" + Long.toHexString(
                            caller.getEntryPoint().subtract(currentProgram.getImageBase())));
                }

                out.println("[instructions]");
                InstructionIterator instructions = listing.getInstructions(function.getBody(), true);
                int instructionCount = 0;
                while (instructions.hasNext() && instructionCount++ < 2500) {
                    Instruction instruction = instructions.next();
                    out.printf("%s RVA=0x%x %s%n", instruction.getAddress(),
                        instruction.getAddress().subtract(currentProgram.getImageBase()), instruction);
                    for (Reference reference : instruction.getReferencesFrom()) {
                        if (!reference.getReferenceType().isCall()) continue;
                        Function callee = listing.getFunctionContaining(reference.getToAddress());
                        out.printf("  CALL -> %s RVA=0x%x %s%n", reference.getToAddress(),
                            reference.getToAddress().subtract(currentProgram.getImageBase()),
                            callee == null ? "<none>" : callee.getName());
                    }
                }

                out.println("[decompile]");
                DecompileResults result = decompiler.decompileFunction(function, 300, monitor);
                if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
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
