// Ghidra 12 headless post-script: export decompiled C text as JSON.
// Usage: analyzeHeadless ... -postScript export_decompile.java <out_json>
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;

public class export_decompile extends GhidraScript {
    private static final int MAX_FUNCTIONS = 500;

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length < 1) {
            throw new IllegalArgumentException("export_decompile.java requires an output JSON path");
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.setSimplificationStyle("decompile");
        decompiler.openProgram(currentProgram);

        int exported = 0;
        boolean first = true;
        try (Writer output = new OutputStreamWriter(
                new FileOutputStream(arguments[0]), StandardCharsets.UTF_8)) {
            output.write("{");
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && exported < MAX_FUNCTIONS) {
                Function function = functions.next();
                try {
                    DecompileResults result = decompiler.decompileFunction(function, 120, monitor);
                    if (result == null || !result.decompileCompleted() ||
                            result.getDecompiledFunction() == null) {
                        continue;
                    }
                    String cText = result.getDecompiledFunction().getC();
                    if (cText == null || cText.isEmpty()) {
                        continue;
                    }
                    if (!first) {
                        output.write(",");
                    }
                    first = false;
                    output.write("\n  \"");
                    output.write(jsonEscape("0x" + Long.toHexString(function.getEntryPoint().getOffset())));
                    output.write("\": {\"name\": \"");
                    output.write(jsonEscape(function.getName()));
                    output.write("\", \"signature\": \"");
                    output.write(jsonEscape(function.getSignature().toString()));
                    output.write("\", \"c\": \"");
                    output.write(jsonEscape(cText));
                    output.write("\"}");
                    exported++;
                } catch (Exception error) {
                    printerr("Could not decompile " + function.getName() + ": " + error.getMessage());
                }
            }
            if (!first) {
                output.write("\n");
            }
            output.write("}\n");
        } finally {
            decompiler.dispose();
        }
        println("REVLab exported " + exported + " functions to " + arguments[0]);
    }

    private static String jsonEscape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder escaped = new StringBuilder(value.length() + 32);
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '\\': escaped.append("\\\\"); break;
                case '\"': escaped.append("\\\""); break;
                case '\b': escaped.append("\\b"); break;
                case '\f': escaped.append("\\f"); break;
                case '\n': escaped.append("\\n"); break;
                case '\r': escaped.append("\\r"); break;
                case '\t': escaped.append("\\t"); break;
                default:
                    if (character < 0x20) {
                        escaped.append(String.format("\\u%04x", (int) character));
                    } else {
                        escaped.append(character);
                    }
            }
        }
        return escaped.toString();
    }
}
