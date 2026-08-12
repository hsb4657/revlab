// Export shortest direct call/tail-jump paths from one RVA to one or more target RVAs.
// Usage: -postScript export_shortest_call_paths.java <output_path> <start_rva> <target_rva>...
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class export_shortest_call_paths extends GhidraScript {
    private static class Edge {
        final Function from;
        final Function to;
        final Address site;
        final String kind;

        Edge(Function from, Function to, Address site, String kind) {
            this.from = from;
            this.to = to;
            this.site = site;
            this.kind = kind;
        }
    }

    private long parseRva(String value) {
        String clean = value.trim().toLowerCase();
        if (clean.startsWith("0x")) clean = clean.substring(2);
        return Long.parseUnsignedLong(clean, 16);
    }

    private String describe(Function function) {
        if (function == null) return "<none>";
        long rva = function.getEntryPoint().subtract(currentProgram.getImageBase());
        return String.format("%s RVA=0x%x %s", function.getEntryPoint(), rva, function.getName());
    }

    private List<Edge> outgoing(Function function, Listing listing) {
        Map<String, Edge> unique = new LinkedHashMap<>();
        InstructionIterator instructions = listing.getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            for (Reference reference : instruction.getReferencesFrom()) {
                boolean call = reference.getReferenceType().isCall();
                boolean jump = reference.getReferenceType().isJump();
                if (!call && !jump) continue;
                Function target = listing.getFunctionAt(reference.getToAddress());
                if (target == null) target = listing.getFunctionContaining(reference.getToAddress());
                if (target == null || target.equals(function)) continue;

                // Conditional branches generally describe local CFG edges, not calls. Keep only
                // jumps whose destination is a distinct function entry (tail calls/thunks).
                if (jump && !target.getEntryPoint().equals(reference.getToAddress())) continue;
                String key = target.getEntryPoint() + "@" + instruction.getAddress();
                unique.putIfAbsent(key, new Edge(function, target, instruction.getAddress(),
                    call ? "CALL" : "TAIL_JUMP"));
            }
        }
        return new ArrayList<>(unique.values());
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) {
            throw new IllegalArgumentException("output path, start RVA, and target RVA(s) required");
        }

        Listing listing = currentProgram.getListing();
        FunctionManager functionManager = currentProgram.getFunctionManager();
        Address imageBase = currentProgram.getImageBase();
        Address startAddress = imageBase.add(parseRva(args[1]));
        Function start = listing.getFunctionContaining(startAddress);
        if (start == null) start = listing.getFunctionAt(startAddress);
        if (start == null) throw new IllegalArgumentException("no function at start RVA " + args[1]);

        Map<Function, String> requestedTargets = new LinkedHashMap<>();
        for (int index = 2; index < args.length; index++) {
            Address address = imageBase.add(parseRva(args[index]));
            Function target = listing.getFunctionContaining(address);
            if (target == null) target = listing.getFunctionAt(address);
            if (target != null) requestedTargets.put(target, args[index]);
        }

        Deque<Function> queue = new ArrayDeque<>();
        Set<Function> visited = new LinkedHashSet<>();
        Map<Function, Edge> predecessor = new LinkedHashMap<>();
        Map<Function, Integer> depth = new LinkedHashMap<>();
        Map<Function, List<Edge>> edgeCache = new LinkedHashMap<>();
        queue.add(start);
        visited.add(start);
        depth.put(start, 0);

        while (!queue.isEmpty()) {
            monitor.checkCancelled();
            Function current = queue.removeFirst();
            List<Edge> edges = outgoing(current, listing);
            edgeCache.put(current, edges);
            for (Edge edge : edges) {
                if (visited.add(edge.to)) {
                    predecessor.put(edge.to, edge);
                    depth.put(edge.to, depth.get(current) + 1);
                    queue.addLast(edge.to);
                }
            }
        }

        Set<Function> pathFunctions = new LinkedHashSet<>();
        Map<Function, List<Edge>> paths = new LinkedHashMap<>();
        for (Function target : requestedTargets.keySet()) {
            if (!visited.contains(target)) continue;
            List<Edge> reversed = new ArrayList<>();
            Function cursor = target;
            pathFunctions.add(cursor);
            while (!cursor.equals(start)) {
                Edge edge = predecessor.get(cursor);
                if (edge == null) break;
                reversed.add(edge);
                pathFunctions.add(edge.from);
                cursor = edge.from;
            }
            Collections.reverse(reversed);
            paths.put(target, reversed);
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.setSimplificationStyle("decompile");
        decompiler.openProgram(currentProgram);
        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            out.printf("program=%s image_base=%s language=%s functions=%d%n",
                currentProgram.getName(), imageBase, currentProgram.getLanguageID(),
                functionManager.getFunctionCount());
            out.printf("start=%s visited=%d%n", describe(start), visited.size());

            for (Map.Entry<Function, String> entry : requestedTargets.entrySet()) {
                Function target = entry.getKey();
                out.printf("%n=== TARGET requested_rva=%s resolved=%s reachable=%s ===%n",
                    entry.getValue(), describe(target), visited.contains(target));
                List<Edge> path = paths.get(target);
                if (path == null) {
                    out.println("PATH=<none in direct call/tail-jump graph>");
                    continue;
                }
                out.printf("DEPTH=%d%n", path.size());
                out.printf("[0] %s%n", describe(start));
                int step = 1;
                for (Edge edge : path) {
                    out.printf("[%d] site=%s site_rva=0x%x kind=%s -> %s%n", step++,
                        edge.site, edge.site.subtract(imageBase), edge.kind, describe(edge.to));
                }
            }

            out.println("\n=== PATH FUNCTION DECOMPILATIONS ===");
            for (Function function : pathFunctions) {
                monitor.checkCancelled();
                out.printf("%nFUNCTION %s SIGNATURE=%s%n", describe(function), function.getSignature());
                out.println("[direct_edges]");
                List<Edge> edges = edgeCache.containsKey(function)
                    ? edgeCache.get(function) : outgoing(function, listing);
                for (Edge edge : edges) {
                    out.printf("site=%s RVA=0x%x kind=%s -> %s%n", edge.site,
                        edge.site.subtract(imageBase), edge.kind, describe(edge.to));
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
