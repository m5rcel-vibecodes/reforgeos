// Export genuine Ghidra decompiler results, including per-function failures.
// SPDX-License-Identifier: MIT OR Apache-2.0
//@category ReforgeOS
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.Application;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import com.google.gson.stream.JsonWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class ReforgeExport extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("output path and timeout required");
        int timeout = Integer.parseInt(args[1]);
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException(decompiler.getLastMessage());
            try (JsonWriter writer = new JsonWriter(Files.newBufferedWriter(Paths.get(args[0]), StandardCharsets.UTF_8))) {
                writer.beginObject();
                writer.name("backend").value("ghidra");
                writer.name("version").value(Application.getApplicationVersion());
                writer.name("language").value(currentProgram.getLanguageID().toString());
                writer.name("compiler").value(currentProgram.getCompilerSpec().getCompilerSpecID().toString());
                writer.name("functions").beginArray();
                FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
                while (functions.hasNext()) {
                    monitor.checkCancelled();
                    Function function = functions.next();
                    writer.beginObject();
                    writer.name("name").value(function.getName());
                    writer.name("address").value(function.getEntryPoint().toString());
                    DecompileResults result = decompiler.decompileFunction(function, timeout, monitor);
                    if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                        writer.name("signature").value(result.getDecompiledFunction().getSignature());
                        writer.name("code").value(result.getDecompiledFunction().getC());
                    }
                    String warning = result.getErrorMessage();
                    if (warning != null && !warning.isEmpty()) writer.name("warning").value(warning);
                    writer.endObject();
                }
                writer.endArray();
                writer.endObject();
            }
        } finally {
            decompiler.dispose();
        }
    }
}
