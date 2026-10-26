// Headless postScript: emit function name + entry as JSON.
// Static listing only; does not execute the program.
//@category RevengDebug

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

public class ExportFunctions extends GhidraScript {

    private static final int MAX_FUNCTIONS = 500;

    @Override
    public void run() throws Exception {
        File out = resolveOutput();
        File parent = out.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }

        StringBuilder sb = new StringBuilder();
        sb.append('[');
        boolean first = true;
        int count = 0;
        if (currentProgram != null) {
            FunctionIterator it =
                currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext() && count < MAX_FUNCTIONS && !monitor.isCancelled()) {
                Function fn = it.next();
                if (!first) {
                    sb.append(',');
                }
                first = false;
                count++;
                sb.append("{\"name\":\"").append(jsonEscape(fn.getName()));
                sb.append("\",\"entry\":\"");
                sb.append(jsonEscape(fn.getEntryPoint().toString()));
                sb.append("\"}");
            }
        }
        sb.append(']');

        OutputStreamWriter writer = new OutputStreamWriter(
            new FileOutputStream(out), StandardCharsets.UTF_8);
        try {
            writer.write(sb.toString());
        } finally {
            writer.close();
        }
        println("ExportFunctions wrote " + out.getAbsolutePath());
    }

    private File resolveOutput() {
        String[] args = getScriptArgs();
        if (args != null && args.length > 0 && args[0].length() > 0) {
            return new File(args[0]);
        }
        return new File("ghidra_functions.json");
    }

    private static String jsonEscape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '"') {
                out.append("\\\"");
            } else if (c == '\\') {
                out.append("\\\\");
            } else if (c == '\n') {
                out.append("\\n");
            } else if (c == '\r') {
                out.append("\\r");
            } else if (c == '\t') {
                out.append("\\t");
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }
}
