package analyzeflowcode.functions.utils;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public class FunctionUtils {
	public static String getFuncNameWithNamespaces(Function f) {
		return f.getName(true);
	}

	public static long getMain(Program program) {
		long addr = -1;
		
		for(Function f: program.getFunctionManager().getFunctions(true)) {
			if(f.getName().equals("main")) {
				addr = f.getEntryPoint().getOffset();
				break;
			}
		}
		
		return addr;
	}
}
