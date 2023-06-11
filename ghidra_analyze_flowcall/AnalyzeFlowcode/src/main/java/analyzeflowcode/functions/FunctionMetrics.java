package analyzeflowcode.functions;

import java.util.TreeSet;

import analyzeflowcode.analyzer.*;
import analyzeflowcode.functions.utils.FunctionUtils;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Function;

/**
 * This class is a dataclass containing all metrics informations 
 * about a function.
 * 
 * Instance attributes:
 * 	- localFunction<Function> : The function for what metrics are done
 * 	- name<String> : The function name (including namespaces)
 * 
 */
public class FunctionMetrics {
	
	private Function localFunction;
	private String name;
	private TreeSet<FunctionAnalyzer> analyzers = new TreeSet<>();
	
	
	public FunctionMetrics(Function f) {
		this.localFunction = f;
		this.name          = FunctionUtils.getFuncNameWithNamespaces(f);
		this.addDefaultAnalyzers();
	}	
	
	/**
	 * Equality is defined by the just the same name
	 * 
	 * Return:
	 * 	- true if names are equals else false
	 */
	@Override
	public boolean equals(Object other) {
		if(other == null || other.getClass() != this.getClass()) {
			return false;
		}
		
		return ((FunctionMetrics)other).getName() == this.getName();
	}
	
	public void feed(Function function, boolean remote, FlatProgramAPI flatProgramApi) {
		for(FunctionAnalyzer analyzer: this.analyzers) {
			analyzer.analyze(function, remote, flatProgramApi);
		}
	}
	
	public void addAnalyzer(FunctionAnalyzer analyzer) {
		this.analyzers.add(analyzer);
	}
	
	public void delAnalyzer(FunctionAnalyzer analyzer) {
		this.analyzers.remove(analyzer);
	}
	
	public String getName() { return this.name; }
	public Function getFunction() { return this.localFunction; }
	public TreeSet<FunctionAnalyzer> getAnalyzers() { return this.analyzers; }
	
	public void addDefaultAnalyzers() {
		this.addAnalyzer(new CountInstructionsAnalyzer());
		this.addAnalyzer(new SyscallAnalyzer());
	}
}
