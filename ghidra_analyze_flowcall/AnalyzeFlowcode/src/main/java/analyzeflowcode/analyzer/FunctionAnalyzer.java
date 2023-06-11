package analyzeflowcode.analyzer;

import javax.swing.JPanel;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

/**
 * This interface offer the capability to be feeded by instructions 
 * and maj metrics about the received instruction if it concern
 * the analyzer.
 * 
 * Implements:
 * 	- Comparable<InstructionAnalyzer> : To allow them to be used in TreeSet or other sorted objects
 *  - Equality : To allow add methods to determine if this analyzer class is already seted
 */
public abstract class FunctionAnalyzer implements Comparable<FunctionAnalyzer> {
	
	/**
	 * This is the setted priority : lower is it, faster it will
	 * be run because of the sort of the global list of analyzers.
	 * 
	 * Return:
	 * 	- int : The priority
	 */
	public abstract int getPriority();
	
	/**
	 * This is the name of this analyzer.
	 * 
	 * Return:
	 * 	- String : The name
	 */
	public abstract String getName();

	/**
	 * This is the description of this analyzer.
	 * 
	 * Return:
	 * 	- String : The description
	 */
	public abstract String getDescription();
	
	/**
	 * This function return the component to show from this metric.
	 * 
	 * Return:
	 * 	- JComponent : The component
	 */
	public abstract JPanel getComponent();
	
	/**
	 * This function answer the query : is the function influencing
	 * this metric ?
	 * 
	 * Parameters:
	 * 	- function<Function> : The provided function
	 * 
	 * Return:
	 * 	- boolean : true if anlysable else false
	 */
	protected abstract boolean isAnalysable(Function function, boolean remote);
	
	/**
	 * This function update the metrics
	 * 
	 * Parameters:
	 * 	- function<Function> : The provided function
	 *  - remote<boolean>    : True if the function is in a child call
	 *  - flatProgramApi<FlatProgramAPI> : Api to help program manipulation
	 */
	protected abstract void update(Function function, FlatProgramAPI flatProgramApi);

	/**
	 * This function do the anlysis.
	 * 
	 * Parameters:
	 * 	- instruction<Instruction> : The provided instruction
	 *  - remote<boolean> : True if the function call is in a child function
	 *  - flatProgramApi<FlatProgramAPI> : Api to help program manipulation
	 */
	public void analyze(Function function, boolean remote, FlatProgramAPI flatProgramApi) {
		if(this.isAnalysable(function, remote)) {
			this.update(function, flatProgramApi);
		}
	}

	//
	// Implements Comparable<InstructionAnalyzer>
	//
	
	@Override
	public int compareTo(FunctionAnalyzer other) {
	    return Integer.compare(this.getPriority(), other.getPriority());
	}
	
	//
	// Implements equality
	//
	
	/**
	 * Equality is defined by the just the same class
	 * 
	 * Return:
	 * 	- true if class are equals else false
	 */
	@Override
	public boolean equals(Object other) {
		return (other != null) && (other.getClass() == this.getClass());
	}
}
