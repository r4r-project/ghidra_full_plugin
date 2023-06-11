package analyzeflowcode.analyzer;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

/**
 * This analyzer is the simplest one : it just count instructions.
 *
 * Instance attributes:
 * 	- done<boolean>  : If true, analysis was done
 * 	- count<long>    : The number of counted instructions
 * 	- panel<JPanel>  : The rendered panel
 * 	- jcount<JLabel> : The count attribute wrapped in a jpanel
 * 
 */
public class CountInstructionsAnalyzer extends FunctionAnalyzer {
	
	private boolean done   = false;
	public long    count  = 0;
	private JPanel  panel  = new JPanel(new FlowLayout());
	private JLabel  jcount = new JLabel();
			
	public CountInstructionsAnalyzer() {
		this.panel.setVisible(true);
		this.jcount.setVisible(true);
		this.panel.add(new JLabel(this.getName() + ":"));
		this.panel.add(this.jcount);
		this.panel.setBorder(BorderFactory.createLineBorder(Color.BLACK));
		this.jcount.setAlignmentX(Component.CENTER_ALIGNMENT);
		this.jcount.setAlignmentY(Component.CENTER_ALIGNMENT);
	}

	//
	// Extends InstructionAnalyzer
	//
	
	@Override
	public int getPriority() {
		return 1024;
	}
	
	@Override
	public String getName() {
		return "Instruction counted";
	}

	@Override
	public String getDescription() {
		return "Provide instruction counted in the function";
	}
	
	@Override
	public JPanel getComponent() {
		this.jcount.setText(Long.toString(this.count));
		return this.panel;
	}

	@Override
	protected boolean isAnalysable(Function function, boolean remote) {
		return !(remote || this.done);
	}

	@Override
	protected void update(Function function, FlatProgramAPI flatProgramApi) {
		long        end      = function.getBody().getMaxAddress().getOffset();
		Instruction curInstr = flatProgramApi.getFirstInstruction(function);

		if(curInstr == null) { return; }
		
		do {
			this.count++;
			curInstr = curInstr.getNext();
		} while(curInstr.getAddress().getOffset() < end);
		
		this.done = true;
	}
}
