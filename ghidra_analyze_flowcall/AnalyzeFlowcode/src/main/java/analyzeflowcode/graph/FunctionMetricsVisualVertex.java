package analyzeflowcode.graph;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;

import aQute.bnd.service.Plugin;
import analyzeflowcode.analyzer.FunctionAnalyzer;
import analyzeflowcode.functions.FunctionMetrics;
import docking.GenericHeader;
import ghidra.app.services.GoToService;
import ghidra.graph.viewer.vertex.AbstractVisualVertex;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Function;

/**
 * This class contain the minimal implementation of a visual vertex
 * 
 * Instance attributes:
 * 	- functionMetrics<FunctionMetrics> : The object containing all functions metrics.
 */
public class FunctionMetricsVisualVertex extends AbstractVisualVertex {

	private FunctionMetrics functionMetrics;
	private JPanel panel;
	private GenericHeader head;
	private boolean compressed;
	
	public FunctionMetricsVisualVertex(Function f) {
		this.functionMetrics = new FunctionMetrics(f);
		this.compressed      = false;
	}

	public boolean getCompressed() { return this.compressed; }

	public void setCompressed(boolean is) { 
		this.compressed = is; 
		if(is) { this.head.setTitle("[...] " + this.getMetrics().getName()); }
		else   { this.head.setTitle(this.getMetrics().getName()); }
	}
	
	public void buildComponent() {
		int counter = 0;
		JPanel temp_panel = new JPanel(new FlowLayout());		
		this.panel = new JPanel();
		
		this.head = new GenericHeader();
		this.head.setTitle(this.getMetrics().getName());
		this.head.setNoWrapToolbar(true);
		
		this.panel.setLayout(new BorderLayout());
		this.panel.add(this.head, BorderLayout.NORTH);
		
		for(FunctionAnalyzer a: this.getMetrics().getAnalyzers()) {
			if(counter == 2) {
				this.panel.add(temp_panel);
				temp_panel = new JPanel(new FlowLayout());
			}
			counter = (counter+1)%2;
			temp_panel.add(a.getComponent());
		}

		if(counter != 2) { this.panel.add(temp_panel); }
	}
	
	/**
	 * Equality is defined by the just the same functionMetrics
	 * 
	 * Return:
	 * 	- true if functionMetrics are equals else false
	 */
	@Override
	public boolean equals(Object other) {
		if(other == null || other.getClass() != this.getClass()) {
			return false;
		}
		
		return ((FunctionMetricsVisualVertex)other).getMetrics() == this.getMetrics();
	}
	
	public void feed(Function function, boolean remote, FlatProgramAPI flatProgramApi) {
		this.functionMetrics.feed(function, remote, flatProgramApi);
	}
	
	public FunctionMetrics getMetrics() { return this.functionMetrics; }
	
	//
	// Extends AbstractVisualVertex
	//
	@Override
	public JComponent getComponent() {
		this.buildComponent();
		return this.panel;
	}

	@Override
	public void dispose() {
	}

}
