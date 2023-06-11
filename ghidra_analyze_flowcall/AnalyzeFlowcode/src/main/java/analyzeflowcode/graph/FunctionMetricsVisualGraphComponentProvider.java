package analyzeflowcode.graph;

import java.awt.BorderLayout;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import javax.swing.JComponent;
import javax.swing.JPanel;

import analyzeflowcode.AnalyzeFlowcodePlugin;
import analyzeflowcode.analyzer.CountInstructionsAnalyzer;
import analyzeflowcode.graph.layouts.FunctionMetricsGraphLayoutProvider;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.graph.viewer.VisualGraphView;
import ghidra.graph.viewer.event.mouse.VertexMouseInfo;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.graph.viewer.vertex.VertexClickListener;
import ghidra.graph.viewer.vertex.VertexFocusListener;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class FunctionMetricsVisualGraphComponentProvider extends ComponentProviderAdapter {

	private FunctionMetricsGraphLayoutProvider layoutProvider;
	private FunctionMetricsVisualGraph graph;
	private AnalyzeFlowcodePlugin plugin;
	private JComponent mainPanel;
	private VisualGraphView<FunctionMetricsVisualVertex, FunctionMetricsVisualEdge, FunctionMetricsVisualGraph> view;
	private JComponent component;
	
	public FunctionMetricsVisualGraphComponentProvider(PluginTool tool, AnalyzeFlowcodePlugin plugin) {
		super(tool, plugin.getName(), plugin.getName());
		this.plugin = plugin;
		this.layoutProvider = new FunctionMetricsGraphLayoutProvider();
		addToTool();
		buildComponent();
	}

	private void installGraph() {
		buildGraph();

		this.view.setLayoutProvider(layoutProvider);
		this.view.setGraph(graph);
	}

	public void dispose() {
		removeFromTool();
	}

	@Override
	public void componentShown() {
		installGraph();
	}

	private void buildComponent() {
		this.view = new VisualGraphView<>();
		this.view.setVertexFocusListener(new VertexFocusListener<FunctionMetricsVisualVertex>() {

			@Override
			public void vertexFocused(FunctionMetricsVisualVertex v) {
				plugin.exposedGoTo(v.getMetrics().getFunction().getEntryPoint());
			}
			
		});
		this.view.setVertexClickListener(new VertexClickListener<>() {

			@Override
			public boolean vertexDoubleClicked(FunctionMetricsVisualVertex v,
					VertexMouseInfo<FunctionMetricsVisualVertex, FunctionMetricsVisualEdge> mouseInfo) {
				v.setCompressed(!v.getCompressed());
				setCompressed(v, v.getCompressed());
				return true;
			}
			
		});
		this.component = this.view.getViewComponent();
		this.mainPanel = new JPanel(new BorderLayout());
		this.mainPanel.add(this.component, BorderLayout.CENTER);
	}

	private void setCompressed(FunctionMetricsVisualVertex v, boolean filter) {
		List<FunctionMetricsVisualVertex> toTraverse;
		HashSet<FunctionMetricsVisualVertex> marqued  = new HashSet<>();
		HashSet<FunctionMetricsVisualVertex> filtered = new HashSet<>(); 
		FunctionMetricsVisualVertex traversed;
		
		Iterator<FunctionMetricsVisualVertex> i = this.graph.getFilteredVertices();
		while(i.hasNext()) { filtered.add(i.next()); }
		
		this.graph.clearFilter();

		toTraverse = StreamSupport
              	.stream(this.graph.getSuccessors(v).spliterator(), false)
              	.collect(Collectors.toList());
		
		while(toTraverse.size() != 0) {
			traversed = toTraverse.remove(0);
			filtered.remove(traversed);
			if(marqued.contains(traversed)) { continue; }
			marqued.add(traversed);
			for(FunctionMetricsVisualVertex s: this.graph.getSuccessors(traversed)) {
				toTraverse.add(s);
			}
		}
		
		if(filter) { this.graph.filterVertices(marqued); }
		else       { this.graph.filterVertices(filtered); }
	}
	
	private void buildGraph() {
		graph = this.plugin.createGraph();

		try {
			VisualGraphLayout<FunctionMetricsVisualVertex, FunctionMetricsVisualEdge> layout =
				layoutProvider.getLayout(graph, TaskMonitor.DUMMY);
			graph.setLayout(layout);
		} catch (CancelledException e) { }
	}

	public FunctionMetricsVisualGraph getGraph() { return graph; }

	@Override
	public JComponent getComponent() { return mainPanel; }
}
