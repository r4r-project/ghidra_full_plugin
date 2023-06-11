package analyzeflowcode.graph.layouts;

import analyzeflowcode.graph.FunctionMetricsVisualEdge;
import analyzeflowcode.graph.FunctionMetricsVisualGraph;
import analyzeflowcode.graph.FunctionMetricsVisualVertex;
import ghidra.graph.viewer.layout.AbstractLayoutProvider;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class FunctionMetricsGraphLayoutProvider extends
		AbstractLayoutProvider<FunctionMetricsVisualVertex, FunctionMetricsVisualEdge, FunctionMetricsVisualGraph> {

	@Override
	public VisualGraphLayout<FunctionMetricsVisualVertex, FunctionMetricsVisualEdge> getLayout(
			FunctionMetricsVisualGraph graph, TaskMonitor monitor) throws CancelledException {
		FunctionMetricsGraphLayout layout = new FunctionMetricsGraphLayout(graph, this.getLayoutName());
		this.initVertexLocations(graph, layout);
		return layout;
	}

	@Override
	public String getLayoutName() {
		return "Function metrics layout";
	}

}
