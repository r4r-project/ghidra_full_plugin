package analyzeflowcode.graph;

import ghidra.graph.graphs.DefaultVisualGraph;
import ghidra.graph.graphs.FilteringVisualGraph;
import ghidra.graph.viewer.layout.VisualGraphLayout;

public class FunctionMetricsVisualGraph extends FilteringVisualGraph<FunctionMetricsVisualVertex, FunctionMetricsVisualEdge> {

	private VisualGraphLayout<FunctionMetricsVisualVertex, FunctionMetricsVisualEdge> layout;
	
	@Override
	public VisualGraphLayout<FunctionMetricsVisualVertex, FunctionMetricsVisualEdge> getLayout() {
		return this.layout;
	}
	
	public void setLayout(VisualGraphLayout<FunctionMetricsVisualVertex, FunctionMetricsVisualEdge> layout) {
		this.layout = layout;
	}

	@Override
	public DefaultVisualGraph<FunctionMetricsVisualVertex, FunctionMetricsVisualEdge> copy() {
		FunctionMetricsVisualGraph newGraph = new FunctionMetricsVisualGraph();
		for (FunctionMetricsVisualVertex v : vertices.keySet()) {
			newGraph.addVertex(v);
		}

		for (FunctionMetricsVisualEdge e : edges.keySet()) {
			newGraph.addEdge(e);
		}

		return newGraph;
	}

}
