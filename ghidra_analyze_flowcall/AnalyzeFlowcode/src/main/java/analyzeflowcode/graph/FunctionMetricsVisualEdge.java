package analyzeflowcode.graph;

import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;
import ghidra.graph.viewer.edge.AbstractVisualEdge;

/**
 * This class contain the minimal implementation of an edge between nodes
 * 
 * Instance attributes:
 * 	- functionMetrics<FunctionMetrics> : The object containing all functions metrics.
 * 	- 
 */
public class FunctionMetricsVisualEdge extends AbstractVisualEdge<FunctionMetricsVisualVertex> {

	public FunctionMetricsVisualEdge(FunctionMetricsVisualVertex start, FunctionMetricsVisualVertex end) {
		super(start, end);
	}

	@SuppressWarnings("unchecked")
	@Override
	public FunctionMetricsVisualEdge cloneEdge(FunctionMetricsVisualVertex start, FunctionMetricsVisualVertex end) {
		return new FunctionMetricsVisualEdge(start, end);
	}
	
	@Override
	public boolean equals(Object other) {
		if(other == null || other.getClass() != this.getClass()) {
			return false;
		}
		
		return ((FunctionMetricsVisualEdge)other).getStart() == this.getStart()
					&&
				((FunctionMetricsVisualEdge)other).getEnd() == this.getEnd();
	}

}
