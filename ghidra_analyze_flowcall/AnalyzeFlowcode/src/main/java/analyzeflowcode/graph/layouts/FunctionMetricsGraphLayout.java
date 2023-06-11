package analyzeflowcode.graph.layouts;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import analyzeflowcode.graph.FunctionMetricsVisualEdge;
import analyzeflowcode.graph.FunctionMetricsVisualGraph;
import analyzeflowcode.graph.FunctionMetricsVisualVertex;
import edu.uci.ics.jung.graph.Graph;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.layout.AbstractVisualGraphLayout;
import ghidra.graph.viewer.layout.GridLocationMap;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.util.exception.CancelledException;

public class FunctionMetricsGraphLayout extends AbstractVisualGraphLayout<FunctionMetricsVisualVertex, FunctionMetricsVisualEdge> {

	protected FunctionMetricsGraphLayout(
		FunctionMetricsVisualGraph graph,
		String layoutName) {
		super(graph, layoutName);
	}

	@Override
	public FunctionMetricsVisualGraph getVisualGraph() {
		return (FunctionMetricsVisualGraph)this.getGraph();
	}

	@Override
	public AbstractVisualGraphLayout<FunctionMetricsVisualVertex, FunctionMetricsVisualEdge> createClonedLayout(
			VisualGraph<FunctionMetricsVisualVertex, FunctionMetricsVisualEdge> newGraph) {
		if (!(newGraph instanceof FunctionMetricsVisualGraph)) {
			throw new IllegalArgumentException("Must pass a " + FunctionMetricsVisualGraph.class.getSimpleName() +
				"to clone the " + getClass().getSimpleName());
		}

		FunctionMetricsGraphLayout newLayout =
			new FunctionMetricsGraphLayout((FunctionMetricsVisualGraph)newGraph, getLayoutName());
		return newLayout;
	}

	@Override
	protected GridLocationMap<FunctionMetricsVisualVertex, FunctionMetricsVisualEdge> performInitialGridLayout(
			VisualGraph<FunctionMetricsVisualVertex, FunctionMetricsVisualEdge> g) throws CancelledException {
		
		GridLocationMap<FunctionMetricsVisualVertex, FunctionMetricsVisualEdge> results = new GridLocationMap<>();
		List<List<FunctionMetricsVisualVertex>> rows = this.getRows(g);
		List<FunctionMetricsVisualVertex> columns;
		int maxColumns = this.getMax(rows);
		int centering;
		
		for(int i = 0; i<rows.size(); i++) {
			columns = rows.get(i);
			centering = (maxColumns-columns.size())/2;
			for(int j = 0; j<columns.size(); j++) {
				results.set(columns.get(j), i, j+centering);
			}
		}
		
		return results;
	}

	private int getMax(List<List<FunctionMetricsVisualVertex>> rows) {
		int w = 0;
		
		for(List<FunctionMetricsVisualVertex> r: rows) {
			w = Math.max(w, r.size());
		}
		
		return w;
	}

	private List<List<FunctionMetricsVisualVertex>> getRows(
			VisualGraph<FunctionMetricsVisualVertex, FunctionMetricsVisualEdge> g) {
		List<List<FunctionMetricsVisualVertex>> result = new ArrayList<>();
		FunctionMetricsVisualVertex root = this.getRoot(g);
		List<FunctionMetricsVisualVertex> toTraverse;
		HashSet<FunctionMetricsVisualVertex> marqued = new HashSet<>();
		
		result.add(List.of(root));
		
		do {
			toTraverse = new ArrayList<>();
			for(FunctionMetricsVisualVertex traversed: result.get(result.size()-1)) {
				if(marqued.contains(traversed)) { continue; }
				marqued.add(traversed);
				for(FunctionMetricsVisualVertex s: g.getSuccessors(traversed)) {
					toTraverse.add(s);
				}
			}
			result.add(toTraverse);
		} while(result.get(result.size()-1).size() != 0);
		
		return result;
	}

	private FunctionMetricsVisualVertex getRoot(VisualGraph<FunctionMetricsVisualVertex, FunctionMetricsVisualEdge> g) {
		for(FunctionMetricsVisualVertex f: g.getVertices()) {
			if(g.getPredecessors(f).size() == 0) {
				return f;
			}
		}
		return null;
	}

}
