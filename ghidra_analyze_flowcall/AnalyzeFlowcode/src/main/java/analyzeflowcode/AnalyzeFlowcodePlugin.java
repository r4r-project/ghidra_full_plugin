/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package analyzeflowcode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import analyzeflowcode.analyzer.CountInstructionsAnalyzer;
import analyzeflowcode.analyzer.SyscallAnalyzer;
import analyzeflowcode.graph.FunctionMetricsVisualEdge;
import analyzeflowcode.graph.FunctionMetricsVisualGraph;
import analyzeflowcode.graph.FunctionMetricsVisualGraphComponentProvider;
import analyzeflowcode.graph.FunctionMetricsVisualVertex;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.NavigatableContextAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.GoToService;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = "analyzeflowcode",
	category = PluginCategoryNames.GRAPH,
	shortDescription = "Analyze flow code plugin",
	description = "Analyze flow code plugin"
)
//@formatter:on
public class AnalyzeFlowcodePlugin extends ProgramPlugin {

	private FunctionMetricsVisualGraphComponentProvider provider;
	private DockingAction action;
	private FunctionMetricsVisualGraph GRAPH = new FunctionMetricsVisualGraph();
	private FlatProgramAPI flatApi;

	public AnalyzeFlowcodePlugin(PluginTool tool) {
		super(tool, true, true);
	}

	private void createActions() {
		this.action = new NavigatableContextAction(this.getName(), this.getName()) {
			@Override
			public void actionPerformed(NavigatableActionContext context) {
				provider.setVisible(true);
			}
		};
		this.action.addToWindowWhen(NavigatableActionContext.class);
		this.action.setMenuBarData(new MenuData(new String[] {
				ToolConstants.MENU_GRAPH, "Flowcode graph"
		}));
		this.action.setDescription("Analyzed flowcode graph");
		this.action.setEnabled(true);
		
		this.getTool().addAction(this.action);		
	}

	@Override
	public void init() {
		super.init();
		this.provider = new FunctionMetricsVisualGraphComponentProvider(tool, this);

		this.createActions();
	}
	
	@Override
	protected void dispose() {
		this.provider.dispose();
	}
	
	//
	// Create graph
	//
	
	/**
	 * This function create the graph
	 * 	 
	 * Exceptions:
	 * 	- CancelledException : If an error occurs
	 */
	public FunctionMetricsVisualGraph createGraph() {
		if(this.currentProgram == null) { return this.GRAPH; }
		Function entrypoint = this.currentProgram.getFunctionManager()
				                                 .getFunctionContaining(
			                                		 this.currentLocation.getAddress()
		                                		 );
		HashMap<String, FunctionMetricsVisualVertex> vertices = new HashMap<>();
		List<FunctionMetricsVisualVertex> toTraverse = new ArrayList<>();
		FunctionMetricsVisualVertex current;
		FunctionMetricsVisualVertex calledVertex;
		this.flatApi = new FlatProgramAPI(this.currentProgram, this.getMonitor());
		GRAPH = new FunctionMetricsVisualGraph();

		toTraverse.add(new FunctionMetricsVisualVertex(entrypoint));
		vertices.put(toTraverse.get(0).getMetrics().getName(), toTraverse.get(0));
		
		this.getMonitor().setMessage("Begin graph creation");
		
		while(toTraverse.size() != 0) {
			current = this.getVertice(toTraverse.remove(0), vertices, toTraverse);
			this.getMonitor().setMessage("Treat " + current.getMetrics().getName());

			current.feed(
				current.getMetrics().getFunction(),
				false,
				this.flatApi
			);

			for(Function called: current.getMetrics().getFunction().getCalledFunctions(this.getMonitor())) {
				calledVertex = this.getVertice(new FunctionMetricsVisualVertex(called), vertices, toTraverse);
				if(current == calledVertex) { continue; }
				GRAPH.addEdge(new FunctionMetricsVisualEdge(current, calledVertex));
			}	
		}
		
		this.getMonitor().setMessage("Begin retro-propagation");
		for(FunctionMetricsVisualVertex f: GRAPH.getVertices()) {
			this.getMonitor().setMessage("Treat " + f.getMetrics().getName());
			this.propagate(f);
		}
		
		return this.GRAPH;
	}

	private FunctionMetricsVisualVertex getVertice(FunctionMetricsVisualVertex get,
			HashMap<String, FunctionMetricsVisualVertex> vertices, List<FunctionMetricsVisualVertex> toTraverse) {
		if(vertices.containsKey(get.getMetrics().getName())) {
			return vertices.get(get.getMetrics().getName());
		} 
		vertices.put(get.getMetrics().getName(), get);
		toTraverse.add(get);
		GRAPH.addVertex(get);
		return get;
	}

	/**
	 * This function feed all parents of current.
	 */
	private void propagate(FunctionMetricsVisualVertex first) {
		HashSet<FunctionMetricsVisualVertex> marqued = new HashSet<>();
		List<FunctionMetricsVisualVertex> toTraverse = new ArrayList<>();
		FunctionMetricsVisualVertex current;
		
		toTraverse.add(first);
		
		while(toTraverse.size() != 0) {
			current = toTraverse.remove(0);

			if(marqued.contains(current)) { continue; }
			marqued.add(current);
			
			for(FunctionMetricsVisualVertex f: GRAPH.getPredecessors(current)) {
				f.feed(
					first.getMetrics().getFunction(),
					true,
					this.flatApi
				);
				toTraverse.add(f);
			}
		}
	}

	public TaskMonitor getMonitor() {
		return TaskMonitor.DUMMY;
	}
	
	public boolean exposedGoTo(Address a) {
		return this.goTo(a);
	}
}
