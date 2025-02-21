package tracemadness.calltree;


import java.util.List;
import java.util.TreeMap;

import javax.swing.JComponent;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.ToggleDockingAction;
import docking.action.ToolBarData;
import ghidra.util.Swing;
import resources.Icons;
import tracemadness.MadnessPlugin;
import tracemadness.dataflowinfo.DataflowFunctionWithArgs;

public class CallTreeProvider extends ComponentProvider {

	final private MadnessPlugin plugin;
	final private CallTree calltree;

	private ToggleDockingAction navigationOutgoingAction;
	private ToggleDockingAction navigationIncomingAction;
	
	public CallTreeProvider(MadnessPlugin plugin) {
		super(plugin.getTool(), "Function Call Tree", plugin.getName());
		this.plugin = plugin;		
		this.calltree = buildComponent();
		addDockingActions();
	}
	
	private void addDockingActions() {

		// Toggling outgoing anchor updates
		navigationOutgoingAction = new ToggleDockingAction("Toggle Outgoing Navigation Events", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
			}
		};
		navigationOutgoingAction.setToolBarData(new ToolBarData(Icons.NAVIGATE_ON_OUTGOING_EVENT_ICON, null));
		navigationOutgoingAction.setEnabled(true);
		navigationOutgoingAction.setSelected(true);
		this.addLocalAction(navigationOutgoingAction);

		// Toggling incoming anchor updates
		navigationIncomingAction = new ToggleDockingAction("Toggle Incoming Navigation Events", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
			}
		};
		navigationIncomingAction.setToolBarData(new ToolBarData(Icons.NAVIGATE_ON_INCOMING_EVENT_ICON, null));
		navigationIncomingAction.setEnabled(true);
		navigationIncomingAction.setSelected(true);
		this.addLocalAction(navigationIncomingAction);
	}
	
	Long getStartingTickFromResult(JSONObject graph) throws JSONException {
		return graph.getJSONObject("selected").getLong("starttick");
	}
	
	FunctionRunNode getCallTreeForTick(long tick) throws Exception {
		
		String param = String.format("for startins in instructionruns filter startins.tick == %d\n"
				+ "for fnrun,fnrune in 1..1 outbound startins infunctionrun\n"
				+ "let callstack=(\n"
				+ "  for r,re in 0..10 inbound fnrun calls \n"
				+ "  for x in instructionruns filter x.tick == r.starttick\n"
				+ "  return x)\n"
				+ "let callees=(\n"
				+ "  for r,re in 1..5 outbound fnrun calls \n"
				+ "  for x in instructionruns filter x.tick == r.starttick\n"
				+ "  return x)\n"
				+ "let instructions=append(callstack,callees)\n"
				+ "\n", tick);
		List<JSONObject> objs = plugin.madness.runQuery("fntrace", new String[] {param, ""});
		TreeMap<Long, FunctionRunNode> tree = new TreeMap<>();
		for(int i = 0; i < objs.size(); i++) {
			DataflowFunctionWithArgs f = new DataflowFunctionWithArgs(objs.get(i), plugin);
			System.out.println(f.toString());
			FunctionRunNode node = new FunctionRunNode(f);
			tree.put(f.tick, node);
		}
		FunctionRunNode root = tree.firstEntry().getValue();
		for(int i = 0; i < objs.size(); i++) {
			JSONObject obj = objs.get(i);
			Long t = obj.getLong("starttick");
			FunctionRunNode node = tree.get(t);
			if(node == null) continue;
			if(obj.has("parent") && !obj.isNull("parent")) {
				Long parentTick = obj.getLong("parent");
				FunctionRunNode parent = tree.get(parentTick);
				node.parent = parent;
			}
			JSONArray children = obj.getJSONArray("children");
			for(int j = 0; j < children.length(); j++) {
				Long childTick = children.getLong(j);
				FunctionRunNode childNode = tree.get(childTick);
				if(childNode != null) {
					node.children.put(childTick, childNode);
				}
			}
			node.root = root;
		}
		for(Long t : tree.navigableKeySet()) {
			tree.get(t).reset();
		}
		
		return tree.firstEntry().getValue();		 		
	}

	@Override
	public JComponent getComponent() {
		return calltree.getComponent();
	}

	private CallTree buildComponent() {
		return new CallTree(this);

	}

	public void tickChanged(Long tick) {
		this.calltree.empty(true);
     Swing.runLater(new Runnable() {

		@Override
		public void run() {			
			 if(tick != null) {
				 try {
					   
						FunctionRunNode root = getCallTreeForTick(tick);
						if(root == null) {
							CallTreeProvider.this.calltree.empty(false);
						}
						CallTreeProvider.this.calltree.update(root, tick);
				 }
				 catch (Exception e) {
					 e.printStackTrace();
					}		 
			 } else {
				 CallTreeProvider.this.calltree.empty(false);
			 }
		}});
	}

	public void tickSelectedInTree(long tick, Long addr) {
	
		//MadnessAnchor x = new MadnessAnchor(tick, addr);
		//sendAnchorUpdate(x);
	}

}
