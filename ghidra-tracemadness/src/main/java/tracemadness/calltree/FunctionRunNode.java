package tracemadness.calltree;

import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import resources.Icons;
import tracemadness.dataflowinfo.DataflowFunctionWithArgs;

public class FunctionRunNode extends GTreeNode {
	public FunctionRunNode parent;
	public FunctionRunNode root;
	public DataflowFunctionWithArgs function;
	public TreeMap<Long, FunctionRunNode> children = new TreeMap<Long, FunctionRunNode>();
	public FunctionRunNode(DataflowFunctionWithArgs f) {
		this.function = f;
	}
	
	public FunctionRunNode getSubnodeAtTick(long tick) {
		if(this.function.tick <= tick && (this.function.endtick == null || this.function.endtick > tick)) {
			Map.Entry<Long, FunctionRunNode> e = children.floorEntry(tick);
			if(e == null) {
				return this;
			}
			FunctionRunNode child = e.getValue();
			if(child == null) {
				return null;
			}
			FunctionRunNode n = child.getSubnodeAtTick(tick);
			if(n != null) {
				return n;
			}
			return this;
		}
		return null;
	}
	
	public void reset() {
		ArrayList<GTreeNode> ans = new ArrayList<>();
		for(Long t : this.children.navigableKeySet()) {
			FunctionRunNode child = this.children.get(t);
			if(child != null) {
				ans.add(child); 
			}
		}
		this.doSetChildrenAndFireEvent(ans);
	}
	
	@Override
	public boolean equals(Object o) {
		if (o != null && (o instanceof FunctionRunNode)) {
			return this.function.tick == ((FunctionRunNode)o).function.tick;
		}
		return false;
	}
	@Override
	public int hashCode() {
		return Long.hashCode(this.function.tick);		
	}
	@Override
	public boolean isLeaf() {
		return this.children.size() == 0;
	}
	@Override
	public String getName() {
		return this.function.toString();
	}
	@Override
	public String toString() {
		return this.function.toString();
	}
	@Override
	public Icon getIcon(boolean expanded) {
		return expanded ? Icons.COLLAPSE_ALL_ICON : Icons.EXPAND_ALL_ICON;
	}
	@Override
	public String getToolTip() {
		return this.function.toString();
	}
}
