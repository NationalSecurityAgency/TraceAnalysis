package tracemadness.calltree;

import java.awt.BorderLayout;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.tree.TreePath;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.internal.InProgressGTreeRootNode;
import docking.widgets.tree.support.GTreeSelectionEvent;
import docking.widgets.tree.support.GTreeSelectionListener;

public class CallTree implements GTreeSelectionListener {
	private JPanel mainPanel;
	private GTree tree = null;
	private final CallTreeProvider provider;
	public JComponent getComponent() {
		return mainPanel;
	}

	public CallTree(CallTreeProvider provider) {
		mainPanel = build();
		this.provider = provider;
		setTree(emptyTree(false));
		
	}

	private void setTree(GTreeNode root) {
		this.tree = new GTree(root);	
		mainPanel.removeAll();
		mainPanel.add(tree, BorderLayout.CENTER);
	}

	public void empty(boolean pending) {
		setTree(new InProgressGTreeRootNode());
	}

	protected GTreeNode emptyTree(boolean pending) {
		return new InProgressGTreeRootNode();
	}

	private JPanel build() {
		mainPanel = new JPanel();
		mainPanel.setLayout(new BorderLayout());
		empty(false);
		return mainPanel;
	}
	
	public void select(long startTick) {
		if (tree == null) {
			return;
		}
		
		FunctionRunNode r = (FunctionRunNode)tree.getModelRoot();
		FunctionRunNode selection = r.getSubnodeAtTick(startTick);

		if (selection != null) {
			tree.setSelectedNode(selection);
		}
		tree.addGTreeSelectionListener(CallTree.this);
		tree.updateUI();
	}
	
	public void update(FunctionRunNode root, long startTick) {
		setTree(root);
		select(startTick);
	}

	@Override
	public void valueChanged(GTreeSelectionEvent e) {
		TreePath p = e.getNewLeadSelectionPath();
		FunctionRunNode r = (FunctionRunNode)p.getLastPathComponent();
		this.provider.tickSelectedInTree(r.function.tick,r.function.pc);
	}
}
