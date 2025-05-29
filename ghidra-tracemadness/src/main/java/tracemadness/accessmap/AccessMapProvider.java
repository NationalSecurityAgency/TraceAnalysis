package tracemadness.accessmap;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridLayout;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.event.MouseMotionListener;
import java.awt.event.MouseWheelEvent;
import java.awt.event.MouseWheelListener;
import java.awt.geom.AffineTransform;
import java.awt.geom.Point2D;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JViewport;

import org.json.JSONObject;


import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.ActionContextProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.widgets.fieldpanel.field.Field;
import generic.theme.GIcon;
import tracemadness.MadnessPlugin;
import tracemadness.MadnessQueryResultListener;
import tracemadness.objectdata.ObjectInfo;
import tracemadness.timelisting.TimeListingActionContext;
import tracemadness.timelisting.TimeListingProvider;
import tracemadness.View;
import tracemadness.accesslisting.AccessEvent;
import tracemadness.dataflowinfo.DataflowAccess;
import tracemadness.listingfield.SpacetimeTickField;

public class AccessMapProvider extends ComponentProvider implements ActionContextProvider {

	private MadnessPlugin plugin;
	private JPanel mainPanel;
	
	public JLabel accessLabel;
	public JLabel objectLabel;
	private AccessMap map;
	private AccessPanel accessPanel;

	private ArrayList<AccessEvent> accesses;
	private ArrayList<ObjectInfo> objects;
	
	public AccessMapProvider(MadnessPlugin plugin, String description, ArrayList<AccessEvent> accesses, ArrayList<ObjectInfo> objs) {
		super(MadnessPlugin.currentTool, description, plugin.getName());
		this.plugin = plugin;
		this.createDockingActions();
		this.createContextActions();
		this.accesses = accesses;
		this.objects = objs;
		this.accessLabel = new JLabel("Access: ");
		this.objectLabel = new JLabel("Object: ");
	}
	
	@Override
	public ActionContext getActionContext(MouseEvent ev) {
		if(ev == null) return new AccessMapActionContext(this, null, null);
		Point2D p = ev.getPoint();
		AccessEvent ae = this.map.getAccess((int)p.getX(), (int)p.getY());
		ObjectInfo o = this.map.getObject((int)p.getX(), (int)p.getY());
		return new AccessMapActionContext(this, ae, o);
	}

	@Override
	public JComponent getComponent() {
		if (mainPanel == null) {
			buildPanel();
		}
		return mainPanel;
	}
	
	private void createContextActions() {
		{
			GoToAccessContextAction a = new GoToAccessContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Go to access"}, null, "space"));
			this.plugin.getTool().addAction(a);
		}	
		{
			TargetObjectContextAction a = new TargetObjectContextAction(this);
			a.setPopupMenuData(new MenuData(new String[] {"Target object"}, null, "space"));
			this.plugin.getTool().addAction(a);
		}		
	}
	
	private void buildPanel() {
		this.mainPanel = new JPanel();

		this.mainPanel.setLayout(new BorderLayout());
		
		JPanel statusPanel = new JPanel();
		statusPanel.setLayout(new GridLayout(2,1));
		statusPanel.add(accessLabel);
		statusPanel.add(objectLabel);
		mainPanel.add(statusPanel, BorderLayout.NORTH);
		
		map = new AccessMap(this.accesses, this.objects);
		this.accessPanel = new AccessPanel(this, map);
		JScrollPane view = new JScrollPane(accessPanel);
		this.mainPanel.add(view, BorderLayout.CENTER);
		//this.accessPanel.zoom = this.accessPanel.getVisibleRect().height/1000.0;
	}
	
	private void createDockingActions() {

		AccessMapProvider self = this;
		// Go to tick
		/*DockingAction gotoAction = new DockingAction("Go To Tick", getName()) {
			@Override
			public void actionPerformed(ActionContext arg0) {
				self.accessPanel.zoom = 1.0;//self.accessPanel.getVisibleRect().height/1000.0;
				self.accessPanel.zoomPointX = 0;
				self.accessPanel.zoomPointY = 0;
				self.accessPanel.repaint();
			}
		};
		gotoAction.setToolBarData(new ToolBarData(new GIcon("icon.plugin.datatypes.filter.pointers.off"), null));
		gotoAction.setEnabled(true);
		this.addLocalAction(gotoAction);*/
	}

	private class GoToAccessContextAction extends DockingAction {
		AccessMapProvider provider;
		public GoToAccessContextAction(AccessMapProvider provider) {
			super("Go to access", provider.plugin.getName());
			this.provider = provider;
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if(!(context instanceof AccessMapActionContext)) return false;
			AccessMapActionContext c = (AccessMapActionContext)context;
			if(c.getAccess() != null) {
				return true;
			}
			return false;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			AccessMapActionContext c = (AccessMapActionContext)context;
			if(c.getAccess() == null) return;
			this.provider.plugin.timeListingProvider.goToTick(c.getAccess().getTick());
		}

	}
	private class TargetObjectContextAction extends DockingAction {
		AccessMapProvider provider;
		public TargetObjectContextAction(AccessMapProvider provider) {
			super("Target object", provider.plugin.getName());
			this.provider = provider;
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if(!(context instanceof AccessMapActionContext)) return false;
			AccessMapActionContext c = (AccessMapActionContext)context;
			ObjectInfo o = c.getObject();
			if(o != null) {
				return true;
			}
			return false;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			AccessMapActionContext c = (AccessMapActionContext)context;
			ObjectInfo o = c.getObject();
			if(o == null) return;
			this.provider.plugin.dataNavProvider.setStartTick(o.getBirth());
			this.provider.plugin.dataNavProvider.setStartAddr(o.getBase());
			this.provider.plugin.dataNavProvider.setEndAddr(o.getBase()+o.getSize());
			if(o.getDeath() != null) this.provider.plugin.dataNavProvider.setEndTick(o.getDeath());
		}

	}
	private class AccessPanel extends JPanel implements MouseListener, MouseMotionListener {
		AccessMapProvider provider;
		
	    private AccessMap map;

		public AccessPanel(AccessMapProvider p, AccessMap map) {
			this.provider = p;
			this.map = map;
			this.addMouseListener(this);
			//this.addMouseWheelListener(this);
			this.addMouseMotionListener(this);
			this.setPreferredSize(new Dimension((int)map.width, (int)map.height));
		}
		@Override
		protected void paintComponent(Graphics g) {
			super.paintComponent(g);
			Graphics2D g2d = (Graphics2D)g;
	        g.drawImage(map.img,0,0,null);
			g2d.dispose();
		}

		@Override
		public void mouseMoved(MouseEvent e) {
			try {
				Point2D p = e.getPoint();
				AccessEvent ae = this.map.getAccess((int)p.getX(), (int)p.getY());
				ObjectInfo o = this.map.getObject((int)p.getX(), (int)p.getY());
				if(ae != null) {
					this.provider.accessLabel.setText("Access: "+ae.toString());
				} else {
					this.provider.accessLabel.setText("Access: <none>");
				}
				if(o != null) {
					this.provider.objectLabel.setText("Object: "+o.toString());
				} else {
					this.provider.objectLabel.setText("Object: <none>");
				}
				System.out.println(p.toString() + " access=" + (ae != null ? ae.toString() : "<?>") + " obj=" + ((o != null) ? o.toString() : "<none>"));
			} catch(Exception exc) {
				exc.printStackTrace();
			}
		}

		@Override
		public void mouseDragged(MouseEvent e) {
			
		}

		@Override
		public void mouseClicked(MouseEvent e) {
			
		}

		@Override
		public void mouseEntered(MouseEvent arg0) {
			
		}

		@Override
		public void mouseExited(MouseEvent arg0) {
			
		}

		@Override
		public void mousePressed(MouseEvent e) {
			
			
		}

		@Override
		public void mouseReleased(MouseEvent arg0) {
			
		}
	}
}
