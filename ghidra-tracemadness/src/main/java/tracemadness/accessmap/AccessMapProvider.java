package tracemadness.accessmap;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridLayout;
import java.awt.Point;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.event.MouseMotionListener;
import java.awt.event.MouseWheelEvent;
import java.awt.event.MouseWheelListener;
import java.awt.geom.AffineTransform;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Point2D;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JViewport;

import org.json.JSONObject;


import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.ActionContextProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import generic.theme.GIcon;
import resources.Icons;
import tracemadness.MadnessPlugin;
import tracemadness.MadnessQueryResultListener;
import tracemadness.objectdata.ObjectInfo;
import tracemadness.View;
import tracemadness.dataflowinfo.DataflowAccess;
import tracemadness.dataflowinfo.DataflowObject;

public class AccessMapProvider extends ComponentProvider implements ActionContextProvider, MadnessQueryResultListener {

	private MadnessPlugin plugin;
	private JPanel mainPanel;
	private AccessPanel accessPanel;
	
	private ArrayList<DataflowAccess> accesses;

	private long minAddr;
	private long maxAddr;
	private long minTick;
	private long maxTick;
	
	public AccessMapProvider(MadnessPlugin plugin, String description) {
		super(MadnessPlugin.currentTool, description, plugin.getName());
		this.plugin = plugin;
		this.createDockingActions();
		this.createContextActions();
		this.accesses = new ArrayList<>();
		
		this.initData();
		//this.initPoints();
	}
	
	public void initData() {
		String[] params = { "for op in operationruns filter (op.bank == 1 or op.opcode == 2 ) and op.tick > 50000 limit 10000" };
		//String[] params = { "for op in operationruns filter (op.bank == 1 and op.addr < 139657211039752+100000) or (op.assocd_bank == 1 and op.assocd_addr < 139657211039752+100000) limit 10000" };
		try {
			plugin.runQuery("accesses", params, this, "accesses");
		} catch(Exception exc) {
			exc.printStackTrace();
		}
	}
	
	/*public void initPoints() {

		long i = 0;
		long end = this.accesses.size();
		for(DataflowAccess a : this.accesses) {
			double x = ((double)(a.tick-minTick)/(double)(maxTick-minTick))*1000;
			double y = (((double)(a.addr-minAddr))/(double)(maxAddr-minAddr))*1000;
			double w = 2.0;
			//System.out.println("access " + i + " at addr " + a.addr + " drawn at " + x + "," + y + "--" + maxAddr + "," + minAddr+","+((double)a.addr/(double)(maxAddr-minAddr)));
			AccessPoint p = new AccessPoint(a, x, y, w);
			this.points.add(p);
			i++;
		}
	}*/
	
	@Override
	public ActionContext getActionContext(MouseEvent ev) {

		ObjectInfo sel = null;//this.getSelectedObject();
		if(sel == null) return null;
		return new AccessMapActionContext(this, sel);
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
			//AccessesContextAction a = new AccessesContextAction(this);
			//a.setPopupMenuData(new MenuData(new String[] {"Object accesses"}, null, "space"));
			//this.plugin.getTool().addAction(a);
		}		
	}
	
	private void buildPanel() {
		this.mainPanel = new JPanel(new GridLayout());

		this.mainPanel.setLayout(new BorderLayout());
		AccessMap map = new AccessMap(this.accesses);
		this.accessPanel = new AccessPanel(this, map);
		JScrollPane view = new JScrollPane(accessPanel);
		this.mainPanel.add(view);
		//this.accessPanel.zoom = this.accessPanel.getVisibleRect().height/1000.0;
	}
	
	private void createDockingActions() {

		AccessMapProvider self = this;
		// Go to tick
		DockingAction gotoAction = new DockingAction("Go To Tick", getName()) {
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
		this.addLocalAction(gotoAction);
	}

	public View exampleView() {
		return new AccessMapView();
	}
	private class AccessPanel extends JPanel implements MouseListener, MouseMotionListener, MouseWheelListener {
		AccessMapProvider provider;
		
	    public double zoom = 1.0;
	    public double zoomPointX = 0;
	    public double zoomPointY = 0;
	    private AffineTransform transform;
	    private Point2D dragStart;
	    private AccessMap map;

		public AccessPanel(AccessMapProvider p, AccessMap map) {
			this.provider = p;
			this.map = map;
			this.transform = new AffineTransform();
			this.addMouseListener(this);
			this.addMouseWheelListener(this);
			this.addMouseMotionListener(this);
			this.setPreferredSize(new Dimension((int)map.width, (int)map.height));
		}
		public void setTransform(double originX, double originY, double z) {
			this.transform = new AffineTransform();
	        //this.transform.translate(originX, originY);
	        this.transform.scale(z, z);
	        //this.transform.translate(-originX, -originY);
		}
		@Override
		protected void paintComponent(Graphics g) {
			super.paintComponent(g);
			Graphics2D g2d = (Graphics2D)g;
	        //g2d.setTransform(this.transform);
	        g.drawImage(map.img,0,0,null);
//	        //draw the background
//	        g2d.setColor(java.awt.Color.white);
//	        java.awt.Rectangle r = this.getVisibleRect();
//	        g2d.fillRect((int)r.getMinX(), (int)r.getMinY(), (int)r.getMaxX(), (int)r.getMaxY());
//
//	        // draw the accesses
//	        g2d.setTransform(this.transform);
//	        g2d.setColor(java.awt.Color.black);
//			for(AccessPoint p : this.provider.points) {
//				g2d.fill(p);
//			}
			
			// draw the objects
			
			// done
			g2d.dispose();
		}

		@Override
		public void mouseMoved(MouseEvent e) {
			try {
				//Point2D m = this.transform.inverseTransform(e.getPoint(), null);
				Point2D p = e.getPoint();
				System.out.println(p);
				
				/*for(AccessPoint p : this.provider.points) {
					if(p.contains(m)) {
						System.out.println(p.access);
					}
				}*/
			} catch(Exception exc) {
				exc.printStackTrace();
			}
		}

		@Override
		public void mouseDragged(MouseEvent e) {
			try {
				
				Point2D p = this.transform.inverseTransform(e.getPoint(), null);
	            zoomPointX += (int)((1/zoom)*(p.getX() - this.dragStart.getX()));
	            zoomPointY += (int)((1/zoom)*(p.getY() - this.dragStart.getY()));
	            System.out.println(e.getPoint() + " = " + p + " from " + this.dragStart);
	            this.setTransform(zoomPointX, zoomPointY, zoom);
	            repaint();
			} catch(Exception exc) {
				exc.printStackTrace();
			}
		}

		@Override
		public void mouseClicked(MouseEvent e) {
			
		}

		@Override
		public void mouseEntered(MouseEvent arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void mouseExited(MouseEvent arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void mousePressed(MouseEvent e) {
			try {
				this.dragStart = this.transform.inverseTransform(e.getPoint(), null);
			} catch(Exception exc) {
				exc.printStackTrace();
			}
			
		}

		@Override
		public void mouseReleased(MouseEvent arg0) {
			// TODO Auto-generated method stub
			
		}
		@Override
		public void mouseWheelMoved(MouseWheelEvent e) {
			try {
				Point2D p = e.getPoint();//this.transform.inverseTransform(e.getPoint(), null);
	            zoomPointX = (p.getX());
	            zoomPointY = (p.getY());
	            if (e.getPreciseWheelRotation() < 0) {
	                zoom -= 0.1;
	            } else {
	                zoom += 0.1;
	            }
	            if (zoom < 0.01) {
	                zoom = 0.01;
	            }
	            this.setTransform(zoomPointX, zoomPointY, zoom);
	            repaint();
			} catch(Exception exc) {
				exc.printStackTrace();
			}
		}
	}
	@Override
	public void queryCompleted(List<JSONObject> results, String tag) {
		for(int i = 0; i < results.size(); i++) {
			try {
				JSONObject obj = results.get(i);
				DataflowAccess access = new DataflowAccess(obj);
				this.accesses.add(access);
			} catch(Exception exc) {
				exc.printStackTrace();
				continue;
			}
		}
		this.buildPanel();
	}
	

	
    /*private class AccessPoint extends Ellipse2D.Double {
    	public DataflowAccess access;
    	public double x;
    	public double y;
    	
        public AccessPoint(DataflowAccess a, double x, double y, double w) {
            super(x-w/2, y - w/2, w, w);
            this.access = a;
        }
    }*/



}
