package tracemadness.accessmap;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.TreeMap;
import java.util.TreeSet;

import tracemadness.accesslisting.AccessEvent;
import tracemadness.objectdata.ObjectInfo;

public class AccessMap {
	public BufferedImage img;
	private HashMap<Long, Long> xToTick;
	private HashMap<Long, Long> yToAddr;
	private TreeMap<Long, AccessEvent> tickToAccess;
	private TreeMap<Long, Long> addrToY;
	private TreeMap<Long, Long> tickToX;
	private TreeSet<Long> addrSet;
	private TreeSet<Long> tickSet;
	public long width;
	public long height;
	//private long minTick, maxTick, minAddr, maxAddr;
	private static final int SCALE = 10;
	private ArrayList<ObjectRectangle> liveObjs;
	
	public AccessMap(List<AccessEvent> accesses, List <ObjectInfo> objs) {
		
		xToTick = new HashMap<>();
		yToAddr = new HashMap<>();
		tickToAccess = new TreeMap<>();
		addrSet = new TreeSet<>();
		tickSet = new TreeSet<>();
		
		tickToX = new TreeMap<>();
		addrToY = new TreeMap<>();
		
		for (AccessEvent access : accesses) {
			tickToAccess.put(access.getTick(), access);
			tickSet.add(access.getTick());
			addrSet.add(access.getAddr());
			/*// Maybe it is better to have accesses marked for the range of addresses they hit rather than just the base address. However this makes for some rather tall pictures... 
			 * for(int i = 0; i < access.getSize(); i++) {
				addrSet.add(access.getAddr()+i);
			}*/
		}
		
		liveObjs = new ArrayList<>();
		ArrayList<ObjectInfo> relevantObjects = new ArrayList<>();
		for(ObjectInfo o : objs) {
			if((o.getBirth() < tickSet.first() && (o.getDeath() == null || o.getDeath() > tickSet.last())) || (tickSet.first() <= o.getBirth() && o.getBirth() <= tickSet.last()) || (o.getDeath() != null && (tickSet.first() <= o.getDeath() && o.getDeath() <= tickSet.last()))) {
				if((o.getBase() < addrSet.first() && addrSet.last() < o.getBase()+o.getSize()) || (addrSet.first() <= o.getBase() && o.getBase() <= addrSet.last()) || (addrSet.first() <= o.getBase() + o.getSize() && o.getBase()+o.getSize() <= addrSet.last())) {
					tickSet.add(o.getBirth());
					tickSet.add(o.getDeath() == null ? tickSet.last() : o.getDeath());
					addrSet.add(o.getBase());
					addrSet.add(o.getBase()+o.getSize());
					relevantObjects.add(o);
				}
			}
		}
		

		for(var o : relevantObjects) {
			liveObjs.add(new ObjectRectangle(o.getBirth(), o.getDeath() == null ? tickSet.last() : o.getDeath(), o.getBase(), o.getBase()+o.getSize(), o));
		}
		
		this.draw();
	}
	
	public AccessEvent getAccess(int x, int y) {
		Long tick = xToTick.get((long)(x - (x%SCALE)));
		if(tick == null) return null;
		return tickToAccess.get(tick);
	}
	public ObjectInfo getObject(int x, int y) {
		Long tick = xToTick.get((long)(x - (x%SCALE)));
		if(tick == null) return null;
		Long addr = yToAddr.get((long)(y - (y%SCALE)));
		if(addr == null) return null;
		for(ObjectRectangle r : liveObjs) {
			if(r.contains(tick, addr)) {
				return r.obj; 
			}
		}
		return null;
	}
	
	private void draw() {
		
		Long Y = 0L;
		Long prevAddr = addrSet.first();
		addrToY.put(prevAddr,  Y);
		Y += SCALE;
		TreeSet<Long> yBreaks = new TreeSet<>();
		
		for(Long addr = addrSet.ceiling(prevAddr+1); addr != null; addr = addrSet.ceiling(addr+1) ) {
			if(addr-prevAddr >= 0x1000) {
				yBreaks.add(Y);
				Y += SCALE;
			}
			addrToY.put(addr,  Y);
			Y += SCALE;
			prevAddr = addr;
		}
		
		Long X = 0L;
		Long prevTick = tickSet.first();
		tickToX.put(prevTick,  X);
		for(Long tick = tickSet.ceiling(prevTick+1); tick != null; tick = tickSet.ceiling(tick+1) ) {
			X += SCALE;
			tickToX.put(tick,  X);
			prevTick = tick;
		}
		
		width = X;
		height = Y;
		if(X > 65536 || Y > 65536) {
			System.out.println("too big...");
			int w = 500;
			int h = 300;
			img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
			Graphics2D g = (Graphics2D)(img.getGraphics());
			g.setColor(java.awt.Color.white);
			g.fillRect(0,  0,  w,  h);
			g.setColor(java.awt.Color.red);
			g.drawString("Too many accesses to map...", 10, 10);
			return;
		}
		System.out.println(width + " x " + height);
		img = new BufferedImage((int)width, (int)height, BufferedImage.TYPE_INT_RGB);
		
		Graphics2D g = (Graphics2D)(img.getGraphics());
		g.setColor(java.awt.Color.white);
		g.fillRect(0,  0,  (int)width,  (int)height);

		g.setStroke(new BasicStroke(1.0f, 0, 0));
		g.setColor(new Color(0xff, 0xcc, 0xcc));
		for(ObjectRectangle o : liveObjs) {
			long x = tickToX.get(o.startTick);
			xToTick.put(x, o.startTick);
			long y = addrToY.get(o.startAddr);
			yToAddr.put(y, o.startAddr);
			long w = tickToX.get(o.endTick)-x;
			long h = addrToY.get(o.endAddr)-y;
			System.out.println(String.format("%d, %d ; %d, %d, %s", x, y, w, h, o.obj.toString()));
			g.fillRect((int)x, (int)y, (int)w, (int)h);
		}

		for(Long t : tickToAccess.keySet()) {
			AccessEvent a = tickToAccess.get(t);
			Long x = tickToX.get(t);
			Long y = addrToY.get(a.getAddr());
			xToTick.put(x, a.getTick());
			yToAddr.put(y, a.getAddr());
			g.setColor(a.isWrite() ? java.awt.Color.red : java.awt.Color.blue);
			g.fillRect((int)x.longValue(), (int)y.longValue(), SCALE, /*a.getSize* */SCALE);
		}
		for(Long y : yBreaks) {
			g.setColor(new java.awt.Color(0xcc, 0xcc, 0xcc));
			g.fillRect(0, (int)y.longValue(), (int)width, SCALE);
		}
		
	}
	private class ObjectRectangle {
		public long startTick;
		public long endTick;
		public long startAddr;
		public long endAddr;
		public ObjectInfo obj;
		
		public boolean contains(long tick, long addr) {
			return startTick <= tick && tick <= endTick && startAddr <= addr && addr <= endAddr;
		}
		
		public ObjectRectangle(long startTick, long endTick, long startAddr, long endAddr, ObjectInfo obj) {
			this.startTick = startTick;
			this.endTick = endTick;
			this.startAddr = startAddr;
			this.endAddr = endAddr;
			this.obj = obj;
		}
	}
}