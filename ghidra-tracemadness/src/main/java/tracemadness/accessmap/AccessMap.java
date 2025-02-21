package tracemadness.accessmap;

import java.awt.BasicStroke;
import java.awt.Graphics2D;
import java.awt.Stroke;
import java.awt.image.BufferedImage;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

import tracemadness.dataflowinfo.DataflowAccess;
import tracemadness.dataflowinfo.DataflowObject;

public class AccessMap {
	public BufferedImage img;
	private HashMap<Long, Long> xToTick;
	private HashMap<Long, Long> yToAddr;
	private TreeMap<Long, DataflowAccess> tickToAccess;
	private TreeMap<Long, Long> addrToY;
	private TreeMap<Long, Long> tickToX;
	private TreeSet<Long> addrSet;
	private TreeSet<Long> tickSet;
	private TreeMap<Long, Long> xBreaks;
	private TreeMap<Long, Long> yBreaks;
	public long width;
	public long height;
	private long minTick, maxTick, minAddr, maxAddr;
	private static final int SCALE = 2;
	
	public AccessMap(List<DataflowAccess> arr) {
		
		xToTick = new HashMap<>();
		yToAddr = new HashMap<>();
		tickToAccess = new TreeMap<>();
		addrSet = new TreeSet<>();
		tickSet = new TreeSet<>();
		xBreaks = new TreeMap<>();
		yBreaks = new TreeMap<>();
		
		tickToX = new TreeMap<>();
		addrToY = new TreeMap<>();
		
		minTick = Long.MAX_VALUE;
		maxTick = Long.MIN_VALUE;
		minAddr = Long.MAX_VALUE;
		maxAddr = Long.MIN_VALUE;
		
		for (DataflowAccess access : arr) {
			if(access.addr < minAddr) minAddr = access.addr;
			if(access.addr > maxAddr) maxAddr = access.addr;
			if(access.tick < minTick) minTick = access.tick;
			if(access.tick > maxTick) maxTick = access.tick;
			tickToAccess.put(access.tick, access);
			tickSet.add(access.tick);
			addrSet.add(access.addr);
		}
		
		this.drawAccesses();
	}
	
	private void drawAccesses() {
		Long Y = 0L;
		Long prevAddr = addrSet.first();
		yBreaks.put(Y, prevAddr);
		addrToY.put(prevAddr,  Y);
		
		for(Long addr = addrSet.ceiling(prevAddr+1); addr != null; addr = addrSet.ceiling(addr+1) ) {
			if (addr - prevAddr > 0x40) {
				Y += SCALE;
				yBreaks.put(Y, addr);
				Y += SCALE;
				addrToY.put(addr,  Y);
				
			} else {
				Y += SCALE*(addr-prevAddr);
				addrToY.put(addr,  Y);
			}
			prevAddr = addr;
		}
		
		Long X = 0L;
		Long prevTick = tickSet.first();
		tickToX.put(prevTick,  X);
		int max_x = Integer.MAX_VALUE/(int)Y.longValue();
		Long maxTick = 0L;
		for(Long tick = tickSet.ceiling(prevTick+1); tick != null; tick = tickSet.ceiling(tick+1) ) {
			if (tick - prevTick > 3) {
				X += SCALE;
				xBreaks.put(X, tick);
				X += SCALE;
				tickToX.put(tick,  X);
				
			} else {
				X += SCALE*(tick-prevTick);
				tickToX.put(tick,  X);
			}
			prevTick = tick;
		}
		
		width = X;
		height = Y;
		System.out.println(width + " x " + height);
		img = new BufferedImage((int)width, (int)height, BufferedImage.TYPE_INT_RGB);
		
		Graphics2D g = (Graphics2D)(img.getGraphics());
		g.setColor(java.awt.Color.white);
		g.fillRect(0,  0,  (int)width,  (int)height);
		
		int i = 0;
		for(Long t : tickToAccess.keySet()) {
			DataflowAccess a = tickToAccess.get(t);
			Long x = tickToX.get(t);
			Long y = addrToY.get(a.addr);
			if(i++ < 1000) System.out.println(a.toString() + " @ " + x + "," + y);
			xToTick.put(x, a.tick);
			yToAddr.put(y, a.addr);
			g.setColor(a.isWrite ? java.awt.Color.red : java.awt.Color.blue);
			g.fillRect((int)x.longValue(), (int)y.longValue(), SCALE, (int)a.size*SCALE);
		}
		
		g.setColor(new java.awt.Color(0xcc, 0xcc, 0xcc));
		for(Long y : yBreaks.keySet()) {
			Long addr = yBreaks.get(y);
			g.fillRect(0, (int)y.longValue(), 10*SCALE, SCALE);
			g.drawString(String.format("0x%x", addr.longValue()), 10, (int)y.longValue()+SCALE);
		}
	}
	
	public void addObject(DataflowObject o) {
		for(Long t = tickToAccess.ceilingKey(o.startTick); t != null; t = tickToAccess.higherKey(t)) {
			DataflowAccess a = tickToAccess.get(t);
			if(a.addr >= o.startAddr && a.addr < o.endAddr) {
				o.addAccessTick(t);
			}
		}
		
		this.drawObject(o);
	}
	
	private void drawObject(DataflowObject o) {
		long x = o.startTick-minTick;
		long w = o.endTick-o.startTick;
		long y = o.startAddr-minAddr;
		long h = o.endAddr-o.startAddr;
		
		Graphics2D g = (Graphics2D)(img.getGraphics());
		g.setStroke(new BasicStroke(1.0f, 0, 0));
		g.setColor(java.awt.Color.orange);
		g.drawRect((int)x*SCALE, (int)y*SCALE, (int)w*SCALE, (int)h*SCALE);
	}
}