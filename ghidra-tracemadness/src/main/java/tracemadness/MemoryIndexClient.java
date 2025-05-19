package tracemadness;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.json.JSONArray;
import org.json.JSONObject;
import org.python.modules.time.Time;

import ghidra.util.task.TaskMonitor;
import tracemadness.memindex.MemorySearchResult;
import tracemadness.memindex.MemoryValueQueryResult;


public class MemoryIndexClient {
	/*
	 * This is an async client for tm-mem-server that speaks the protocol
	 * query: 
	 * {
	 * 	"buffer":[byte array]
	 * } 
	 * -> response: 
	 * {
	 * 	"buffer_addrs":[addresses at which that buffer is found], 
	 * 	"buffer_creation_ticks":[the ticks at which those addresses become populated with the buffer being searched for],
	 *  "buffer_destruction_ticks":[the ticks at which those addresses cease to be entirely populated with the buffer being searched for]
	 * }
	 *   
	 * OR
	 *
	 * query: 
	 * {
	 * 	"mem_tick":tick at which to query,
	 * 	"mem_base":the start address at to search for values as of that tick,
	 * 	"mem_len":the length of the region to retrieve values for that tick,
	 * } 
	 * -> response: 
	 * { 
	 * 	"mem_addrs":[the (long) addresses for which values were found in the trace at or before the specified tick],
	 * 	"mem_results":[the byte values of memory at those addresses],
	 *  "mem_ticks":[the ticks at which those values came to be]
	 * } 
	 */
	String server_addr;
	int server_port;
	private final ExecutorService executor = Executors.newSingleThreadExecutor();
	public MemoryIndexClient(String server, int port) throws Exception {
		this.server_addr = server;
		this.server_port = port;
	}
	public CompletableFuture<JSONObject> makeRequest(byte[] req, int timeout) {
		return CompletableFuture.supplyAsync(() -> doSendAndReceive(req, timeout), executor);
	}
	public void cancel() {
	    executor.shutdownNow();
	}
	private JSONObject doSendAndReceive(byte[] req, int timeout) {
		try {
			SocketChannel channel = SocketChannel.open();
			channel.configureBlocking(true);
			channel.setOption(StandardSocketOptions.SO_REUSEADDR, true);
			InetSocketAddress addr = new InetSocketAddress(this.server_addr, this.server_port);
			boolean isConnected = channel.connect(addr);
			int t = 0;
			while(!isConnected) {
				try {
					TimeUnit.MILLISECONDS.sleep(100);
					isConnected = channel.finishConnect();
				} catch(InterruptedException e) {
					channel.close();
					return null;
				} catch(IOException e) {
					channel.close();
					return null;
				}
				t += 100;
				if(t >= 1000*timeout) {
					channel.close();
					return null;
				}
			}
			if(!channel.isConnected()) {
				channel.close();
				return null;
			}
			int l = req.length;
			ByteBuffer bb = ByteBuffer.allocate(4+l);
			bb.order(ByteOrder.LITTLE_ENDIAN);
			bb.putInt(l);
			bb.put(req);
			bb.position(0);
			int wrote = channel.write(bb);
			System.out.println("wrote : " + wrote);
		    byte[] lenBytes = new byte[4];
		    ByteBuffer lenBuffer = ByteBuffer.wrap(lenBytes);
		    lenBuffer.order(ByteOrder.LITTLE_ENDIAN);
		    lenBuffer.position(0);
		    int readBytes = channel.read(lenBuffer);
		    if(readBytes < lenBytes.length) {
		    	channel.close();
		    	return null;
		    }
		    lenBuffer.rewind();
		    int len = lenBuffer.getInt();
		    ByteBuffer buf = ByteBuffer.wrap(new byte[len]);
			readBytes = channel.read(buf);
			if(readBytes != len) {
				channel.close();
				return null;
			}
			buf.position(0);
			byte[] respData = new byte[len];
			buf.get(respData);
			JSONObject ans = new JSONObject(new String(respData));
			return ans;
		} catch(IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	public void test() {
		{
			ArrayList<MemorySearchResult> res = this.searchMemory(new byte[] {113, 119, 101, 113}, null, 10);
			for(var r : res) {
				System.out.println("FOUND qweq at...");
				System.out.println(r);
			}
		}
		{
			ArrayList<MemoryValueQueryResult> res = this.getMemory(150000, 0x5f699da712e0L, 100, null, 10);
			for(var r : res) {
				System.out.println("FOUND qweq at...");
				System.out.println(r);
			}
		}
	}
	public ArrayList<MemorySearchResult> searchMemory(byte[] searchString, TaskMonitor monitor, int timeout) {
		ArrayList<MemorySearchResult> res = new ArrayList<>();
		try {
			JSONObject req = new JSONObject();
			JSONArray buffer = new JSONArray();
			for(int i = 0; i < searchString.length; i++) {
				buffer.put(searchString[i]);
			}
			req.put("buffer", buffer);
			System.out.println("req: " + req.toString());
			CompletableFuture<JSONObject> futureResponse = this.makeRequest(req.toString().getBytes(), timeout);
			int t = 0;
			
			while(t < timeout) {
				Time.sleep(1);
				if(monitor != null && monitor.isCancelled()) {
					futureResponse.cancel(true);
					return null;
				}
				if(futureResponse.isDone()) break;
			}
			if(futureResponse.isCancelled()) return null;
			if(futureResponse.isCompletedExceptionally()) return null;
			if(!futureResponse.isDone()) {
				futureResponse.cancel(true);
				return null;
			}
			try {
				JSONObject ans = futureResponse.get(1, TimeUnit.SECONDS);
				res.add(new MemorySearchResult(ans));
			} catch(TimeoutException e) {
				futureResponse.cancel(true);
				return null;
			} catch(ExecutionException e) {
				return null;
			} catch(InterruptedException e) {
				// do we need to do anything with the future in this case?
				return null;
			}
		} catch(Exception e) {
			e.printStackTrace();
		}
		return res;
	}
	public ArrayList<MemoryValueQueryResult> getMemory(long tick, long base, long len, TaskMonitor monitor, int timeout) {
		ArrayList<MemoryValueQueryResult> res = new ArrayList<>();
		try {
			JSONObject req = new JSONObject();
			req.put("mem_base", base);
			req.put("mem_len", len);
			req.put("mem_tick", tick);

			CompletableFuture<JSONObject> futureResponse = this.makeRequest(req.toString().getBytes(), timeout);
			int t = 0;
			
			while(t < timeout) {
				Time.sleep(1);
				if(monitor != null && monitor.isCancelled()) {
					futureResponse.cancel(true);
					return null;
				}
				if(futureResponse.isDone()) break;
			}
			if(futureResponse.isCancelled()) return null;
			if(futureResponse.isCompletedExceptionally()) return null;
			if(!futureResponse.isDone()) {
				futureResponse.cancel(true);
				return null;
			}
			try {
				JSONObject ans = futureResponse.get(1, TimeUnit.SECONDS);
				res.add(new MemoryValueQueryResult(ans));
			} catch(TimeoutException e) {
				futureResponse.cancel(true);
				return null;
			} catch(ExecutionException e) {
				return null;
			} catch(InterruptedException e) {
				// do we need to do anything with the future in this case?
				return null;
			}
		} catch(Exception e) {
			e.printStackTrace();
		}
		return res;
	}
}
