package tracemadness;

import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import tracemadness.memindex.MemorySearchResult;

import java.util.ArrayList;


public class MadnessMemorySearchCommand extends Task {

	private byte[] searchString;
	private MadnessMemorySearchQueryResultListener resultListener;
	private MemoryIndexClient client;
	private String tag;

	public MadnessMemorySearchCommand(byte[] searchString, MemoryIndexClient client, MadnessMemorySearchQueryResultListener listener, String queryTag) throws Exception {
		super("Memory search");
		this.searchString = searchString;
		this.resultListener = listener;
		this.client = client;
		this.tag = queryTag;
	}

	@Override
	public void run(TaskMonitor monitor) {
		ArrayList<MemorySearchResult> res = this.client.searchMemory(searchString, monitor, 120);
		if(res == null) return;
		
		this.resultListener.queryCompleted(res, tag);
		return;
	}
}
