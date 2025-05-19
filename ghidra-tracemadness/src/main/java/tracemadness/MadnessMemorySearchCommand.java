package tracemadness;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import tracemadness.memindex.MemorySearchResult;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import org.json.JSONException;
import org.json.JSONObject;
import org.python.modules.time.Time;

import com.arangodb.ArangoCursorAsync;
import com.arangodb.ArangoDatabaseAsync;
import com.arangodb.shaded.fasterxml.jackson.databind.JsonNode;


public class MadnessMemorySearchCommand extends BackgroundCommand {

	private byte[] searchString;
	private MadnessMemorySearchQueryResultListener resultListener;
	private MemoryIndexClient client;
	private String tag;

	public MadnessMemorySearchCommand(byte[] searchString, MemoryIndexClient client, MadnessMemorySearchQueryResultListener listener, String queryTag) throws Exception {
		this.searchString = searchString;
		this.resultListener = listener;
		this.client = client;
		this.tag = queryTag;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		ArrayList<MemorySearchResult> res = this.client.searchMemory(searchString, monitor, 120);
		if(res == null) return false;
		
		this.resultListener.queryCompleted(res, tag);
		return true;
	}
}
