package tracemadness;

import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

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


public class MadnessQueryCommand extends Task {

	private MadnessQuery query;
	private MadnessQueryResultListener resultListener;
	private String[] queryParams;
	private ArangoDatabaseAsync dbConnection;
	private String tag;

	public MadnessQueryCommand(MadnessQuery baseQuery, String[] params, ArangoDatabaseAsync db, MadnessQueryResultListener listener, String queryTag) throws Exception {
		super("TraceMadness Query");
		this.query = baseQuery;
		this.resultListener = listener;
		this.queryParams = params;
		this.dbConnection = db;
		this.tag = queryTag;
	}

	@Override
	public void run(TaskMonitor monitor) {
		String q = this.query.queries.get("default");

		String formattedQuery = new MessageFormat(q).format(this.queryParams);
		MadnessPlugin.LOG.info("MadnessQuery List RUNNING: " + formattedQuery);
		
		CompletableFuture<ArangoCursorAsync<JsonNode>> f = this.dbConnection.query(formattedQuery, JsonNode.class);
		int t = 0;
		
		while(t < 120) {
			Time.sleep(1);
			if(monitor.isCancelled()) {
				f.cancel(true);
				return;
			}
			if(f.isDone()) break;
		}
		if(f.isCancelled()) return;
		if(f.isCompletedExceptionally()) return;
		if(!f.isDone()) return;
		
		//ArangoCursor<JsonNode> queryResults = this.dbConnection.query(formattedQuery, JsonNode.class);
		try {
			ArrayList<JSONObject> ret = new ArrayList<JSONObject>();
			while(true) {
				ArangoCursorAsync<JsonNode> cursor = f.get();
				List<JsonNode> queryResults = cursor.getResult();
				for(JsonNode doc : queryResults) {
					try {
						JSONObject parsed = new JSONObject(doc.toString());
						ret.add(parsed);
					} catch (JSONException e) {
						e.printStackTrace();
					}
				}
				if(!cursor.hasMore()) {
					cursor.close();
					break;
				}
				f = cursor.nextBatch();
			}
			this.resultListener.queryCompleted(ret, tag);
			return;
		} catch(Exception e) {
			e.printStackTrace();
			return;
		}
		
	}
}
