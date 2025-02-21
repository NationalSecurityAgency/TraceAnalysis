package tracemadness;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
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


public class MadnessQueryCommand extends BackgroundCommand {

	private MadnessQuery query;
	private MadnessQueryResultListener resultListener;
	private String[] queryParams;
	private ArangoDatabaseAsync dbConnection;
	private String tag;

	public MadnessQueryCommand(MadnessQuery baseQuery, String[] params, ArangoDatabaseAsync db, MadnessQueryResultListener listener, String queryTag) throws Exception {
		this.query = baseQuery;
		this.resultListener = listener;
		this.queryParams = params;
		this.dbConnection = db;
		this.tag = queryTag;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		if(!(obj instanceof Program)) {
			return false;
		}
		Program prog = (Program) obj;
		String proc = prog.getLanguage().toString();

		String q = null;
		if (this.query.queries.containsKey(proc)) {
			q = this.query.queries.get(proc);
		} else if (this.query.queries.containsKey("default")) {
			q = this.query.queries.get("default");
			MadnessPlugin.LOG.info("query:\n"+query);
		} else {
			MadnessPlugin.LOG.error("Query: " + this.query.name + " did not specify an AQL file for the specified processor " + proc);
			monitor.cancel();
			return false;
		}

		String formattedQuery = new MessageFormat(q).format(this.queryParams);
		MadnessPlugin.LOG.info("MadnessQuery List RUNNING: " + formattedQuery);
		
		CompletableFuture<ArangoCursorAsync<JsonNode>> f = this.dbConnection.query(formattedQuery, JsonNode.class);
		int t = 0;
		
		while(t < 120) {
			Time.sleep(1);
			if(monitor.isCancelled()) {
				f.cancel(true);
				return false;
			}
			if(f.isDone()) break;
		}
		if(f.isCancelled()) return false;
		if(f.isCompletedExceptionally()) return false;
		
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
			return true;
		} catch(Exception e) {
			e.printStackTrace();
			return false;
		}
		
	}
}
