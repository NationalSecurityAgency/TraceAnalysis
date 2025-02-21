package tracemadness;

import java.io.InputStream;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.json.JSONException;
import org.json.JSONObject;

import com.arangodb.ArangoCursor;
import com.arangodb.ArangoDatabase;
import com.arangodb.shaded.fasterxml.jackson.databind.JsonNode;

import resources.ResourceManager;

public class MadnessQuery {

	public String name;
	public HashMap<String, String> queries;
	public String description;

	public MadnessQuery(JSONObject queriesJson, String queryName) throws Exception {
		this.queries = new HashMap<String, String>();
		JSONObject obj = queriesJson.getJSONObject(queryName);
		if (obj == null) {
			throw new Exception("No such query: " + queryName);
		}

		this.name = queryName;
		String queryFile = "";
		if (obj.has("query")) {
			queryFile = obj.getString("query");
		}

		ArrayList<String> procs = new ArrayList<String>();
		if (obj.has("queryproc")) {
			var ks = obj.getJSONObject("queryproc").keys();
			while (ks.hasNext()) {
				procs.add(ks.next());
			}
		} else {
			procs.add("default");
		}
		for (String proc : procs) {
			if (proc == "default") {
				queryFile = obj.getString("query");
			} else {
				queryFile = obj.getJSONObject("queryproc").getString(proc);
			}
			//MadnessPlugin.LOG.info("query from " + queryFile);
			
			//MadnessPlugin.LOG.info("query from " + queryFile);
			InputStream is = ResourceManager.getResourceAsStream("data/" + queryFile);

			String queryStr = IOUtils.toString(is, "UTF-8");
			//MadnessPlugin.LOG.info("raw query "+queryStr);
			queryStr = queryStr.replaceAll("\\{(?:(?![0-9]+\\}))", "'{'");
			queryStr = queryStr.replaceAll("(?:(?<!\\{[0-9]+))\\}", "'}'");
			//MadnessPlugin.LOG.info("fixed query "+queryStr);
			this.queries.put(proc, queryStr);
		}
		this.description = obj.getString("description");
	}

	public List<JSONObject> runQuery(String[] params, ArangoDatabase db) throws Exception {
		String proc = MadnessPlugin.getProgramManager().getCurrentProgram().getLanguage().toString();

		String query = null;
		if (this.queries.containsKey(proc)) {
			query = this.queries.get(proc);
		} else if (this.queries.containsKey("default")) {
			query = this.queries.get("default");
			MadnessPlugin.LOG.info("query:\n"+query);
		} else {
			throw new Exception(
					"Query: " + this.name + " did not specify an AQL file for the specified processor " + proc);
		}

		String formattedQuery = new MessageFormat(query).format(params);
		MadnessPlugin.LOG.info("MadnessQuery List RUNNING: " + formattedQuery);
		
		ArangoCursor<JsonNode> queryResults = db.query(formattedQuery, JsonNode.class);

		ArrayList<JSONObject> ret = new ArrayList<JSONObject>();
		queryResults.forEachRemaining(doc -> {
			try {
				JSONObject parsed = new JSONObject(doc.toString());
				ret.add(parsed);
			} catch (JSONException e) {
				e.printStackTrace();
			}
		});

		return ret;
	}
}
