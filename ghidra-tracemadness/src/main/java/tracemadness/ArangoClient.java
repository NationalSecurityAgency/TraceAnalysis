package tracemadness;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.Level;

import org.apache.logging.log4j.core.config.Configurator;
import org.json.JSONObject;

import com.arangodb.ArangoDB;
import com.arangodb.ArangoDatabase;
import com.arangodb.ArangoDatabaseAsync;
import com.arangodb.Protocol;
import com.arangodb.config.ArangoConfigProperties;
import com.arangodb.entity.BaseDocument;
import com.arangodb.entity.BaseEdgeDocument;

import resources.ResourceManager;
import tracemadness.objectdata.ObjectInfo;
import tracemadness.objectdata.ObjectPhase;

public class ArangoClient {

	protected ArangoConfigProperties config = null;
	private ArangoDB arangoClient = null;
	private HashMap<String, ArangoDatabaseAsync> dbs = null;
	private ArangoDatabase db2 = null;
	private ArangoDatabaseAsync db = null;
	private HashMap<String, MadnessQuery> queries = null;

	public ArangoClient() throws Exception {
		config = ArangoConfigProperties.fromFile();

		arangoClient = new ArangoDB.Builder().loadProperties(config).protocol(Protocol.HTTP_JSON).build();
		dbs = new HashMap<String, ArangoDatabaseAsync>();
		Configurator.setLevel("com.arangodb.shaded.netty", Level.ERROR); //this quiets down a very chatty logging setup that fills up 'application.log' very fast

		List<String> availableDBs = new ArrayList<String>(arangoClient.getAccessibleDatabases());
		for (int i = 0; i < availableDBs.size(); i++) {
			String database = availableDBs.get(i);
			if (database.startsWith("_"))
				continue;
			if (this.db == null) {
				this.db2 = arangoClient.db(database);
				this.db = arangoClient.async().db(database);
			}
			this.dbs.put(database, arangoClient.async().db(database));
		}

		this.queries = new HashMap<String, MadnessQuery>();
		JSONObject queryJson = readJSONFile("data/queries.json");

		Iterator<?> queryList = queryJson.keys();
		while (queryList.hasNext()) {
			String currName = (String) queryList.next();
			MadnessQuery currQuery = new MadnessQuery(queryJson, currName);
			this.queries.put(currName, currQuery);
		}
	}

	public void selectDB(String selector) {
		this.db = this.dbs.get(selector); // throws key error.
	}

	public ArangoDatabaseAsync getCurrentDB() {
		return this.db;
	}

	public Collection<String> getAllDBs() {
		return this.dbs.keySet();
	}

	public static JSONObject readJSONFile(String absFileLocation) {
		InputStream is = ResourceManager.getResourceAsStream(absFileLocation);
		JSONObject jdata = null;
		try {
			String jsonTxt = IOUtils.toString(is, "UTF-8");
			jdata = new JSONObject(jsonTxt);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return jdata;
	}

	public int getNumberOfAvailableQueries() {
		return this.queries.size();
	}

	public List<MadnessQuery> getAvailableQueries() {
		return new ArrayList<MadnessQuery>(this.queries.values());
	}

	public MadnessQuery getQuery(String name) {
		return this.queries.containsKey(name) ? this.queries.get(name) : null;
	}

	public List<JSONObject> runQuery(String queryName, String[] params) throws Exception {
		MadnessQuery query = getQuery(queryName);
		if (query == null) {
			return null;
		}
		return query.runQuery(params, this.db2);
	}

	public void setObject(ObjectInfo obj) {
		String name = obj.getName();
		long base = obj.getBase().longValue();
		long size = obj.getSize().longValue();
		Long starttick = obj.getBirth();
		Long endtick = obj.getDeath();
		//MadnessPlugin.LOG.info("SetObject base = %x = %d\n", base, base);
		BaseDocument doc = new BaseDocument();
		String key = obj.getKey();
		doc.setKey(key);
		doc.addAttribute("name", name);
		doc.addAttribute("base", base);
		doc.addAttribute("size", size);
		doc.addAttribute("start", starttick);
		doc.addAttribute("end", endtick);

		
		try {
			this.db.collection("objects").insertDocument(doc);
		} catch (Exception e) {
			e.printStackTrace();
			//MadnessPlugin.LOG.info("SetObject UPDATING...");
			this.db.collection("objects").updateDocument(key, doc);
		}

		ObjectPhase[] timeline = obj.getTimeline();
		for(int i = 0 ; i < timeline.length; i++) {
			BaseDocument entry = new BaseDocument();
			String k = String.format("%s_%d", obj.getKey(), timeline[i].getStart());
			entry.setKey(k);
			entry.addAttribute("start", timeline[i].getStart());
			entry.addAttribute("type", timeline[i].getType().getUniversalID().toString());
			BaseEdgeDocument edge = new BaseEdgeDocument();
			edge.setFrom("objects/"+obj.getKey());
			edge.setTo("phases/"+entry.getKey());
			edge.setKey(doc.getKey() + "_" + entry.getKey());
			try {
				this.db.collection("phases").insertDocument(entry);
				this.db.collection("objectphases").insertDocument(edge);
			} catch(Exception e) {
				e.printStackTrace();
			}
		}

		// BaseEdgeDocument edge = new BaseEdgeDocument();
		// edge.setTo("types/"+"TYPE_"+typename.replaceAll("\\*",
		// "PTR").replaceAll("[^a-zA-Z0-9_]", "_"));
		// edge.setFrom("objects/"+Long.toString(base));
		// this.db.collection("hastype").insertDocument(edge);
	}
	
	public void updateObject(ObjectInfo obj) {
		try {
			String[] params = new String[] { obj.getKey() };	
			runQuery("rmobj", params);
			this.setObject(obj);
		} catch(Exception e) {
			e.printStackTrace();
			return;
		}
	}

	public void removeObject(ObjectInfo obj) {
		try {
			String[] params = new String[] { obj.getKey() };	
			runQuery("rmobj", params);
		} catch (Exception e) {
			e.printStackTrace();
			return;
		}
	}
}
