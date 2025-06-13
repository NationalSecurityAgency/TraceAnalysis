package tracemadness;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

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
import com.arangodb.entity.DocumentCreateEntity;
import com.arangodb.entity.DocumentUpdateEntity;

import ghidra.program.model.data.DataType;
import resources.ResourceManager;
import tracemadness.objectdata.ObjectInfo;
import tracemadness.objectdata.ObjectWitness;

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
		DataType ty = obj.getType();
		//MadnessPlugin.LOG.info("SetObject base = %x = %d\n", base, base);
		BaseDocument doc = new BaseDocument();
		String key = obj.getKey();
		doc.setKey(key);
		doc.addAttribute("name", name);
		doc.addAttribute("base", base);
		doc.addAttribute("size", size);
		doc.addAttribute("birth", starttick);
		doc.addAttribute("death", endtick);
		doc.addAttribute("type", ty.getUniversalID().toString());

		
		try {
			CompletableFuture<DocumentCreateEntity<Void>> f = this.db.collection("objects").insertDocument(doc);
			try {
				f.get();
			} catch(InterruptedException ie) {
				System.out.println("document creation interrupted: " + ie.getStackTrace());
			} catch(ExecutionException ee) {
				System.out.println("document creation failed: " + ee.getStackTrace());
			}
		} catch (Exception e) {
			e.printStackTrace();
			CompletableFuture<DocumentUpdateEntity<Void>> f = this.db.collection("objects").updateDocument(key, doc);
			try {
				f.get();
			} catch(InterruptedException ie) {
				System.out.println("document update interrupted: " + ie.getStackTrace());
			} catch(ExecutionException ee) {
				System.out.println("document update failed: " + ee.getStackTrace());
			}
		}
	}
	public void setWitness(ObjectWitness w) {
		System.out.println("make: " + w);
		JSONObject obj = w.toJSON();
		BaseDocument doc = new BaseDocument();
		String key = w.getKey();
		doc.setKey(key);
		for(var k : obj.keySet()) {
			doc.addAttribute(k, obj.get(k));
		}
		System.out.println("make: " + doc);
		
		
		try {
			CompletableFuture<DocumentCreateEntity<Void>> f = this.db.collection("witnesses").insertDocument(doc);
			try {
				f.get();
			} catch(InterruptedException ie) {
				System.out.println("witness creation interrupted: " + ie.getStackTrace());
			} catch(ExecutionException ee) {
				System.out.println("witness creation failed: " + ee.getStackTrace());
			}
		} catch (Exception e) {
			e.printStackTrace();
			CompletableFuture<DocumentUpdateEntity<Void>> f = this.db.collection("witnesses").updateDocument(key, doc);
			try {
				f.get();
			} catch(InterruptedException ie) {
				System.out.println("document update interrupted: " + ie.getStackTrace());
			} catch(ExecutionException ee) {
				System.out.println("document update failed: " + ee.getStackTrace());
			}
		}
	}
	public void updateWitness(ObjectWitness w) {
		removeWitness(w);
		setWitness(w);
	}
	public void removeWitness(ObjectWitness w) {
		try {
			String[] params = new String[] { w.getKey() };	
			runQuery("rmwitness", params);
		} catch (Exception e) {
			e.printStackTrace();
			return;
		}
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
