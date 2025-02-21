package tracemadness;

import java.util.List;

import org.json.JSONObject;

public interface MadnessQueryResultListener {
	public void queryCompleted(List<JSONObject> results, String tag);
}
