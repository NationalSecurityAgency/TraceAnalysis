package tracemadness;

import java.util.List;

import org.json.JSONObject;

import tracemadness.memindex.MemorySearchResult;

public interface MadnessMemorySearchQueryResultListener {
	public void queryCompleted(List<MemorySearchResult> results, String tag);
}
