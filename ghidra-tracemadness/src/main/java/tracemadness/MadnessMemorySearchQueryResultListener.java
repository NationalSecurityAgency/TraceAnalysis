package tracemadness;

import java.util.List;

import tracemadness.memindex.MemorySearchResult;

public interface MadnessMemorySearchQueryResultListener {
	public void queryCompleted(List<MemorySearchResult> results, String tag);
}
