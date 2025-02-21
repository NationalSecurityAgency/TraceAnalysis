package tracemadness.timelisting;

import java.awt.Color;

import generic.theme.GColor;

public class TimeListingSettings {
	// TODO expose these as settings or get them from the ghidra theme or something
	public static final int MAX_WIDTH = 2800;
	public static final int DISAS_FIELD_WIDTH = 400;
	public static final int PC_FIELD_WIDTH = 180;
	public static final int FN_OFFSET_FIELD_WIDTH = 250;
	public static final int TICK_FIELD_WIDTH = 100;
	public static final int PAD_WIDTH = 10;
	public static final Color PC_COLOR = Color.BLUE;
	public static final Color TICK_COLOR = Color.RED;
	public static final Color DISAS_COLOR = Color.BLACK;
	public static final Color OP_COLOR = Color.BLACK;
	public static final Color CURSOR_HIGHLIGHT_COLOR = new GColor("color.bg.currentline.listing");
	public static final int TIME_WINDOW_RADIUS = 1000;
	public static final Color BACKGROUND_COLOR = Color.WHITE;
}
