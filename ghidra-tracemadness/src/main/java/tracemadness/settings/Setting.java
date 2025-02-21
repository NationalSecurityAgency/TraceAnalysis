package tracemadness.settings;

import java.awt.Color;

import docking.Tool;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;

public class Setting {

	private String name;
	private OptionType type;
	private Tool tool;

	public Setting(String _name, OptionType _type, PluginTool _tool) {
		this.name = _name;
		this.type = _type;
		this.tool = _tool;

		Options options = this.tool.getOptions("TraceAnalysis");
		if (!options.contains(this.name)) {
			options.registerOption(this.name, this.type, null, null, this.name);
		}
	}

	public String getName() {
		return this.name;
	}

	public OptionType getType() {
		return this.type;
	}

	public Object getValue() {
		Options options = this.tool.getOptions("TraceAnalysis");
		Object value = options.getObject(this.name, null);
		return value;
	}

	public void setValue(Object value) {
		Options options = this.tool.getOptions("TraceAnalysis");
		switch (this.type) {
		case INT_TYPE:
			options.setInt(this.name, (int) value);
			break;
		case DOUBLE_TYPE:
			options.setDouble(this.name, (double) value);
			break;
		case STRING_TYPE:
			options.setString(this.name, (String) value);
			break;
		case BOOLEAN_TYPE:
			options.setBoolean(this.name, (boolean) value);
			break;
		case COLOR_TYPE:
			options.setColor(this.name, (Color) value);
			break;
		default:
			// Unsupported type
			break;
		}
	}

}
