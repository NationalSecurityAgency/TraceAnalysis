package tracemadness.settings;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSpinner;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.ComponentProvider;
import docking.Tool;
import ghidra.app.plugin.core.colorizer.ColorizingService;

public class SettingsProvider extends ComponentProvider {

	private List<Setting> settings;
	private JComponent component;
	private Tool tool;

	public SettingsProvider(Tool tool, String name, String owner, List<Setting> settings) {
		super(tool, name, owner);
		this.tool = tool;
		this.settings = settings;
		this.component = buildPanel();
	}

	@Override
	public JComponent getComponent() {
		return this.component;
	}

	private JPanel buildPanel() {
		JPanel mainPanel = new JPanel(new GridLayout(0, 1));
		List<JComponent> individualSettingDisplays = new ArrayList<JComponent>();

		this.settings.sort(new Comparator<Setting>() {
			@Override
			public int compare(Setting a, Setting b) {
				return a.getName().compareTo(b.getName());
			}
		});

		for (final Setting setting : this.settings) {

			JPanel settingComponent = new JPanel(new BorderLayout());
			settingComponent.add(new JLabel(setting.getName() + ": "), BorderLayout.WEST);
			JComponent settingInput = new JPanel();

			switch (setting.getType()) {

			case INT_TYPE:
				Integer intValue = (Integer) setting.getValue();
				if (intValue == null)
					intValue = 0;

				SpinnerNumberModel intModel = new SpinnerNumberModel((int) intValue, Integer.MIN_VALUE,
						Integer.MAX_VALUE, 1);
				final JSpinner intInput = new JSpinner(intModel);
				intInput.addChangeListener(new ChangeListener() {
					@Override
					public void stateChanged(ChangeEvent e) {
						setting.setValue((int) intInput.getValue());
					}
				});
				settingInput = intInput;
				break;

			case DOUBLE_TYPE:
				Double doubleValue = (Double) setting.getValue();
				if (doubleValue == null)
					doubleValue = 0.0;

				SpinnerNumberModel doubleModel = new SpinnerNumberModel((double) doubleValue, -Double.MAX_VALUE,
						Double.MAX_VALUE, 0.01);
				final JSpinner doubleInput = new JSpinner(doubleModel);
				doubleInput.addChangeListener(new ChangeListener() {
					@Override
					public void stateChanged(ChangeEvent e) {
						setting.setValue((double) doubleInput.getValue());
					}
				});
				settingInput = doubleInput;
				break;

			case STRING_TYPE:
				final JTextField stringInput = new JTextField((String) setting.getValue());
				stringInput.getDocument().addDocumentListener(new DocumentListener() {
					@Override
					public void changedUpdate(DocumentEvent e) {
						setting.setValue(stringInput.getText());
					}

					@Override
					public void insertUpdate(DocumentEvent e) {
						changedUpdate(e);
					}

					@Override
					public void removeUpdate(DocumentEvent e) {
						changedUpdate(e);
					}
				});
				settingInput = stringInput;
				break;

			case BOOLEAN_TYPE:
				boolean boolValue = false;
				if (setting.getValue() != null && (boolean) setting.getValue() == true) {
					boolValue = true;
				}

				final JCheckBox booleanInput = new JCheckBox();
				booleanInput.setSelected(boolValue);
				booleanInput.addActionListener(new ActionListener() {
					@Override
					public void actionPerformed(ActionEvent e) {
						if (booleanInput.isSelected()) {
							setting.setValue(true);
						} else {
							setting.setValue(false);
						}
					}
				});
				settingInput = booleanInput;
				break;

			case COLOR_TYPE:
				final JPanel colorInput = new JPanel(new BorderLayout());
				final JLabel colorLabel = new JLabel("          ");
				colorLabel.setOpaque(true);
				Color currColorValue = (Color) setting.getValue();
				if (currColorValue != null) {
					colorLabel.setBackground(currColorValue);
				}

				final JButton colorButton = new JButton("Select Color");
				colorButton.addActionListener(new ActionListener() {
					@Override
					public void actionPerformed(ActionEvent e) {
						Color colorValue = tool.getService(ColorizingService.class).getColorFromUser(null);
						setting.setValue(colorValue);
						colorLabel.setBackground(colorValue);
					}
				});

				colorInput.add(colorLabel, BorderLayout.WEST);
				colorInput.add(colorButton, BorderLayout.CENTER);
				settingInput = colorInput;
				break;

			default:
				// Unsupported type
				break;
			}

			settingComponent.add(settingInput, BorderLayout.CENTER);
			individualSettingDisplays.add(settingComponent);
		}

		for (JComponent settingComponent : individualSettingDisplays) {
			mainPanel.add(settingComponent);
		}

		return mainPanel;
	}
}
