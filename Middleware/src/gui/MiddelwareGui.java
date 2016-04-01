package gui;

import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

public class MiddelwareGui extends JFrame {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private static final int ENTER_PIN = 0;
	private static final int ENTER_STORE = 1;
	private int state;
	private boolean entered;
	private JTextArea area;
	private JScrollPane scrollPane;

	private String input;

	public MiddelwareGui() {
		input = new String();
		area = new JTextArea("Please enter PIN.\n");
		scrollPane = new JScrollPane(area);
		state = 0;
		entered = false;
		init();

	}

	private void init() {
		setTitle("Middelware");
		setSize(1000, 750);
		setLocationRelativeTo(null);
		setDefaultCloseOperation(EXIT_ON_CLOSE);

		Container pane = getContentPane();
		pane.setLayout(new FlowLayout());
		pane.add(new NumPad());
		scrollPane.setPreferredSize(new Dimension(400, 400));
		pane.add(scrollPane);
	}

	private class NumPad extends JPanel {

		private static final long serialVersionUID = 1L;
		private StringBuffer buffer;

		private JPanel numpadPanel;
		private JTextField jtf;

		private JButton b0 = new JButton("0");
		private JButton b1 = new JButton("1");
		private JButton b2 = new JButton("2");
		private JButton b3 = new JButton("3");
		private JButton b4 = new JButton("4");
		private JButton b5 = new JButton("5");
		private JButton b6 = new JButton("6");
		private JButton b7 = new JButton("7");
		private JButton b8 = new JButton("8");
		private JButton b9 = new JButton("9");
		private JButton correction = new JButton("Corr");
		private JButton stop = new JButton("Stop");
		private JButton enter = new JButton("Enter");
		private JButton fill1 = new JButton();
		private JButton fill2 = new JButton();
		private JButton fill3 = new JButton();

		public NumPad() {
			buffer = new StringBuffer();

			jtf = new JTextField("PIN");
			numpadPanel = new JPanel(new GridLayout(4, 4));
			numpadPanel.setSize(new Dimension(200, 200));

			fill1.setEnabled(false);
			fill2.setEnabled(false);
			fill3.setEnabled(false);

			numpadPanel.add(b1);
			numpadPanel.add(b2);
			numpadPanel.add(b3);
			numpadPanel.add(correction);
			numpadPanel.add(b4);
			numpadPanel.add(b5);
			numpadPanel.add(b6);
			numpadPanel.add(stop);
			numpadPanel.add(b7);
			numpadPanel.add(b8);
			numpadPanel.add(b9);
			numpadPanel.add(enter);
			numpadPanel.add(fill1);
			numpadPanel.add(b0);
			numpadPanel.add(fill2);
			numpadPanel.add(fill3);

			ButtonListener listener = new ButtonListener();

			b1.addActionListener(listener);
			b2.addActionListener(listener);
			b3.addActionListener(listener);
			correction.addActionListener(listener);
			b4.addActionListener(listener);
			b5.addActionListener(listener);
			b6.addActionListener(listener);
			stop.addActionListener(listener);
			b7.addActionListener(listener);
			b8.addActionListener(listener);
			b9.addActionListener(listener);
			enter.addActionListener(listener);

			setLayout(new BorderLayout());
			add(numpadPanel, BorderLayout.CENTER);
			add(jtf, BorderLayout.NORTH);

			jtf.setHorizontalAlignment(SwingConstants.RIGHT);
			jtf.setPreferredSize(new Dimension(300, 30));

		}

		class ButtonListener implements ActionListener {

			@Override
			public void actionPerformed(ActionEvent arg0) {

				if (arg0.getSource() == correction) {
					buffer.deleteCharAt(buffer.length() - 1);
					jtf.setText(buffer.toString());
				} else if (arg0.getSource() == stop) {
					JDialog.setDefaultLookAndFeelDecorated(true);
					int result = JOptionPane.showConfirmDialog(null, "Wilt u het programma afsluiten?", "Afsluiten",
							JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
					if (result == JOptionPane.YES_OPTION) {
						System.exit(0);
					}
				} else if (arg0.getSource() == enter) {
					if (state == ENTER_PIN) {
						input = buffer.toString();
						if (input.length() != 4) {
							buffer.setLength(0);
							JDialog.setDefaultLookAndFeelDecorated(true);
							JOptionPane.showMessageDialog(null, "Ingegeven PIN is te kort.", "PIN te kort.",
									JOptionPane.OK_OPTION);
							jtf.setText("PIN");
							area.append("PIN te kort.\n");
						} else {
							state = ENTER_STORE;
							entered = true;
							
						}
					}
				} else {
					buffer.append(((JButton) arg0.getSource()).getText());
					jtf.setText(buffer.toString());
				}

			}

		}

	}

	public String getPin() {
		while (!entered) {

		}
		entered = false;
		return input;
	}

}
