package gui;

import java.awt.BorderLayout;
import java.awt.Color;
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

import be.msec.client.Client;

public class MiddelwareGui extends JFrame {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private static final int ENTER_PIN = 100;
	private static final int ENTER_STORE = 101;

	private static final String PIN_INVALID_MSG_TITLE = "PIN invalid!";
	private static final String STOREID_INVALID_TITLE = "Winkel ID invalid!";
	private static final String QUIT_TITLE = "Afsluiten";
	private static final String PIN_INVALID_MSG_1 = "Er werd een foute PIN ingegeven. Nog 2 pogingen resterend";
	private static final String PIN_INVALID_MSG_2 = "Er werd terug een foute PIN ingegeven. Nog 1 poging restered. Indien nogmaals een foute PIN ingegeven wordt, zal de account verwijderd worden!";
	private static final String PIN_INVALID_MSG_3 = "Er werd tot driemaal toe een foute PIN ingegeven. Uw account is verwijderd, gelieve contact op te nemen met uw LCP.";
	private static final String STOREID_INVALID = "Het ingegeven winkel nummer werd niet terug gevonden. Probeer een ander nummer";
	private static final String QUIT = "Wilt u het programma afsluiten?";

	private JTextArea area;
	private JScrollPane scrollPane;
	private Client client;
	private NumPad numpad;

	public MiddelwareGui(Client client) {
		this.client = client;
		area = new JTextArea("Please enter PIN.\n");
		area.setEnabled(false);
		area.setDisabledTextColor(Color.black);
		scrollPane = new JScrollPane(area);
		numpad = new NumPad();
		init();

	}

	private void init() {
		setTitle("Middelware");
		setSize(1000, 550);
		setLocationRelativeTo(null);
		setDefaultCloseOperation(EXIT_ON_CLOSE);

		Container pane = getContentPane();
		pane.setLayout(new FlowLayout());
		pane.add(numpad);
		scrollPane.setPreferredSize(new Dimension(650, 500));
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
			numpadPanel.setSize(new Dimension(300, 300));

			fill1.setEnabled(false);
			fill2.setEnabled(false);
			fill3.setEnabled(false);

			correction.setBackground(Color.YELLOW);
			stop.setBackground(Color.RED);
			enter.setBackground(Color.GREEN);

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
			b0.addActionListener(listener);

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
					int result = JOptionPane.showConfirmDialog(null, QUIT, QUIT_TITLE, JOptionPane.YES_NO_OPTION,
							JOptionPane.QUESTION_MESSAGE);
					if (result == JOptionPane.YES_OPTION) {
						try {
							client.closeConnections();
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
						System.exit(0);
					}
				} else if (arg0.getSource() == enter) {

					if (client.getState() == ENTER_PIN) {

						try {
							pinProcedure(buffer.toString());
						} catch (Exception e) {
							e.printStackTrace();
						}

					} else if (client.getState() == ENTER_STORE) {

						short storeID = Short.parseShort(buffer.toString());

						if (!client.validStore(storeID)) {
							clearBuffer();
							setTextOfField("Winkel nummer");
							JDialog.setDefaultLookAndFeelDecorated(true);
							JOptionPane.showMessageDialog(null, STOREID_INVALID, STOREID_INVALID_TITLE,
									JOptionPane.ERROR_MESSAGE);
						} else {
							try {
								client.addStoreProcedure(storeID);
							} catch (Exception e) {
								try {
									client.closeConnections();
								} catch (Exception e1) {
									// TODO Auto-generated catch block
									e1.printStackTrace();
								}
								e.printStackTrace();
							}
						}

					}

				} else {
					buffer.append(((JButton) arg0.getSource()).getText());
					jtf.setText(buffer.toString());
				}
			}
		}

		public void clearBuffer() {
			buffer.setLength(0);
		}

		public void setTextOfField(String text) {
			jtf.setText(text);
		}

	}

	private void pinProcedure(String pin) throws Exception {

		numpad.clearBuffer();
		numpad.setTextOfField("PIN");

		try {
			client.loginCard(pin);
		} catch (Exception e) {
			e.printStackTrace();
		}
		if (client.getPinTries() == 1 && !client.pinValid()) {

			JDialog.setDefaultLookAndFeelDecorated(true);
			JOptionPane.showMessageDialog(null, PIN_INVALID_MSG_1, PIN_INVALID_MSG_TITLE, JOptionPane.ERROR_MESSAGE);
		} else if (client.getPinTries() == 2 && !client.pinValid()) {
			JDialog.setDefaultLookAndFeelDecorated(true);
			JOptionPane.showMessageDialog(null, PIN_INVALID_MSG_2, PIN_INVALID_MSG_TITLE, JOptionPane.ERROR_MESSAGE);
		} else if (client.getPinTries() == 3 && !client.pinValid()) {
			JDialog.setDefaultLookAndFeelDecorated(true);
			JOptionPane.showMessageDialog(null, PIN_INVALID_MSG_3, PIN_INVALID_MSG_TITLE, JOptionPane.ERROR_MESSAGE);
		} else {
			client.resetPinTries();
			client.keyAgreementLCPAndCard();
			client.requestCertificate();
			if (client.isCorrectCardCert()) {
				numpad.setTextOfField("Winkel nummer");
			}
		}

	}

	public void addText(String text) {
		area.append(text + "\n");
	}

}
