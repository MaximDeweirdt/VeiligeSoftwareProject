import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.border.Border;

public class WinkelGUI extends JFrame {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private Winkel winkel;

	public WinkelGUI(Winkel winkel) {
		this.winkel = winkel;
		init();
	}

	private void init() {
		setTitle("Winkel GUI");
		setSize(750, 500);
		setLocationRelativeTo(null);
		setDefaultCloseOperation(EXIT_ON_CLOSE);

		Container pane = getContentPane();
		JLabel winkelNaamLabel = new JLabel(winkel.getWinkelNaam());
		Border paddingBorder = BorderFactory.createEmptyBorder(10, 10, 10, 10);
		winkelNaamLabel.setFont(winkelNaamLabel.getFont().deriveFont(16f));
		winkelNaamLabel.setHorizontalAlignment(SwingConstants.CENTER);
		winkelNaamLabel.setBorder(paddingBorder);
		pane.add(winkelNaamLabel, BorderLayout.PAGE_START);
		pane.add(new NumPad(), BorderLayout.PAGE_END);

	}

	private class NumPad extends JPanel {

		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;

		StringBuffer puntenBuffer = new StringBuffer();

		int punten = 0;

		JTextField jtf = new JTextField();
		JButton b1 = new JButton("1");
		JButton b2 = new JButton("2");
		JButton b3 = new JButton("3");
		JButton b4 = new JButton("4");
		JButton b5 = new JButton("5");
		JButton b6 = new JButton("6");
		JButton b7 = new JButton("7");
		JButton b8 = new JButton("8");
		JButton b9 = new JButton("9");
		JButton b0 = new JButton("0");
		JButton bEnter = new JButton("Enter");
		JButton bTotaalKlant = new JButton("Totaal");
		JButton bClear = new JButton("Clear");
		JButton bMinus = new JButton("-");
		JButton bClown = new JButton(new ImageIcon("belangrijkeDocumenten/pepeclown.png"));
		JButton bQuit = new JButton("Quit");

		public NumPad() {

			JPanel panel1 = new JPanel(new GridLayout(4, 4));

			panel1.add(b1);
			panel1.add(b2);
			panel1.add(b3);
			panel1.add(bClear);
			panel1.add(b4);
			panel1.add(b5);
			panel1.add(b6);
			panel1.add(bTotaalKlant);
			panel1.add(b7);
			panel1.add(b8);
			panel1.add(b9);
			panel1.add(bMinus);
			panel1.add(bEnter);
			panel1.add(b0);
			panel1.add(bClown);
			panel1.add(bQuit);

			ButtonListener listener = new ButtonListener();

			b1.addActionListener(listener);
			b1.setSize(55, 55);
			b2.addActionListener(listener);
			b2.setSize(55, 55);
			b3.addActionListener(listener);
			b3.setSize(55, 55);
			b4.addActionListener(listener);
			b4.setSize(55, 55);
			b5.addActionListener(listener);
			b5.setSize(55, 55);
			b6.addActionListener(listener);
			b6.setSize(55, 55);
			b7.addActionListener(listener);
			b7.setSize(55, 55);
			b8.addActionListener(listener);
			b8.setSize(55, 55);
			b9.addActionListener(listener);
			b9.setSize(55, 55);
			b0.addActionListener(listener);
			b0.setSize(55, 55);
			bClear.addActionListener(listener);
			bClear.setSize(55, 55);
			bMinus.addActionListener(listener);
			bMinus.setSize(55, 55);
			bTotaalKlant.addActionListener(listener);
			bTotaalKlant.setSize(55, 55);
			bQuit.addActionListener(listener);
			bQuit.setSize(55, 55);
			bEnter.addActionListener(listener);
			bEnter.setSize(55, 55);

			setLayout(new BorderLayout());
			add(panel1, BorderLayout.CENTER);
			add(jtf, BorderLayout.NORTH);

			jtf.setHorizontalAlignment(SwingConstants.RIGHT);
			jtf.setPreferredSize(new Dimension(300, 30));

		}

		class ButtonListener implements ActionListener {

			@Override
			public void actionPerformed(ActionEvent e) {

				if (e.getSource() == bClear) {
					puntenBuffer = new StringBuffer();
					punten = 0;
					jtf.setText(puntenBuffer.toString());
				} else if (e.getSource() == bEnter) {
					JDialog.setDefaultLookAndFeelDecorated(true);
					int result = JOptionPane.showConfirmDialog(null, punten + " punten toevoegen bij klant?",
							"Punten toevoegen", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
					if (result == JOptionPane.YES_OPTION) {
						winkel.puntenToevoegen(punten);
					}
					puntenBuffer = new StringBuffer();
					punten = 0;
					jtf.setText(puntenBuffer.toString());
				} else if (e.getSource() == bMinus) {
					if (puntenBuffer.charAt(0) == '-') {
						puntenBuffer.deleteCharAt(0);
					} else {
						puntenBuffer.insert(0, '-');
					}
					punten = -1 * punten;
				} else if (e.getSource() == bQuit) {
					JDialog.setDefaultLookAndFeelDecorated(true);
					int result = JOptionPane.showConfirmDialog(null, "Wilt u het programma afsluiten?", "Afsluiten",
							JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
					if (result == JOptionPane.YES_OPTION) {
						System.exit(0);
					}
				} else if (e.getSource() == bTotaalKlant) {
					JDialog.setDefaultLookAndFeelDecorated(true);
					JOptionPane.showMessageDialog(null, "Hier komt dan het totaal aantal punten van de klant",
							"Totaal aantal  punten klant", JOptionPane.INFORMATION_MESSAGE);
				} else {
					puntenBuffer.append(((JButton) e.getSource()).getText());
					punten = Integer.parseInt(puntenBuffer.toString());
					jtf.setText(puntenBuffer.toString());
				}

			}

		}
	}

}
