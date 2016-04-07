import java.awt.Color;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.text.DefaultCaret;

public class WinkelGUI extends JFrame {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private JScrollPane scrollPane;
	private static JTextArea area;
	private Winkel winkel;

	public WinkelGUI(Winkel winkel) {
		this.winkel = winkel;
		area = new JTextArea();
		scrollPane = new JScrollPane(area);
		init();
	}

	private void init() {
		setTitle(winkel.getWinkelNaam());
		setSize(400, 400);
		setLocationRelativeTo(null);
		setDefaultCloseOperation(EXIT_ON_CLOSE);
		Container pane = getContentPane();
		pane.setLayout(new FlowLayout());
		scrollPane.setPreferredSize(new Dimension(385, 385));
		area.setEditable(false);
		area.setDisabledTextColor(Color.BLACK);
		area.setLineWrap(true);
		area.setWrapStyleWord(true);
		pane.add(scrollPane);

	}

	public static short promptForThemPoints(short nPoints) {
		JDialog.setDefaultLookAndFeelDecorated(true);
		String punten = JOptionPane.showInputDialog(null,
				"Klant heeft " + nPoints + " momenteel. Geef het aantal punten in dat toegevoegd moet worden.",
				"Punten", JOptionPane.QUESTION_MESSAGE);
		return Short.parseShort(punten);
	}
	
	public static void addText(String text){
		area.append(text+"\n");
	}

}
