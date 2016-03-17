import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.HeadlessException;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;

public class WinkelGUI extends JFrame {

	private Winkel winkel;

	public WinkelGUI(Winkel winkel) throws HeadlessException {
		super();
		this.winkel = winkel;
		init();
	}

	private void init() {
		setTitle("Winkel GUI");
		setSize(750, 500);
		setLocationRelativeTo(null);
		setDefaultCloseOperation(EXIT_ON_CLOSE);
		
	}
	
	private class NumPad extends JPanel {

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

		    // add listener to all buttons

		    setLayout(new BorderLayout());
		    add(panel1, BorderLayout.CENTER);
		    add(jtf, BorderLayout.NORTH);

		    jtf.setHorizontalAlignment(SwingConstants.RIGHT);
		    jtf.setPreferredSize(new Dimension(300, 30));

		}

		

		class ButtonListener implements ActionListener {

		    @Override
		    public void actionPerformed(ActionEvent e) {

		    }

		}
	}
	
	private JPanel createNumPad(){
		
		JPanel panel = new NumPad();
		return panel;
		
	}

}
