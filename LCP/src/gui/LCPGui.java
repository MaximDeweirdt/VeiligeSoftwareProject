package gui;

import java.awt.Color;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.math.BigInteger;
import java.security.cert.X509Certificate;

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.plaf.basic.BasicListUI.ListSelectionHandler;
import javax.swing.table.DefaultTableModel;

import main.MainLCP;

public class LCPGui extends JFrame {

	private JScrollPane areaScrollPane;
	private JScrollPane tableScrollPane;
	private static JTextArea area;
	private static JTable certTable;

	private static final String[] COLUMNNAMES = { "Name", "Serialnumber", "Valid" };

	public LCPGui() {
		area = new JTextArea("Dit is de interface van de LCP.\n");
		certTable = new JTable(new DefaultTableModel(COLUMNNAMES, 0));
		areaScrollPane = new JScrollPane(area);
		tableScrollPane = new JScrollPane(certTable);
		init();
	}

	private void init() {
		setTitle("LCP");
		setSize(800, 450);
		setLocationRelativeTo(null);
		Container pane = getContentPane();
		pane.setLayout(new FlowLayout());
		area.setEditable(false);
		area.setDisabledTextColor(Color.black);
		area.setLineWrap(true);
		area.setWrapStyleWord(true);
		certTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		certTable.getSelectionModel().addListSelectionListener(selectionEvent -> {
			if (!selectionEvent.getValueIsAdjusting()
					&& selectionEvent.getSource().equals(certTable.getSelectionModel())) {
				int row = certTable.getSelectedRow();
				System.out.println("Row index: " + row);
				if (row >= 0) {
					String certName = (String) certTable.getModel().getValueAt(row, 0);
					JDialog.setDefaultLookAndFeelDecorated(true);
					int result = JOptionPane.showConfirmDialog(null,
							"Wilt u het certificaat van " + certName + " ongeldig maken?",
							"Certificaat ongelidg maken.", JOptionPane.YES_NO_CANCEL_OPTION,
							JOptionPane.QUESTION_MESSAGE);
					if (result == JOptionPane.YES_OPTION) {
						BigInteger serienummer = new BigInteger((String) certTable.getModel().getValueAt(row, 1));
						X509Certificate cert = MainLCP.getCert(serienummer);
						MainLCP.invalidateCert(cert);
						certTable.getModel().setValueAt("" + MainLCP.certIsValid(serienummer), row, 2);
						DefaultTableModel model = (DefaultTableModel) certTable.getModel();
						model.fireTableDataChanged();
					}
				}
			}
		});
		areaScrollPane.setPreferredSize(new Dimension(385, 385));
		tableScrollPane.setPreferredSize(new Dimension(385, 385));
		pane.add(areaScrollPane);
		pane.add(tableScrollPane);
		setVisible(true);
	}

	public static void addText(String text) {
		area.append(text + "\n");
	}

	public static void addCertToTable(Object[] row) {
		DefaultTableModel model = (DefaultTableModel) certTable.getModel();
		model.addRow(row);
		model.fireTableDataChanged();
	}

}
