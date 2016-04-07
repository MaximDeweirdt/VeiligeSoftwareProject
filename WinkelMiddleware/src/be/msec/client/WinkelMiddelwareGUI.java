package be.msec.client;

import java.awt.Color;
import java.awt.Container;
import java.awt.Dimension;

import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

public class WinkelMiddelwareGUI extends JFrame{
	
	private static JTextArea area;
	private JScrollPane scrollPane;
	
	public WinkelMiddelwareGUI() {
		area = new JTextArea();
		scrollPane = new JScrollPane(area);
		setTitle("WinkelmiddelwareGUI");
		setSize(400, 400);
		setLocationRelativeTo(null);
		setDefaultCloseOperation(EXIT_ON_CLOSE);
		Container pane = getContentPane();
		scrollPane.setPreferredSize(new Dimension(385, 385));
		area.setEditable(false);
		area.setDisabledTextColor(Color.BLACK);
		area.setLineWrap(true);
		area.setWrapStyleWord(true);
		pane.add(scrollPane);
		setVisible(true);
	}
	
	public static void addText(String text){
		area.append(text+"\n");
	}
	
	
	
	

}
