package gui;

import java.awt.Color;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.text.SimpleDateFormat;

import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

public class LCPGui extends JFrame{
	
	private JScrollPane scrollPane;
	private static JTextArea area;
	
	public LCPGui() {
		area = new JTextArea("Dit is de interface van de LCP.\n");
		scrollPane = new JScrollPane(area);
		init();
	}
	
	private void init(){
		setTitle("LCP");
		setSize(400, 400);
		setLocationRelativeTo(null);
		Container pane = getContentPane();
		pane.setLayout(new FlowLayout());
		area.setEditable(false);
		area.setDisabledTextColor(Color.black);
		area.setLineWrap(true);
		area.setWrapStyleWord(true);
		scrollPane.setPreferredSize(new Dimension(385, 385));
		pane.add(scrollPane);
		setVisible(true);
	}
	
	public static void addText(String text){
		area.append(text+"\n");
	}

}
