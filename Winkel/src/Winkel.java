import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class Winkel {
	
	private String winkelNaam;
	
	public Winkel(String winkelNaam){
		this.winkelNaam = winkelNaam;
	}
	
	public String getWinkelNaam() {
		return winkelNaam;
	}
	
	public void puntenToevoegen(int punten){
		System.out.println("Er worden " + punten + " punten toegevoegd");
	}
	
	public void startGUI(){
		WinkelGUI gui = new WinkelGUI(this);
		gui.setVisible(true);
	}

}
