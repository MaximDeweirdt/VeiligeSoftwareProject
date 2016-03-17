import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class Winkel {
	
	private KeyStore keyStore;
	private String winkelNaam;
	private String filePadTotKeyStore;
	
	public Winkel(String winkelNaam, String filePadTotKeyStore){
		this.winkelNaam = winkelNaam;
		this.filePadTotKeyStore = filePadTotKeyStore;
	}
	
	protected void loadKeyStore(char[] paswoordVoorKeyStore)
			throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException{
		
		keyStore = KeyStore.getInstance("JKS");
		FileInputStream inputStream = new FileInputStream(new File(filePadTotKeyStore));
		keyStore.load(inputStream, paswoordVoorKeyStore);
		inputStream.close();
	}
	
	

}
