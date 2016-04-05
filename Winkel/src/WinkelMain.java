import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;

public class WinkelMain {

	private static ECPrivateKey privateKeyWinkel;
	private static ECPublicKey publicKeyWinkel;
	private static ECPublicKey publicKeyLCP;
	private static X509Certificate winkelCert;
	private static Winkel winkel;
	public static int winkelNummer;
	private static final char [] KEYSTOREPASWOORD = "kiwikiwi".toCharArray();
	
	
	
	private static final Scanner SCANNER = new Scanner(System.in);
	
	private static final String ALIENWARE_NAME = "Alienware";
	private static final String COLRUYT_NAME = "Colruyt";
	private static final String DELHAIZE_NAME = "Delhaize";
	private static final String RAZOR_NAME = "Razor";
	
	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {


		System.out.println("Geef het nummer van de winkel.");
		System.out.println("Colruyt    \t0\nDelhaize\t1\nAlienware\t2\nRazor      \t3");

		// Inlezen van het winkelnummer
		// Dit blijft gebeuren dat het winkelnummer een aanvaardbaar nummer is
		// (nummer tussen 1-4).
		winkelNummer = Integer.parseInt(SCANNER.nextLine());
		
		while (winkelNummer < 0 || winkelNummer > 3) {
			System.err.println("Het ingegeven winkelnummer is niet correct");
			winkelNummer = Integer.parseInt(SCANNER.nextLine());
		}

		// Een juist winkel object maken op basis van het ingelezen winkelnummer.
		// Default wordt Alienware gemaakt.
		
		switch (winkelNummer) {
		case 0:
			winkel = new Winkel(COLRUYT_NAME);
			break;
		case 1:
			winkel = new Winkel(DELHAIZE_NAME);
		case 2:
			winkel = new Winkel(ALIENWARE_NAME);
			break;
		case 3:
			winkel = new Winkel(RAZOR_NAME);
			break;
		default:
			System.err.println("Er ging iets mis bij het laden van de keystores: " + WinkelMain.class);
			System.err.println("De keystore van de winkel Alienware wordt default ingeladen. FEELSBADMAN");
			winkel = new Winkel(ALIENWARE_NAME);
			break;
		}
		makeKeysAndCerts(winkelNummer);
		winkel.startGUI();
		
		int portNumber = 5000+winkelNummer;
		
		ServerSocket ss = new ServerSocket(portNumber);
		System.out.println("RegisterSocket Ready");
		while (true) {
			try {
				new WinkelThread(ss.accept()).start();
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
	}
	
	private static void makeKeysAndCerts(int winkelNummer) throws Exception {
		
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		KeyFactory kf = KeyFactory.getInstance("EC", "BC"); 
		
		// get public key and private key
		setPublicKeyWinkel((ECPublicKey) kf.generatePublic(new X509EncodedKeySpec(SecurityData.getPublicKey(winkelNummer))));
		
		setPrivateKeyWinkel((ECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(SecurityData.getPrivateKey(winkelNummer))));
		
		setPublicKeyLCP((ECPublicKey) kf.generatePublic(new X509EncodedKeySpec(SecurityData.getPublickeylcp())));
	
		KeyStore keyStore = KeyStore.getInstance("JKS");
		String directoryNaam =  "keystore";
		String bestandsNaam;
		String fileName;
		File keystoreFile;
		FileInputStream keyIn;
		switch(winkelNummer){
		case 0: 
			bestandsNaam = "Colruytcert";
			fileName = directoryNaam + "/" + bestandsNaam + "";
			keystoreFile = new File(fileName);
			System.out.println(keystoreFile.exists());
			
			keyIn = new FileInputStream(keystoreFile);
			keyStore.load(keyIn, "kiwikiwi".toCharArray());
			setWinkelCert((X509Certificate)keyStore.getCertificate("Colruytcert"));
			break;
		case 1:
			bestandsNaam = "DelhaizeCert";
			fileName = directoryNaam + "/" + bestandsNaam + "";
			keystoreFile = new File(fileName);
			System.out.println(keystoreFile.exists());
			
			keyIn = new FileInputStream(keystoreFile);
			keyStore.load(keyIn, "kiwikiwi".toCharArray());
			setWinkelCert((X509Certificate)keyStore.getCertificate("DelhaizeCert"));
		}	
		
	}

	public static ECPrivateKey getPrivateKeyWinkel() {
		return privateKeyWinkel;
	}

	public static void setPrivateKeyWinkel(ECPrivateKey privateKeyWinkel) {
		WinkelMain.privateKeyWinkel = privateKeyWinkel;
	}

	public static ECPublicKey getPublicKeyWinkel() {
		return publicKeyWinkel;
	}

	public static void setPublicKeyWinkel(ECPublicKey publicKeyWinkel) {
		WinkelMain.publicKeyWinkel = publicKeyWinkel;
	}

	public static ECPublicKey getPublicKeyLCP() {
		return publicKeyLCP;
	}

	public static void setPublicKeyLCP(ECPublicKey publicKeyLCP) {
		WinkelMain.publicKeyLCP = publicKeyLCP;
	}

	public static X509Certificate getWinkelCert() {
		return winkelCert;
	}

	public static void setWinkelCert(X509Certificate winkelCert) {
		WinkelMain.winkelCert = winkelCert;
	}

}
