package main;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.cert.Certificate;

import org.bouncycastle.jce.interfaces.ECPrivateKey;

import socketListeners.RegisterSocketListenerThread;
import socketListeners.VerificationSocketListenerThread;

public class MainLCP {
	
	private static ECPrivateKey privateKeyLCP;
	private static PublicKey publicKeyLCP;
	private static Certificate cardCert;
	public static void main(String[] args) throws Exception {
		
		
		makeKeysAndCerts();
//		winkelDataList = makeWinkelData();
		
		int registerPort = 4443; // Port where the SSL Server needs to listen for new requests from the client
		int verificationPort = 4444;
		
		
		new RegisterSocketListenerThread(registerPort).start();
		new VerificationSocketListenerThread(verificationPort).start();
		
	}


	private static void makeKeysAndCerts() throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		KeyFactory kf = KeyFactory.getInstance("EC", "BC"); 
		
		// get public key and private key
		setPublicKeyLCP(kf.generatePublic(new X509EncodedKeySpec(main.SecurityData.publicKey)));
		
		setPrivateKeyLCP((ECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(main.SecurityData.privateKey)));
		
		KeyStore keyStore = KeyStore.getInstance("JKS");
		String directoryNaam = "keystore";
		String bestandsNaam = "cardCert";
		
		String fileName = directoryNaam + "/" + bestandsNaam + "";
		File keystoreFile = new File(fileName);
		System.out.println(keystoreFile.exists());
		
		FileInputStream keyIn = new FileInputStream(keystoreFile);
		keyStore.load(keyIn, "kiwikiwi".toCharArray());
		
		setCardCert(keyStore.getCertificate("cardCert"));
															
		
	}


	public static ECPrivateKey getPrivateKeyLCP() {
		return privateKeyLCP;
	}


	public static void setPrivateKeyLCP(ECPrivateKey privateKeyLCP) {
		MainLCP.privateKeyLCP = privateKeyLCP;
	}


	public static PublicKey getPublicKeyLCP() {
		return publicKeyLCP;
	}


	public static void setPublicKeyLCP(PublicKey publicKeyLCP) {
		MainLCP.publicKeyLCP = publicKeyLCP;
	}


	public static Certificate getCardCert() {
		return cardCert;
	}


	public static void setCardCert(Certificate cardCert) {
		MainLCP.cardCert = cardCert;
	}
}
		

