package socketListeners;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.asn1.x9.DHPublicKey;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import main.SecurityData;
import protocols.LCPProtocol;
import socketThreads.LCPVerificationThread;
import socketThreads.RegisterThread;

public class registerSocketListenerThread extends Thread {

	private ServerSocket ss;

	public registerSocketListenerThread(int registerPort) throws IOException {
		super("registerSocketListenerThread");
		ss = new ServerSocket(registerPort);

	}

	public void run() {
		// get certificate of the card
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		String directoryNaam = "keystore";
		String bestandsNaam = "cardCert";
		try{
			KeyStore keyStore = KeyStore.getInstance("JKS");
			
			String fileName = directoryNaam + "/" + bestandsNaam + "";
			File keystoreFile = new File(fileName);
			System.out.println(keystoreFile.exists());
			
			FileInputStream in = new FileInputStream(keystoreFile);
			keyStore.load(in, "kiwikiwi".toCharArray());
			
			java.security.cert.Certificate cardCert = keyStore.getCertificate("cardCert");
	
			KeyFactory kf = KeyFactory.getInstance("EC", "BC"); 
																
			// get public key from the certificate of card
			PublicKey publicKeyCard = kf.generatePublic(new X509EncodedKeySpec(cardCert.getPublicKey().getEncoded()));
			
			ECPrivateKey privateKeyLCP = (ECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(SecurityData.privateKey));
	
			KeyAgreement keyAgreementLCP = KeyAgreement.getInstance("ECDH", "BC");
			keyAgreementLCP.init(privateKeyLCP);
			keyAgreementLCP.doPhase(publicKeyCard, true);
	
			MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
			System.out.println(new String(hash.digest(keyAgreementLCP.generateSecret())));
			
			SecretKey secretKey = keyAgreementLCP.generateSecret("DES");
			
			System.out.println("RegisterSocket Ready with secretKey");
			while (true) {
				try {
					new RegisterThread(ss.accept(), secretKey).start();
				} catch (IOException e) {
					e.printStackTrace();
				}
	
			}
		}catch(Exception e){
			e.printStackTrace();
		}
	}
}
