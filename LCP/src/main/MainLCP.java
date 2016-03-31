package main;

import java.io.File;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import java.security.cert.Certificate;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import socketListeners.RegisterSocketListenerThread;
import socketListeners.VerificationSocketListenerThread;

public class MainLCP {
	
	private static ECPrivateKey privateKeyLCP;
	private static ECPublicKey publicKeyLCP;
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
		setPublicKeyLCP((ECPublicKey) kf.generatePublic(new X509EncodedKeySpec(main.SecurityData.publicKey)));
		
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
															
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		KeyAgreement keyAgreementLCP = KeyAgreement.getInstance("ECDH", "BC");
		ECPublicKey cardPublicKey = (ECPublicKey)  kf.generatePublic(new X509EncodedKeySpec(MainLCP.getCardCert().getPublicKey().getEncoded()));
		
		keyAgreementLCP.init(MainLCP.getPrivateKeyLCP());
		keyAgreementLCP.doPhase(cardPublicKey, true);

		MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
		byte[] hashKey = hash.digest(keyAgreementLCP.generateSecret());
		
		SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
		DESKeySpec desSpec = new DESKeySpec(hashKey);
		SecretKey secretKey = skf.generateSecret(desSpec);
		
		System.out.println("symmetric key with card = " + new BigInteger(1,secretKey.getEncoded()).toString(16));
		
	}


	public static ECPrivateKey getPrivateKeyLCP() {
		return privateKeyLCP;
	}


	public static void setPrivateKeyLCP(ECPrivateKey privateKeyLCP) {
		MainLCP.privateKeyLCP = privateKeyLCP;
	}


	public static ECPublicKey getPublicKeyLCP() {
		return publicKeyLCP;
	}


	public static void setPublicKeyLCP(ECPublicKey publicKeyLCP) {
		MainLCP.publicKeyLCP = publicKeyLCP;
	}


	public static Certificate getCardCert() {
		return cardCert;
	}


	public static void setCardCert(Certificate cardCert) {
		MainLCP.cardCert = cardCert;
	}
}
		

