package protocols;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.util.encoders.Base64;


public class RegisterProtocol {
	
	private SecretKey secretKey;
	private Cipher aesCipher;
	
	public static final int TESTCONNECTIONSTATE = -1;
	public static final int KIESWINKELSTATE = 0;
	
	int state = TESTCONNECTIONSTATE;
	
	public RegisterProtocol(SecretKey secretKey){
		this.secretKey = secretKey;
	}
	
	public byte[] processInput(Object theInput) throws Exception {

		byte[] theOutput = null;
		
		
		
		byte[] input = (byte[]) theInput;
		
		System.out.println("Input: " +Base64.encode(input));
		
		byte[] decryptedInput = decryptInput(input);
		
		if(theInput != null && theInput.toString().equals("close connection")){
			theOutput = Base64.decode("Bye");
		}
		else if (state == TESTCONNECTIONSTATE){
			System.out.println("decrypted input: " + Base64.encode(decryptedInput));
			theOutput =  Base64.decode("test test");
		}
		else if (state == KIESWINKELSTATE){
			switch(decryptedInput.toString()){
			case "1": 
				System.out.println("winkel 1 gekozen");
				break;
			case "2":
				System.out.println("winkel 2 gekozen");
				break;
			default: theOutput =  Base64.decode("Bye");
			}
			
		}
		
		return encryptOutput(theOutput);
	}

	private byte[] decryptInput(byte[] theInput) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		// Create the cipher
		KeyStore keyStore = KeyStore.getInstance("JKS");
		String directoryNaam = "keystore";
		String bestandsNaam = "cardCert";
		
		String fileName = directoryNaam + "/" + bestandsNaam + "";
		File keystoreFile = new File(fileName);
		System.out.println(keystoreFile.exists());
		
		FileInputStream keyIn = new FileInputStream(keystoreFile);
		keyStore.load(keyIn, "kiwikiwi".toCharArray());
		
		java.security.cert.Certificate LCPCert = keyStore.getCertificate("cardCert");

		KeyFactory kf = KeyFactory.getInstance("EC", "BC"); 
															
		// get public key from the certificate of card
		PublicKey publicKeyLCP = kf.generatePublic(new X509EncodedKeySpec(LCPCert.getPublicKey().getEncoded()));
		
		ECPrivateKey privateKeyCard = (ECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(main.SecurityData.privateKey));

		KeyAgreement keyAgreementLCP = KeyAgreement.getInstance("ECDH", "BC");
		keyAgreementLCP.init(privateKeyCard);
		keyAgreementLCP.doPhase(publicKeyLCP, true);

		MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
		byte[] hashKey = hash.digest(keyAgreementLCP.generateSecret());
		
		SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
		DESKeySpec desSpec = new DESKeySpec(hashKey);
		SecretKey secretKey = skf.generateSecret(desSpec);
		
	    aesCipher = Cipher.getInstance("DES","BC");

	    // Initialize the cipher for encryption
	    aesCipher.init(Cipher.DECRYPT_MODE, secretKey);

	    // Decrypt the cleartext
	    byte[] decryptedText = aesCipher.doFinal(theInput);
		return decryptedText;
	}
	
	private byte[] encryptOutput(byte[] theOutput) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		// Create the cipher
		KeyStore keyStore = KeyStore.getInstance("JKS");
		String directoryNaam = "keystore";
		String bestandsNaam = "cardCert";
		
		String fileName = directoryNaam + "/" + bestandsNaam + "";
		File keystoreFile = new File(fileName);
		System.out.println(keystoreFile.exists());
		
		FileInputStream keyIn = new FileInputStream(keystoreFile);
		keyStore.load(keyIn, "kiwikiwi".toCharArray());
		
		java.security.cert.Certificate LCPCert = keyStore.getCertificate("cardCert");

		KeyFactory kf = KeyFactory.getInstance("EC", "BC"); 
															
		// get public key from the certificate of card
		PublicKey publicKeyLCP = kf.generatePublic(new X509EncodedKeySpec(LCPCert.getPublicKey().getEncoded()));
		
		ECPrivateKey privateKeyCard = (ECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(main.SecurityData.privateKey));

		KeyAgreement keyAgreementLCP = KeyAgreement.getInstance("ECDH", "BC");
		keyAgreementLCP.init(privateKeyCard);
		keyAgreementLCP.doPhase(publicKeyLCP, true);

		MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
		byte[] hashKey = hash.digest(keyAgreementLCP.generateSecret());
		
		SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
		DESKeySpec desSpec = new DESKeySpec(hashKey);
		SecretKey secretKey = skf.generateSecret(desSpec);
		
		// Create the cipher
	    aesCipher = Cipher.getInstance("DES","BC");

	    // Initialize the cipher for encryption
	    aesCipher.init(Cipher.ENCRYPT_MODE, secretKey);

	    // Encrypt the cleartext
	    byte[] ciphertext = aesCipher.doFinal(theOutput);

		return ciphertext;
	}

}
