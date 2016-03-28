package be.msec.client;

import be.msec.client.connection.Connection;
import be.msec.client.connection.IConnection;
import be.msec.client.connection.SimulatedConnection;

import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.*;

import org.bouncycastle.jce.interfaces.ECPrivateKey;

import com.sun.org.apache.xml.internal.security.utils.Base64;

public class Client {

	private final static byte IDENTITY_CARD_CLA =(byte)0x80;
	private static final byte VALIDATE_PIN_INS = 0x22;
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	
	private static final Scanner SCANNER = new Scanner(System.in);
	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception {
		IConnection c;

		//Real Card:
//		c = new Connection();
//		((Connection)c).setTerminal(0); //depending on which cardreader you use
//		
//		c.connect(); 
		
		String hostname = "localhost";
		int portNumber = 4443;
		
		Socket socket = new Socket(hostname, portNumber);
		
		ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
		ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
		
		Object ob;
		
		//dit mag hier niet uiteraard gewoon om te testen
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		String directoryNaam = "keystore";
		String bestandsNaam = "LCPcert";
		try{
			KeyStore keyStore = KeyStore.getInstance("JKS");
			
			String fileName = directoryNaam + "/" + bestandsNaam + "";
			File keystoreFile = new File(fileName);
			System.out.println(keystoreFile.exists());
			
			FileInputStream keyIn = new FileInputStream(keystoreFile);
			keyStore.load(keyIn, "kiwikiwi".toCharArray());
			
			java.security.cert.Certificate LCPCert = keyStore.getCertificate("LCPcert");
	
			KeyFactory kf = KeyFactory.getInstance("EC", "BC"); 
																
			// get public key from the certificate of card
			PublicKey publicKeyLCP = kf.generatePublic(new X509EncodedKeySpec(LCPCert.getPublicKey().getEncoded()));
			
			ECPrivateKey privateKeyCard = (ECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(SecurityData.privateKeyCard));
	
			KeyAgreement keyAgreementLCP = KeyAgreement.getInstance("ECDH", "BC");
			keyAgreementLCP.init(privateKeyCard);
			keyAgreementLCP.doPhase(publicKeyLCP, true);
	
			MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
			byte[] hashKey = hash.digest(keyAgreementLCP.generateSecret());
			
			SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
			DESKeySpec desSpec = new DESKeySpec(hashKey);
			SecretKey secretKey = skf.generateSecret(desSpec);
			
//			SecretKey secret = keyAgreementLCP.generateSecret("DES");
			
			// Create the cipher
		    Cipher aesCipher = Cipher.getInstance("DES","BC");

		    // Initialize the cipher for encryption
		    aesCipher.init(Cipher.ENCRYPT_MODE, secretKey);

		    // Encrypt the cleartext
		    byte[] output = "Hello from the other side".getBytes();
		    System.out.println("clean bytearray: " + output);
		    byte[] ciphertext = aesCipher.doFinal(output);
		    
			System.out.println("sending message: " +ciphertext);
			out.writeObject(ciphertext);
			
			byte[] input = (byte[]) in.readObject();
			System.out.println("received message");
			 // Initialize the cipher for encryption
		    aesCipher.init(Cipher.DECRYPT_MODE, secretKey);

		    // Decrypt the cleartext
		    byte[] decryptedText = aesCipher.doFinal(input);
		    
			System.out.println(Base64.encode(decryptedText));
			
		}catch(Exception e){
			e.printStackTrace();
		}
		
		/*
		try {
			
			CommandAPDU a;
			ResponseAPDU r;
			
			//Send PIN
			a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00,new byte[]{0x01,0x02,0x03,0x04});
			r = c.transmit(a);

			System.out.println(r);
			if (r.getSW()==SW_VERIFICATION_FAILED) throw new Exception("PIN INVALID");
			else if(r.getSW()!=0x9000) throw new Exception("Exception on the card: " + r.getSW());
			System.out.println("PIN Verified");
			
			//kiezen bij welke winkel te registreren
			
			int winkelnummer = Integer.parseInt(SCANNER.nextLine());
			byte[] winkelKeuze = "0".getBytes();
			while (winkelnummer <= 0 || winkelnummer > 4) {
				System.err.println("Het ingegeven winkelnummer is niet correct");
				winkelnummer = Integer.parseInt(SCANNER.nextLine());
			}
			
			switch (winkelnummer) {
			//aan de kaart het winkelcertificaat vragen en dat doorsturen?
			//moet alleszins ook iets van de kaart zijn zodat het geencrypteerd doorgestuurd kan worden
			case 1:
				winkelKeuze = "1".getBytes();
				break;
			case 2:
				winkelKeuze = "2".getBytes();
				break;
			default:
				System.err.println("rip");
				break;
			}
			out.writeObject(winkelKeuze);
			//hier komt het geencrypteerde certificaat met het pseudoniem dat op de kaart moet opgeslaan worden
			//dit is ook het certificaat van de kaart dat later gerevoceerd moet kunnen worden (dus ook bijgehouden op LCP denk ik)
			ob = in.readObject();
			
			
		} catch (Exception e) {
			throw e;
		}
		finally {
			c.close();  // close the connection with the card
			
			out.writeObject("stop");
			socket.close();
		}

*/
	}

}
