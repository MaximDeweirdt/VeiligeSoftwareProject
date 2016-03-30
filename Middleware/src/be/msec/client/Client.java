package be.msec.client;

import be.msec.client.connection.Connection;
import be.msec.client.connection.IConnection;
import be.msec.client.connection.SimulatedConnection;

import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
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
import org.bouncycastle.jce.interfaces.ECPublicKey;

import com.sun.org.apache.xml.internal.security.utils.Base64;

public class Client {

	private final static byte IDENTITY_CARD_CLA =(byte)0x80;
	private static final byte VALIDATE_PIN_INS = 0x01;
	
	private static final byte KEY_AGREEMENT_LCP_INS = 0x02;
	private static final byte ENCRYPT_DATA_LCP_INS = 0x03;
	private static final byte DECRYPT_DATA_LCP_INS = 0x04;
	
	
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	
	private static final Scanner SCANNER = new Scanner(System.in);
	/**
	 * @param args
	 */
	
	private static byte[] publicKeyParameterQFromLCP = new byte[]{
			(byte) 0x04, (byte) 0xa9, (byte) 0xfe, (byte) 0x35, (byte) 0x45, (byte) 0xf0, 
			(byte) 0xaf, (byte) 0x79, (byte) 0x60, (byte) 0x8f, (byte) 0xd5, (byte) 0x79, 
			(byte) 0x09, (byte) 0xcb, (byte) 0x32, (byte) 0x9b, (byte) 0x77, (byte) 0xde, 
			(byte) 0x96, (byte) 0x8a, (byte) 0x9c, (byte) 0x2e, (byte) 0x3f, (byte) 0x3c, 
			(byte) 0x63, (byte) 0x8d, (byte) 0xc4, (byte) 0x36, (byte) 0x94, (byte) 0x3e, 
			(byte) 0x62, (byte) 0x1c, (byte) 0x95, (byte) 0xb3, (byte) 0xa0, (byte) 0x4b, 
			(byte) 0x3b, (byte) 0x90, (byte) 0xab, (byte) 0x0b, (byte) 0xdf, (byte) 0x14, 
			(byte) 0x19, (byte) 0xba, (byte) 0x0a, (byte) 0xed, (byte) 0x4d, (byte) 0x90, 
			(byte) 0x2c

		};
	
	private static byte[] publicKeyLCP = new byte[]{
			(byte) 0x30, (byte) 0x49, (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07, 
			(byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x02, 
			(byte) 0x01, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, 
			(byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0x03, 
			(byte) 0x32, (byte) 0x00, (byte) 0x04, (byte) 0xa9, (byte) 0xfe, (byte) 0x35, 
			(byte) 0x45, (byte) 0xf0, (byte) 0xaf, (byte) 0x79, (byte) 0x60, (byte) 0x8f, 
			(byte) 0xd5, (byte) 0x79, (byte) 0x09, (byte) 0xcb, (byte) 0x32, (byte) 0x9b, 
			(byte) 0x77, (byte) 0xde, (byte) 0x96, (byte) 0x8a, (byte) 0x9c, (byte) 0x2e, 
			(byte) 0x3f, (byte) 0x3c, (byte) 0x63, (byte) 0x8d, (byte) 0xc4, (byte) 0x36, 
			(byte) 0x94, (byte) 0x3e, (byte) 0x62, (byte) 0x1c, (byte) 0x95, (byte) 0xb3, 
			(byte) 0xa0, (byte) 0x4b, (byte) 0x3b, (byte) 0x90, (byte) 0xab, (byte) 0x0b, 
			(byte) 0xdf, (byte) 0x14, (byte) 0x19, (byte) 0xba, (byte) 0x0a, (byte) 0xed, 
			(byte) 0x4d, (byte) 0x90, (byte) 0x2c
		};
	
	public static void main(String[] args) throws Exception {
		IConnection c;
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		//Real Card:
		c = new Connection();
		((Connection)c).setTerminal(0); //depending on which cardreader you use
		
		c.connect(); 
		
		String hostname = "localhost";
		int portNumber = 4443;
		
		/*Socket socket = new Socket(hostname, portNumber);
		
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
		}*/
		
		
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
			System.out.println();
			
			//KEY AGREEMENT WITH LCP, set DES key and generate cipher in the java card 
			KeyFactory kf = KeyFactory.getInstance("EC","BC"); // or "EC" or whatever
			a = new CommandAPDU(IDENTITY_CARD_CLA, KEY_AGREEMENT_LCP_INS , (byte)(publicKeyParameterQFromLCP.length &0xff) , 0x00,publicKeyParameterQFromLCP);
			r = c.transmit(a);
			byte[] symmetricKey = r.getData();
			//System.out.println("serialnumber = " + serialNumber);
			System.out.println(r);
			System.out.println("symmetric key with LCP = " + new BigInteger(1,symmetricKey).toString(16));
			System.out.println();
			
			
			//SEND data to encrypt on java card
			byte[] data = new byte[]{'t','e','s','t','t','e','s','t'};
			a = new CommandAPDU(IDENTITY_CARD_CLA, ENCRYPT_DATA_LCP_INS, (byte) (data.length&0xff), 0x00,data);
			r = c.transmit(a);
			System.out.println(r);
			byte[] encryptedDataFromJavaCard = r.getData();
			System.out.println("encrypted data from the card = " + new String(r.getData()));
			
			//encryption on java
			DESKeySpec dks = new DESKeySpec(symmetricKey);
			SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
			SecretKey desKey = skf.generateSecret(dks);
			Cipher encryptCipher = Cipher.getInstance("DES/ECB/NoPadding ");
			encryptCipher.init(Cipher.ENCRYPT_MODE, desKey);
			byte[] textinCipher = encryptCipher.doFinal(data);
			System.out.println("encrypted data from client = " + new String(textinCipher));
			System.out.println();
			
			//decryption on java card
			a = new CommandAPDU(IDENTITY_CARD_CLA, DECRYPT_DATA_LCP_INS, (byte) (encryptedDataFromJavaCard.length&0xff), 0x00,encryptedDataFromJavaCard);
			r = c.transmit(a);
			System.out.println(r);
			System.out.println("decrypted data from the card = " + new String(r.getData()));
			
			//decryption on java
			encryptCipher.init(Cipher.DECRYPT_MODE, desKey);
			byte[] text = encryptCipher.doFinal(textinCipher);
			System.out.println("decrypted data from client = " + new String(text));
			System.out.println();
			
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
			
			
			/*out.writeObject(winkelKeuze);
			//hier komt het geencrypteerde certificaat met het pseudoniem dat op de kaart moet opgeslaan worden
			//dit is ook het certificaat van de kaart dat later gerevoceerd moet kunnen worden (dus ook bijgehouden op LCP denk ik)
			ob = in.readObject();*/
			
			
			
		} catch (Exception e) {
			throw e;
		}
		finally {
			c.close();  // close the connection with the card
			
			/*out.writeObject("stop");
			socket.close();*/
		}


	}

}
