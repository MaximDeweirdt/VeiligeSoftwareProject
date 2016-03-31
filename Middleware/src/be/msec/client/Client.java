package be.msec.client;

import be.msec.client.connection.Connection;
import be.msec.client.connection.IConnection;
import be.msec.client.connection.SimulatedConnection;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
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
	//private static final byte ENCRYPT_DATA_LCP_INS = 0x03;
	//private static final byte DECRYPT_DATA_LCP_INS = 0x04;
	private static final byte SET_ID_SHOP_INS = 0x05;
	private static final byte SET_PSEUDONIEM_INS = 0x06;
	private static final byte GET_PART1_CERTIFICATE = 0x07;
	private static final byte GET_PART2_CERTIFICATE = 0x08;
	
	
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	
	private static final Scanner SCANNER = new Scanner(System.in);
	/**
	 * @param args
	 */
	public static byte[] cardCertificate ={
			(byte) 0x30, (byte) 0x82, (byte) 0x01, (byte) 0x03, (byte) 0x30, (byte) 0x81, (byte) 0xbb, (byte) 0x02, (byte) 0x01, (byte) 0x02, (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x04, (byte) 0x01, (byte) 0x30, (byte) 0x1e, (byte) 0x31, (byte) 0x1c, (byte) 0x30, (byte) 0x1a, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x13, (byte) 0x13, (byte) 0x43, (byte) 0x41, (byte) 0x20, (byte) 0x63, (byte) 0x61, (byte) 0x72, (byte) 0x64, (byte) 0x20, (byte) 0x63, (byte) 0x65, (byte) 0x72, (byte) 0x74, (byte) 0x69, (byte) 0x66, (byte) 0x69, (byte) 0x63, (byte) 0x61, (byte) 0x74, (byte) 0x65, (byte) 0x30, (byte) 0x20, (byte) 0x17, (byte) 0x0d, (byte) 0x31, (byte) 0x36, (byte) 0x30, (byte) 0x33, (byte) 0x33, (byte) 0x31, (byte) 0x31, (byte) 0x33, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x33, (byte) 0x5a, (byte) 0x18, (byte) 0x0f, (byte) 0x33, (byte) 0x39, (byte) 0x31, (byte) 0x37, (byte) 0x30, (byte) 0x31, (byte) 0x33, (byte) 0x31, (byte) 0x32, (byte) 0x32, (byte) 0x35, (byte) 0x39, (byte) 0x35, (byte) 0x39, (byte) 0x5a, (byte) 0x30, (byte) 0x1e, (byte) 0x31, (byte) 0x1c, (byte) 0x30, (byte) 0x1a, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x13, (byte) 0x13, (byte) 0x43, (byte) 0x41, (byte) 0x20, (byte) 0x63, (byte) 0x61, (byte) 0x72, (byte) 0x64, (byte) 0x20, (byte) 0x63, (byte) 0x65, (byte) 0x72, (byte) 0x74, (byte) 0x69, (byte) 0x66, (byte) 0x69, (byte) 0x63, (byte) 0x61, (byte) 0x74, (byte) 0x65, (byte) 0x30, (byte) 0x49, (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0x03, (byte) 0x32, (byte) 0x00, (byte) 0x04, (byte) 0x22, (byte) 0x11, (byte) 0x21, (byte) 0xbd, (byte) 0x7d, (byte) 0xf3, (byte) 0x47, (byte) 0xfd, (byte) 0xfe, (byte) 0x3e, (byte) 0x89, (byte) 0x5d, (byte) 0xe0, (byte) 0x02, (byte) 0x65, (byte) 0xb3, (byte) 0x5c, (byte) 0x49, (byte) 0x91, (byte) 0x28, (byte) 0x71, (byte) 0x66, (byte) 0x2e, (byte) 0x29, (byte) 0xa3, (byte) 0xdf, (byte) 0x73, (byte) 0x5a, (byte) 0x52, (byte) 0x87, (byte) 0x50, (byte) 0x79, (byte) 0xd7, (byte) 0x5c, (byte) 0x3d, (byte) 0x56, (byte) 0x70, (byte) 0x76, (byte) 0xca, (byte) 0xaf, (byte) 0xad, (byte) 0x2e, (byte) 0xaf, (byte) 0x07, (byte) 0xc3, (byte) 0xa4, (byte) 0x76, (byte) 0xdf, (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x04, (byte) 0x01, (byte) 0x03, (byte) 0x38, (byte) 0x00, (byte) 0x30, (byte) 0x35, (byte) 0x02, (byte) 0x19, (byte) 0x00, (byte) 0xe1, (byte) 0x10, (byte) 0x53, (byte) 0x30, (byte) 0xbb, (byte) 0x7a, (byte) 0x1a, (byte) 0xd1, (byte) 0x90, (byte) 0x15, (byte) 0xca, (byte) 0x3d, (byte) 0xe8, (byte) 0x13, (byte) 0x87, (byte) 0x5c, (byte) 0xaf, (byte) 0x81, (byte) 0xb0, (byte) 0x32, (byte) 0xe7, (byte) 0x30, (byte) 0x56, (byte) 0x22, (byte) 0x02, (byte) 0x18, (byte) 0x30, (byte) 0x02, (byte) 0x12, (byte) 0xa9, (byte) 0x01, (byte) 0xf6, (byte) 0x6e, (byte) 0x35, (byte) 0xce, (byte) 0xba, (byte) 0x25, (byte) 0x35, (byte) 0xd6, (byte) 0x7e, (byte) 0x9f, (byte) 0xf7, (byte) 0x79, (byte) 0xe5, (byte) 0x8f, (byte) 0xc2, (byte) 0x69, (byte) 0x23, (byte) 0x2c, (byte) 0x41
	};
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
		
		Socket socket = new Socket(hostname, portNumber);
		
		ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
		ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
		
		Object ob;
		
		//dit mag hier niet uiteraard gewoon om te testen
		/*Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
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
			
			CommandAPDU a = null;
			ResponseAPDU r = null;

			//Send PIN
			byte[] pin = new byte[]{0x01,0x02,0x03,0x04};
			loginCard(a,r,c,pin);
			
			
			//KEY AGREEMENT WITH LCP, set DES key and generate cipher in the java card 
			byte[]  symmetrickey = keyAgreementLCPAndCard(a,r,c);
			
			//opvragen van het certificaat van de kaart
			byte[] cardCert = requestCertificate(a, r, c);
			out.writeObject(cardCert);
			
			byte[] input = (byte[]) in.readObject();
			
			//SEND data to encrypt on java card
			/*byte[] data = new byte[]{'t','e','s','t','t','e','s','t'};
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
			*/
			

			
			//kiezen bij welke winkel te registreren
			System.out.print("winkelkeuze = ");
			int winkelnummer = Integer.parseInt(SCANNER.nextLine());
			byte[] winkelKeuze = "0".getBytes();
			while (winkelnummer <= 0 || winkelnummer > 4) {
				System.err.println("Het ingegeven winkelnummer is niet correct");
				winkelnummer = Integer.parseInt(SCANNER.nextLine());
			}
			
			winkelKeuze = shortToByte((short)winkelnummer);
			//-----------------------------------------------------------------------
			//DIT GEDEELTE IS ENKEL VOOR TE TESTEN VOOR DE PSEUDONIEM-> MAG LATER WEG
			/*byte[] data = new byte[]{'t','e','s','t','t','e','s','t'};
			DESKeySpec dks = new DESKeySpec(symmetrickey);
			SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
			SecretKey desKey = skf.generateSecret(dks);
			Cipher encryptCipher = Cipher.getInstance("DES/ECB/NoPadding ");
			encryptCipher.init(Cipher.ENCRYPT_MODE, desKey);
			byte[] textinCipher = encryptCipher.doFinal(data);
			System.out.println("encrypted data from client = " + new String(textinCipher));
			System.out.println();*/
			//EINDE GEDEELTE
			//-----------------------------------------------------------------------
			
			out.writeObject(winkelnummer);
			byte[] textinCipher = (byte[]) in.readObject();
			System.out.println(new BigInteger(1,textinCipher).toString(16));
			//versturen van winkelkeuze naar de kaart
			//setten van pseudoniem in de kaart 
			//TODO TEXTINCIPHER MOET HET EFFECTIEVE PSEUDONIEM VAN DE LCP WORDEN!!!!!
			setShopIdAndPseudoniem(a,r,c,winkelKeuze,textinCipher);
			//decryption on java
			
			/*DESKeySpec dks = new DESKeySpec(symmetrickey);
			SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
			SecretKey desKey = skf.generateSecret(dks);
			Cipher encryptCipher = Cipher.getInstance("DES/ECB/NoPadding ");
			encryptCipher.init(Cipher.DECRYPT_MODE, desKey);
			byte[] text = encryptCipher.doFinal(textinCipher);
			byte[] text2 = Arrays.copyOfRange(text, 3, 240);
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			InputStream bbb = new ByteArrayInputStream(text2);
			X509Certificate cert = (X509Certificate)certFactory.generateCertificate(bbb);
			System.out.println();*/
			


			
			/*out.writeObject(winkelKeuze);
			//hier komt het geencrypteerde certificaat met het pseudoniem dat op de kaart moet opgeslaan worden
			//dit is ook het certificaat van de kaart dat later gerevoceerd moet kunnen worden (dus ook bijgehouden op LCP denk ik)
			ob = in.readObject();*/
			
			
			
		} catch (Exception e) {
			throw e;
		}
		finally {
			out.writeObject("close connection");
			c.close();  // close the connection with the card
			
			//out.writeObject("stop");
			socket.close();
		}


	}
	
	private static void loginCard(CommandAPDU a, ResponseAPDU r, IConnection c, byte[] pin) throws Exception{
		a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00,new byte[]{0x01,0x02,0x03,0x04});
		r = c.transmit(a);

		System.out.println(r);
		if (r.getSW()==SW_VERIFICATION_FAILED) throw new Exception("PIN INVALID");
		else if(r.getSW()!=0x9000) throw new Exception("Exception on the card: " + r.getSW());
		System.out.println("PIN Verified");
		System.out.println();
	}
	
	private static byte[] keyAgreementLCPAndCard(CommandAPDU a, ResponseAPDU r, IConnection c) throws Exception{
		KeyFactory kf = KeyFactory.getInstance("EC","BC"); // or "EC" or whatever
		a = new CommandAPDU(IDENTITY_CARD_CLA, KEY_AGREEMENT_LCP_INS , (byte)(publicKeyParameterQFromLCP.length &0xff) , 0x00,publicKeyParameterQFromLCP);
		r = c.transmit(a);
		byte[] symmetricKey = r.getData();
		//System.out.println("serialnumber = " + serialNumber);
		System.out.println(r);
		System.out.println("symmetric key with LCP = " + new BigInteger(1,symmetricKey).toString(16));
		System.out.println();
		return symmetricKey;
	}
	
	private static byte[] requestCertificate(CommandAPDU a, ResponseAPDU r, IConnection c) throws Exception{
		ByteBuffer bb = ByteBuffer.allocate(263);
		byte[] certificate = new byte[263];
		a = new CommandAPDU(IDENTITY_CARD_CLA, GET_PART1_CERTIFICATE , 0x00 , 0x00,new byte[]{(byte)0xff});
		r = c.transmit(a);
		System.out.println("part1 " + r);
		bb.put(r.getData());
		a = new CommandAPDU(IDENTITY_CARD_CLA, GET_PART2_CERTIFICATE , 0x00 , 0x00,new byte[]{(byte)0xff});
		r = c.transmit(a);
		System.out.println("part2 " + r);
		bb.put(r.getData());
		certificate = bb.array();
		System.out.println("certificaat = " + new BigInteger(1,certificate).toString(16));
		return certificate;
	}
	
	private static void setShopIdAndPseudoniem(CommandAPDU a, ResponseAPDU r, IConnection c,byte[] shopId, byte[] textinCipher) throws Exception{
		//versturen van winkelkeuze naar de kaart
		a = new CommandAPDU(IDENTITY_CARD_CLA, SET_ID_SHOP_INS, (byte) (shopId.length&0xff), 0x00,shopId);
		r = c.transmit(a);
		System.out.println(r);
		short lngth = (short) textinCipher.length;
		//System.out.println(byteToShort((byte)(lngth&0xff)));
		//setten van pseudoniem in de kaart
		byte []pseudoniem = textinCipher;
		a = new CommandAPDU(IDENTITY_CARD_CLA, SET_PSEUDONIEM_INS, lngth, 0x00,pseudoniem);
		r = c.transmit(a);
		System.out.println(r);
	//	System.err.println(byteArrayToShort(r.getData()));
	}
	
	private static short byteToShort(byte b) {
		return (short) (b & 0xff);
	}

	private static short byteArrayToShort(byte[] b) {
		short value = (short) (((b[0] << 8)) | ((b[1] & 0xff)));
		return value;
	}

	private static byte[] shortToByte(short s) {
		byte[] shortByte = new byte[2];
		shortByte[0] = (byte) ((s >> 8) & 0xff);
		shortByte[1] = (byte) (s & 0xff);
		return shortByte;
	}
}
