import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.bouncycastle.jce.interfaces.ECPublicKey;

public class WinkelProtocol {
	private Cipher cipher;
	private WinkelThread wt;
	private SecretKey secretKey;
	Scanner sc = new Scanner(System.in);
	public static final int TESTCONNECTIONSTATE = -1;

	public static final int CHECKCERTIFICATESTATE = 0;
	public static final int CHANGEPOINTSSTATE = 1;

	int state = CHECKCERTIFICATESTATE;

	public WinkelProtocol(WinkelThread wt) {
		this.wt = wt;
	}

	public Object processInput(Object theInput) throws Exception {

		Object theOutput = null;

		// byte[] decryptedInput = decryptInput(input);

		if (theInput != null && theInput.toString().equals("close connection")) {

			theOutput = "close connection";
		} else if (state == CHECKCERTIFICATESTATE) {
			byte[] input = (byte[]) theInput;
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			InputStream in = new ByteArrayInputStream(input);
			X509Certificate cardCert = (X509Certificate) certFactory.generateCertificate(in);
			
			try{
				cardCert.checkValidity();
				cardCert.verify(WinkelMain.getPublicKeyLCP());
			}catch(Exception e){
				System.err.println("signature doesn't match");
				byte[] denied = { 'd', 'e', 'n', 'i', 'e', 'd', 'e', 'd' };
				theOutput = encryptOutput(denied);
				return theOutput;
			}
			//checken of kaart certificaat legit is
			Socket verifyCertSocket = new Socket("localhost", 4444);
			ObjectOutputStream verifyOut = new ObjectOutputStream(verifyCertSocket.getOutputStream());
			ObjectInputStream verifyIn = new ObjectInputStream(verifyCertSocket.getInputStream());
			//eerst keyAgreement
			verifyOut.writeObject(WinkelMain.getWinkelCert().getEncoded());
			makeSecretKeyWithLCP();
			input = (byte[]) verifyIn.readObject();
			byte[] decryptedInput = decryptInput(input);
			
			if(decryptedInput[0] == 'd'){
				System.err.println("winkelCertificaat niet aanvaard");
			}
			else if(decryptedInput[0] == 'a'){
				
				verifyOut.writeObject(cardCert.getEncoded());
				
				input = (byte[]) verifyIn.readObject();
				decryptedInput = decryptInput(input);

				if(decryptedInput[0] == 'd'){
					byte[] denied = { 'd', 'e', 'n', 'i', 'e', 'd', 'e', 'd' };
					theOutput = encryptOutput(denied);
				}
				else{
					//legit => winkelCertificaat terugsturen
					makeSecretKeyWithCard(cardCert);
					theOutput = encryptOutput(WinkelMain.getWinkelCert().getEncoded());
					state = CHANGEPOINTSSTATE;
				}
			}
			verifyOut.writeObject("close connection");
			verifyCertSocket.close();
			
		} else if (state == CHANGEPOINTSSTATE) {
			byte[] input = (byte[]) theInput;
			byte[] decryptedInput = decryptInput(input);
			short nPoints = byteArrayToShort(decryptedInput);
			System.out.println("je hebt " + nPoints + ", geef het aantal punten toe te voegen of af te trekken: ");
			
			short addjustPoints = (short) sc.nextInt();
			
			byte[] byteAddjust = shortToByte(addjustPoints);
			
			theOutput = encryptOutput(byteAddjust);
		}

		return theOutput;
	}
	
	private byte[] trimArray(byte[] decryptedInput) {
		int i = 0;
		while(decryptedInput[i] == 0){
			i++;
		}
		byte[]trimmedInput = new byte[decryptedInput.length-i];
		
		System.arraycopy(decryptedInput, i, trimmedInput, 0, trimmedInput.length);
		return trimmedInput;
	}

	private void makeSecretKeyWithCard(X509Certificate cert) throws Exception{
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		KeyFactory kf = KeyFactory.getInstance("EC", "BC"); 
		KeyAgreement keyAgreementLCP = KeyAgreement.getInstance("ECDH", "BC");
		ECPublicKey certPublicKey = (ECPublicKey)  kf.generatePublic(new X509EncodedKeySpec(cert.getPublicKey().getEncoded()));
		
		keyAgreementLCP.init(WinkelMain.getPrivateKeyWinkel());
		keyAgreementLCP.doPhase(certPublicKey, true);

		MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
		byte[] hashKey = hash.digest(keyAgreementLCP.generateSecret());
//		System.out.println("symmetric key with cert = " + new BigInteger(1,((hash.digest(keyAgreementLCP.generateSecret())))).toString(16));
		
		SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
		DESKeySpec desSpec = new DESKeySpec(hashKey);
		secretKey = skf.generateSecret(desSpec);
		
	}
	
	private void makeSecretKeyWithLCP() throws Exception{

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		KeyFactory kf = KeyFactory.getInstance("EC", "BC"); 
		KeyAgreement keyAgreementLCP = KeyAgreement.getInstance("ECDH", "BC");
		ECPublicKey lcpPublicKey = (ECPublicKey)  kf.generatePublic(new X509EncodedKeySpec(WinkelMain.getPublicKeyLCP().getEncoded()));
		
		keyAgreementLCP.init(WinkelMain.getPrivateKeyWinkel());
		keyAgreementLCP.doPhase(lcpPublicKey, true);

		MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
		byte[] hashKey = hash.digest(keyAgreementLCP.generateSecret());
//		System.out.println("symmetric key with cert = " + new BigInteger(1,((hash.digest(keyAgreementLCP.generateSecret())))).toString(16));
		
		SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
		DESKeySpec desSpec = new DESKeySpec(hashKey);
		secretKey = skf.generateSecret(desSpec);
		
	}

	private byte[] decryptInput(byte[] theInput) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		// KeyAgreement keyAgreementLCP = KeyAgreement.getInstance("ECDH",
		// "BC");
		// keyAgreementLCP.init(MainLCP.getPrivateKeyLCP());
		// keyAgreementLCP.doPhase(MainLCP.getCardCert().getPublicKey(), true);
		//
		// MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
		// byte[] hashKey = hash.digest(keyAgreementLCP.generateSecret());
		//
		// SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
		// DESKeySpec desSpec = new DESKeySpec(hashKey);
		// SecretKey secretKey = skf.generateSecret(desSpec);
		//
		// System.out.println("symmetric key with card = " + new
		// BigInteger(1,secretKey.getEncoded()).toString(16));

		cipher = Cipher.getInstance("DES/ECB/NoPadding");

		// Initialize the cipher for encryption
		cipher.init(Cipher.DECRYPT_MODE, secretKey);

		// Decrypt the cleartext
		byte[] decryptedText = cipher.doFinal(theInput);
		return decryptedText;
	}

	private byte[] encryptOutput(byte[] theOutput) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		System.out.println(theOutput.length);
		if (theOutput.length % 8 != 0) {
			int nAddZeros = 8-theOutput.length % 8;
			byte[] zeros = new byte[nAddZeros];
			for (int i = 0; i < nAddZeros; i++) {
				zeros[i] = 0;
			}
//			int aLen = a.length;
//			int bLen = b.length;
			byte[] concat = new byte[nAddZeros + theOutput.length];
			System.arraycopy(zeros, 0, concat, 0, nAddZeros);
			System.arraycopy(theOutput, 0, concat, nAddZeros, theOutput.length);
			theOutput = concat;
		}
		System.out.println(theOutput.length);
		// KeyAgreement keyAgreementLCP = KeyAgreement.getInstance("ECDH",
		// "BC");
		// keyAgreementLCP.init(MainLCP.getPrivateKeyLCP());
		// keyAgreementLCP.doPhase(MainLCP.getCardCert().getPublicKey(), true);
		//
		// MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
		// byte[] hashKey = hash.digest(keyAgreementLCP.generateSecret());
		//
		// SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
		// DESKeySpec desSpec = new DESKeySpec(hashKey);
		// SecretKey secretKey = skf.generateSecret(desSpec);

		// Create the cipher
		cipher = Cipher.getInstance("DES/ECB/NoPadding");

		// Initialize the cipher for encryption
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);

		// Encrypt the cleartext
		byte[] ciphertext = cipher.doFinal(theOutput);

		return ciphertext;
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