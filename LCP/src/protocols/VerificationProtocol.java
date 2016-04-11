package protocols;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.bouncycastle.jce.interfaces.ECPublicKey;

import gui.LCPGui;
import main.MainLCP;

public class VerificationProtocol {

	public static final int KEYAGREESTATE = 0;
	public static final int VERIFYCERTSTATE = 1;
	
	private int state = KEYAGREESTATE;
	private SecretKey secretKey;
	private Cipher cipher;
	
	public Object processInput(Object theInput) throws Exception {
		
		System.out.println(theInput.toString());
		
		Object theOutput = null;

		// byte[] decryptedInput = decryptInput(input);

		if (theInput != null && theInput.toString().equals("close connection")) {

			theOutput = "close connection";
		} else if (state == KEYAGREESTATE) {
			byte[] input = (byte[]) theInput;
			boolean valid = true;
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			InputStream in = new ByteArrayInputStream(input);
			X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);
			if(MainLCP.getCertList().containsKey(cert)){
				 valid = MainLCP.getCertList().get(cert).isValid();
			}
			if(valid){
				try {
					cert.checkValidity();
					cert.verify(MainLCP.getPublicKeyLCP());
					System.out.println("signature is correct");
					makeSecretKey(cert);
					state = VERIFYCERTSTATE;
					byte[] accepted = { 'a', 'c', 'c', 'e', 'p', 't', 'e', 'd' };
					theOutput = encryptOutput(accepted);
				} catch (Exception e) {
					System.err.println("signature isn't correct");
					byte[] denied = { 'd', 'e', 'n', 'i', 'e', 'd', 'e', 'd' };
					theOutput = encryptOutput(denied);
					state = KEYAGREESTATE;
				}
			}
			else{
				byte[] denied = { 'd', 'e', 'n', 'i', 'e', 'd', 'e', 'd' };
				makeSecretKey(cert);
				theOutput = encryptOutput(denied);
				state = KEYAGREESTATE;
			}
		}else if (state == VERIFYCERTSTATE) {
			byte[] input = (byte[]) theInput;
			
			boolean valid = true;
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			InputStream in = new ByteArrayInputStream(input);
			X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);
			if(MainLCP.getCertList().containsKey(cert)){
				 valid = MainLCP.getCertList().get(cert).isValid();
				// LCPGui.addText("certificaat ongeldig");
			}
			if(valid){
				try {
					cert.checkValidity();
					cert.verify(MainLCP.getPublicKeyLCP());
					System.out.println("signature is correct");
					
					byte[] accepted = getSimpleCert(cert);
					theOutput = encryptOutput(accepted);
				} catch (Exception e) {
					System.err.println("signature isn't correct");
					byte[] denied = { 'd', 'e', 'n', 'i', 'e', 'd', 'e', 'd' };
					theOutput = encryptOutput(denied);
				}
			}
			else{
				byte[] denied = { 'd', 'e', 'n', 'i', 'e', 'd', 'e', 'd' };
				theOutput = encryptOutput(denied);
			}
		}

		
		return theOutput;
	}


	private byte[] getSimpleCert(X509Certificate cert) throws Exception {
		KeyFactory kf = KeyFactory.getInstance("EC", "BC"); 
		ECPublicKey certPublicKey = (ECPublicKey)  kf.generatePublic(new X509EncodedKeySpec(cert.getPublicKey().getEncoded()));
		
		byte[] qParameter = certPublicKey.getQ().getEncoded();
		short shopNR = -1;
		if(cert.getIssuerX500Principal().getName().contains("Colruyt")){
			shopNR = 0;
		}
		else if(cert.getIssuerX500Principal().getName().contains("Delhaize")){
			shopNR = 1;
		}
		else if(cert.getIssuerX500Principal().getName().contains("Alienware")){
		      shopNR = 2;
		}
		else if(cert.getIssuerX500Principal().getName().contains("Razor")){
		      shopNR = 3;
		}
		
		byte[] shopNumber = shortToByte(shopNR);
		byte[] serialNumber = shortToByte((short)cert.getSerialNumber().intValue());
		
//		int aLen = a.length;
//		int bLen = b.length;
		byte[] concat = new byte[qParameter.length + shopNumber.length];
		System.arraycopy(qParameter, 0, concat, 0, qParameter.length);
		System.arraycopy(shopNumber, 0, concat, qParameter.length, shopNumber.length);
		
		byte[] simpleCert = new byte[concat.length + serialNumber.length];
		System.arraycopy(concat, 0, simpleCert, 0, concat.length);
		System.arraycopy(serialNumber, 0, simpleCert, concat.length, serialNumber.length);
		
		return simpleCert;
	}


	private void makeSecretKey(X509Certificate cert) throws Exception{
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		KeyFactory kf = KeyFactory.getInstance("EC", "BC"); 
		KeyAgreement keyAgreementLCP = KeyAgreement.getInstance("ECDH", "BC");
		ECPublicKey certPublicKey = (ECPublicKey)  kf.generatePublic(new X509EncodedKeySpec(cert.getPublicKey().getEncoded()));
		
		keyAgreementLCP.init(MainLCP.getPrivateKeyLCP());
		keyAgreementLCP.doPhase(certPublicKey, true);

		MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
		byte[] hashKey = hash.digest(keyAgreementLCP.generateSecret());
//		System.out.println("symmetric key with cert = " + new BigInteger(1,((hash.digest(keyAgreementLCP.generateSecret())))).toString(16));
		
		SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
		DESKeySpec desSpec = new DESKeySpec(hashKey);
		secretKey = skf.generateSecret(desSpec);
		
	}
	
	private byte[] decryptInput(byte[] theInput) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

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
			byte[] concat = new byte[nAddZeros + theOutput.length];
			System.arraycopy(zeros, 0, concat, 0, nAddZeros);
			System.arraycopy(theOutput, 0, concat, nAddZeros, theOutput.length);
			theOutput = concat;
		}
		System.out.println(theOutput.length);

		// Create the cipher
		cipher = Cipher.getInstance("DES/ECB/NoPadding");

		// Initialize the cipher for encryption
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);

		// Encrypt the cleartext
		byte[] ciphertext = cipher.doFinal(theOutput);

		return ciphertext;
	}
	
	public static byte[] shortToByte(short s) {
		byte[] shortByte = new byte[2];
		shortByte[0] = (byte) ((s >> 8) & 0xff);
		shortByte[1] = (byte) (s & 0xff);
		return shortByte;
	}
}
