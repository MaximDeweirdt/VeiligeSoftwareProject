package protocols;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import main.MainLCP;
import socketListeners.RegisterSocketListenerThread;
import socketThreads.RegisterThread;

public class RegisterProtocol {

	private Cipher cipher;
	private RegisterThread rt;
	private SecretKey secretKey;
	
	public static final int TESTCONNECTIONSTATE = -1;

	public static final int CHECKCERTIFICATESTATE = 0;
	public static final int KIESWINKELSTATE = 1;

	int state = CHECKCERTIFICATESTATE;

	public RegisterProtocol(RegisterThread rt) {
		this.rt = rt;
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

			try {
				cardCert.checkValidity();
				cardCert.verify(MainLCP.getPublicKeyLCP());
				System.out.println("signature is correct");
				makeSecretKey(cardCert);
				byte[] accepted = { 'a', 'c', 'c', 'e', 'p', 't', 'e', 'd' };
				theOutput = encryptOutput(accepted);
				state = KIESWINKELSTATE;
			} catch (Exception e) {
				System.err.println("signature isn't correct");
				byte[] denied = { 'd', 'e', 'n', 'i', 'e', 'd', 'e', 'd' };
				theOutput = encryptOutput(denied);
				state = CHECKCERTIFICATESTATE;
			}
			

		} else if (state == KIESWINKELSTATE) {
			byte[] input = (byte[]) theInput;
			X509Certificate shopPseudoCert;
			byte[] decryptedInput = decryptInput(input);
			short winkelNummer = byteArrayToShort(decryptedInput);
			
			switch (winkelNummer) {
			case 0:
				System.out.println("winkel 0 gekozen");
				shopPseudoCert = makePseudonimCert("winkel0");
				MainLCP.addCertToList(shopPseudoCert);
				theOutput = encryptOutput(shopPseudoCert.getEncoded());
				break;
			case 1:
				System.out.println("winkel 1 gekozen");
				shopPseudoCert = makePseudonimCert("winkel1");
				MainLCP.addCertToList(shopPseudoCert);
				theOutput = encryptOutput(shopPseudoCert.getEncoded());
				break;
			case 2:
				System.out.println("winkel 2 gekozen");
				shopPseudoCert = makePseudonimCert("winkel2");
				MainLCP.addCertToList(shopPseudoCert);
				theOutput = encryptOutput(shopPseudoCert.getEncoded());
				break;
			case 3:
				System.out.println("winkel 3 gekozen");
				shopPseudoCert = makePseudonimCert("winkel3");
				MainLCP.addCertToList(shopPseudoCert);
				theOutput = encryptOutput(shopPseudoCert.getEncoded());
				break;
			}
			rt.finishedCom = true;
		}

		return theOutput;
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
	

	private X509Certificate makePseudonimCert(String shopName) throws Exception {
		Date startDate = new Date();
		Date expiryDate = new Date(2016, 12, 31, 23, 59, 59);
		Long uniqueCardID = RegisterSocketListenerThread.getCardShopID().getAndIncrement();

		BigInteger serialNumber = new BigInteger("" + 10 + uniqueCardID); // serial
																			// number
																			// for
		// certificate

		// keypair is the EC public/private key pair
		X500Principal dnName = new X500Principal("CN= " + shopName);
		ContentSigner signer = new JcaContentSignerBuilder("SHA1withECDSA").build(MainLCP.getPrivateKeyLCP());

		X509v1CertificateBuilder v1CertGen = new JcaX509v1CertificateBuilder(dnName, serialNumber, startDate,
				expiryDate, dnName, MainLCP.getCardCert().getPublicKey());
		X509CertificateHolder holder = v1CertGen.build(signer);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		InputStream certIs = new ByteArrayInputStream(holder.getEncoded());
		X509Certificate cert = (X509Certificate) cf.generateCertificate(certIs);

		System.out.println(cert);
		return cert;

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
