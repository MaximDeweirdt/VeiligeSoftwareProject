import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import javax.security.auth.x500.X500Principal;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class ECJavaPublicKeyGen {
	
	public static byte[] privateKeyLCPBytes = new byte[]{
			(byte) 0x30, (byte) 0x7b, (byte) 0x02, (byte) 0x01, (byte) 0x00, (byte) 0x30, 
			(byte) 0x13, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48, 
			(byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01, (byte) 0x06, (byte) 0x08, 
			(byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x03, 
			(byte) 0x01, (byte) 0x01, (byte) 0x04, (byte) 0x61, (byte) 0x30, (byte) 0x5f, 
			(byte) 0x02, (byte) 0x01, (byte) 0x01, (byte) 0x04, (byte) 0x18, (byte) 0x53, 
			(byte) 0xad, (byte) 0x00, (byte) 0x6a, (byte) 0xaf, (byte) 0xfd, (byte) 0xca, 
			(byte) 0x87, (byte) 0xb9, (byte) 0x58, (byte) 0xf2, (byte) 0x6e, (byte) 0x65, 
			(byte) 0x87, (byte) 0x1d, (byte) 0xbc, (byte) 0xb0, (byte) 0xe6, (byte) 0x4a, 
			(byte) 0xbe, (byte) 0xb2, (byte) 0x58, (byte) 0x69, (byte) 0x45, (byte) 0xa0, 
			(byte) 0x0a, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, 
			(byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0xa1, 
			(byte) 0x34, (byte) 0x03, (byte) 0x32, (byte) 0x00, (byte) 0x04, (byte) 0xa9, 
			(byte) 0xfe, (byte) 0x35, (byte) 0x45, (byte) 0xf0, (byte) 0xaf, (byte) 0x79, 
			(byte) 0x60, (byte) 0x8f, (byte) 0xd5, (byte) 0x79, (byte) 0x09, (byte) 0xcb, 
			(byte) 0x32, (byte) 0x9b, (byte) 0x77, (byte) 0xde, (byte) 0x96, (byte) 0x8a, 
			(byte) 0x9c, (byte) 0x2e, (byte) 0x3f, (byte) 0x3c, (byte) 0x63, (byte) 0x8d, 
			(byte) 0xc4, (byte) 0x36, (byte) 0x94, (byte) 0x3e, (byte) 0x62, (byte) 0x1c, 
			(byte) 0x95, (byte) 0xb3, (byte) 0xa0, (byte) 0x4b, (byte) 0x3b, (byte) 0x90, 
			(byte) 0xab, (byte) 0x0b, (byte) 0xdf, (byte) 0x14, (byte) 0x19, (byte) 0xba, 
			(byte) 0x0a, (byte) 0xed, (byte) 0x4d, (byte) 0x90, (byte) 0x2c
		};

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		KeyFactory kf = KeyFactory.getInstance("EC"); // or "EC" or whatever
		PrivateKey privateKeyLCP = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyLCPBytes));
		
		KeyPair kp = ECJavaPublicKeyGen.generateECCKeyPair();

		String directoryNaam = "keystore";
		String bestandsNaam = "DelhaizeCert";
		char[] password = "kiwikiwi".toCharArray();
		KeyStore keyStore = KeyStore.getInstance("JKS");
		String fileName = directoryNaam + "/" + bestandsNaam + "";
		File keystoreFile = new File(fileName);
		System.out.println(keystoreFile.exists());
		// Code om certificaat aan te maken en ts schrijven naar een keystore
		// file
		FileInputStream in = new FileInputStream(keystoreFile);
		keyStore.load(in, "kiwikiwi".toCharArray());
		in.close();
		// Add the certificate
		X509Certificate certificate = generateCertificate(kp,privateKeyLCP);
		keyStore.setCertificateEntry("DelhaizeCert", certificate);
		// Save the new keystore contents
		FileOutputStream out = new FileOutputStream(keystoreFile);
		keyStore.store(out, password);
		out.close();
		
		

		ECPrivateKey pKey = (ECPrivateKey) kp.getPrivate();

		System.out.println("public key parameter Q");
		ECPublicKey publickey = (ECPublicKey) kp.getPublic();
		//printSecret(publickey);
		print("" + new BigInteger(1, publickey.getQ().getEncoded()).toString(16));
		// ECJavaPublicKeyGen.printSecret((ECPublicKey) kp.getPublic());

		ECPrivateKey privateKey = (ECPrivateKey) kp.getPrivate();
		System.out.println("private key parameter D");
		print("" + new BigInteger(1, privateKey.getD().toByteArray()).toString(16));

		System.out.println("public key");
		print("" + new BigInteger(1, publickey.getEncoded()).toString(16));

		System.out.println("private key");
		print("" + new BigInteger(1, privateKey.getEncoded()).toString(16));

		// ECJavaPublicKeyGen.printSecret((ECPrivateKey) kp.getPrivate());
		// ECJavaPublicKeyGen.printSecret((ECPublicKey) kp.getPublic());

		ECPrivateKey priv = (ECPrivateKey) kp.getPrivate();
		ECPublicKey pub = (ECPublicKey) kp.getPublic();
		// System.out.println(new BigInteger(1,
		// priv.getEncoded()).toString(16));
		// System.out.println(new BigInteger(1, pub.getEncoded()).toString(16));

		byte[] testPriv = priv.getEncoded();

		byte[] testPub = pub.getEncoded();
		
		// PrivateKey privateK = kf.generatePrivate(new
		// PKCS8EncodedKeySpec(lcpPrivateKey));
		//ECPublicKey publicK = (ECPublicKey) kf.generatePublic(new X509EncodedKeySpec(testPub));
		/*
		 * ECGenParameterSpec ecParamSpec = new
		 * ECGenParameterSpec("prime192v1"); ISigner signer =
		 * SignerUtilities.GetSigner("SHA-256withECDSA");
		 */

	}

	public static KeyPair generateECCKeyPair() throws NoSuchProviderException {
		try {
			ECGenParameterSpec ecParamSpec = new ECGenParameterSpec("prime192v1");
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
			kpg.initialize(ecParamSpec);
			return kpg.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e.getLocalizedMessage());
		} catch (InvalidAlgorithmParameterException e) {
			throw new IllegalStateException(e.getLocalizedMessage());
		}
	}

	public static void printSecret(ECPrivateKey key) {
		System.out.println("S: " + new BigInteger(1, key.getD().toByteArray()).toString(16));
	}

	public static void printSecret(ECPublicKey key) {
		System.out.println("W: " + new BigInteger(1, key.getQ().getEncoded()).toString(16));
	}

	public static void print(String byteText) {
		for (int i = 0; i < byteText.length(); i++) {
			System.out.print("(byte) 0x" + byteText.charAt(i));
			if (i != byteText.length() - 1) {
				i++;
				System.out.print(byteText.charAt(i));
			}

			if (i != byteText.length() - 1)
				System.out.print(", ");
		}
		System.out.println();
	}

	public static X509Certificate generateCertificate(KeyPair keyPair,PrivateKey LCPprivateKey)
			throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException,
			SignatureException, OperatorCreationException, CertificateException, IOException {
		Date startDate = new Date();
		Date expiryDate = new Date(2016, 12, 31, 23, 59, 59);
		BigInteger serialNumber = new BigInteger("" + 4); // serial number for
															// certificate
		// keypair is the EC public/private key pair
		X500Principal dnName = new X500Principal("CN=CA Delhaize certificate");
		ContentSigner signer = new JcaContentSignerBuilder("SHA1withECDSA").build(LCPprivateKey);

		X509v1CertificateBuilder v1CertGen = new JcaX509v1CertificateBuilder(dnName, serialNumber, startDate,
				expiryDate, dnName, keyPair.getPublic());
		X509CertificateHolder holder = v1CertGen.build(signer);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		InputStream certIs = new ByteArrayInputStream(holder.getEncoded());
		X509Certificate cert = (X509Certificate) cf.generateCertificate(certIs);

		System.out.println(cert);
		return cert;
	}

}
