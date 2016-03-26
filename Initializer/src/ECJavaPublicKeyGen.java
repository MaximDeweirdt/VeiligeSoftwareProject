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
import java.security.PublicKey;
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
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		KeyPair kp = ECJavaPublicKeyGen.generateECCKeyPair();

		String directoryNaam = "keystore";
		String bestandsNaam = "Colruytcert";
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
		X509Certificate certificate = generateCertificate1(kp);
		keyStore.setCertificateEntry("LCPcert", certificate);
		// Save the new keystore contents
		FileOutputStream out = new FileOutputStream(keystoreFile);
		keyStore.store(out, password);
		out.close();
		
		
		/*// Store Public Key.
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(kp.getPublic().getEncoded());
		out = new FileOutputStream(keystoreFile);
		out.write(x509EncodedKeySpec.getEncoded());
		out.close();

		// Store Private Key.
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded());
		out = new FileOutputStream(keystoreFile);
		out.write(pkcs8EncodedKeySpec.getEncoded());
		out.close();*/

		// System.out.println(certificate);

		ECPrivateKey pKey = (ECPrivateKey) kp.getPrivate();

		System.out.println("public key parameter Q");
		ECPublicKey publickey = (ECPublicKey) kp.getPublic();
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

		PrivateKey priv = kp.getPrivate();
		PublicKey pub = kp.getPublic();
		// System.out.println(new BigInteger(1,
		// priv.getEncoded()).toString(16));
		// System.out.println(new BigInteger(1, pub.getEncoded()).toString(16));

		byte[] testPriv = priv.getEncoded();

		byte[] testPub = pub.getEncoded();
		KeyFactory kf = KeyFactory.getInstance("EC"); // or "EC" or whatever
		// PrivateKey privateK = kf.generatePrivate(new
		// PKCS8EncodedKeySpec(lcpPrivateKey));
		PublicKey publicK = kf.generatePublic(new X509EncodedKeySpec(testPub));
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

	public static X509Certificate generateCertificate1(KeyPair keyPair)
			throws InvalidKeyException, IllegalStateException, NoSuchProviderException,
			NoSuchAlgorithmException, SignatureException, OperatorCreationException, CertificateException, IOException {
		Date startDate = new Date();
		Date expiryDate = new Date(2016, 12, 31, 23, 59, 59);
		BigInteger serialNumber = new BigInteger("" + 3); // serial number for certificate
		// keypair is the EC public/private key pair
		X500Principal dnName = new X500Principal("CN=CA Colruy certificate");
		ContentSigner signer = new JcaContentSignerBuilder("SHA1withECDSA").build(keyPair.getPrivate());

		X509v1CertificateBuilder v1CertGen = new JcaX509v1CertificateBuilder(
				dnName, 
				serialNumber, 
				startDate,
				expiryDate, 
				dnName, 
				keyPair.getPublic()
			);
		X509CertificateHolder holder = v1CertGen.build(signer);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");  
	    InputStream certIs = new ByteArrayInputStream(holder.getEncoded()); 
	    X509Certificate  cert = (X509Certificate) cf.generateCertificate(certIs); 
		
	    System.out.println(cert);
		return cert;
	}

	public static X509Certificate generateCertificate(KeyPair keyPair)
			throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException,
			SignatureException, OperatorCreationException, CertificateException, IOException {
		Date startDate = new Date();
		Date expiryDate = new Date(2016, 12, 31, 23, 59, 59);
		BigInteger serialNumber = new BigInteger("" + 2); // serial number for
															// certificate
		// keypair is the EC public/private key pair
		X500Principal dnName = new X500Principal("CN=CA LCP certificate");
		ContentSigner signer = new JcaContentSignerBuilder("SHA1withECDSA").build(keyPair.getPrivate());

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
