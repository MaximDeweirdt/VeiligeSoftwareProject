import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CertificateUpdate {
	private static byte[] publicKeyCardBytes = new byte[]{
			(byte) 0x30, (byte) 0x49, (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07, 
			(byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x02, 
			(byte) 0x01, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, 
			(byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0x03, 
			(byte) 0x32, (byte) 0x00, (byte) 0x04, (byte) 0x22, (byte) 0x11, (byte) 0x21, 
			(byte) 0xbd, (byte) 0x7d, (byte) 0xf3, (byte) 0x47, (byte) 0xfd, (byte) 0xfe, 
			(byte) 0x3e, (byte) 0x89, (byte) 0x5d, (byte) 0xe0, (byte) 0x02, (byte) 0x65, 
			(byte) 0xb3, (byte) 0x5c, (byte) 0x49, (byte) 0x91, (byte) 0x28, (byte) 0x71, 
			(byte) 0x66, (byte) 0x2e, (byte) 0x29, (byte) 0xa3, (byte) 0xdf, (byte) 0x73, 
			(byte) 0x5a, (byte) 0x52, (byte) 0x87, (byte) 0x50, (byte) 0x79, (byte) 0xd7, 
			(byte) 0x5c, (byte) 0x3d, (byte) 0x56, (byte) 0x70, (byte) 0x76, (byte) 0xca, 
			(byte) 0xaf, (byte) 0xad, (byte) 0x2e, (byte) 0xaf, (byte) 0x07, (byte) 0xc3, 
			(byte) 0xa4, (byte) 0x76, (byte) 0xdf

		};
	
	public static byte[] privateKeyCardBytes = new byte[]{
			(byte) 0x30, (byte) 0x7b, (byte) 0x02, (byte) 0x01, (byte) 0x00, (byte) 0x30, 
			(byte) 0x13, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48, 
			(byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01, (byte) 0x06, (byte) 0x08, 
			(byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x03, 
			(byte) 0x01, (byte) 0x01, (byte) 0x04, (byte) 0x61, (byte) 0x30, (byte) 0x5f, 
			(byte) 0x02, (byte) 0x01, (byte) 0x01, (byte) 0x04, (byte) 0x18, (byte) 0x7e, 
			(byte) 0x2d, (byte) 0xec, (byte) 0x75, (byte) 0xc2, (byte) 0xac, (byte) 0xee, 
			(byte) 0x8d, (byte) 0x50, (byte) 0x62, (byte) 0x28, (byte) 0x05, (byte) 0x7e, 
			(byte) 0x9a, (byte) 0x7d, (byte) 0x18, (byte) 0x9a, (byte) 0xb1, (byte) 0x23, 
			(byte) 0xac, (byte) 0xf4, (byte) 0x4e, (byte) 0x32, (byte) 0x68, (byte) 0xa0, 
			(byte) 0x0a, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, 
			(byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0xa1, 
			(byte) 0x34, (byte) 0x03, (byte) 0x32, (byte) 0x00, (byte) 0x04, (byte) 0x22, 
			(byte) 0x11, (byte) 0x21, (byte) 0xbd, (byte) 0x7d, (byte) 0xf3, (byte) 0x47, 
			(byte) 0xfd, (byte) 0xfe, (byte) 0x3e, (byte) 0x89, (byte) 0x5d, (byte) 0xe0, 
			(byte) 0x02, (byte) 0x65, (byte) 0xb3, (byte) 0x5c, (byte) 0x49, (byte) 0x91, 
			(byte) 0x28, (byte) 0x71, (byte) 0x66, (byte) 0x2e, (byte) 0x29, (byte) 0xa3, 
			(byte) 0xdf, (byte) 0x73, (byte) 0x5a, (byte) 0x52, (byte) 0x87, (byte) 0x50, 
			(byte) 0x79, (byte) 0xd7, (byte) 0x5c, (byte) 0x3d, (byte) 0x56, (byte) 0x70, 
			(byte) 0x76, (byte) 0xca, (byte) 0xaf, (byte) 0xad, (byte) 0x2e, (byte) 0xaf, 
			(byte) 0x07, (byte) 0xc3, (byte) 0xa4, (byte) 0x76, (byte) 0xdf

		};
	
	private static byte[] publicKeyLCPBytes = new byte[]{
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
	
	private static byte[] publicKeyColruytBytes = new byte[]{
			(byte) 0x30, (byte) 0x49, (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07, 
			(byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x02, 
			(byte) 0x01, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, 
			(byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0x03, 
			(byte) 0x32, (byte) 0x00, (byte) 0x04, (byte) 0x44, (byte) 0xfd, (byte) 0x27, 
			(byte) 0x94, (byte) 0xf9, (byte) 0xa8, (byte) 0x67, (byte) 0x25, (byte) 0x2e, 
			(byte) 0x02, (byte) 0x2c, (byte) 0xf0, (byte) 0xfc, (byte) 0x0e, (byte) 0xe7, 
			(byte) 0xb6, (byte) 0x1c, (byte) 0x82, (byte) 0xf8, (byte) 0xbe, (byte) 0x4e, 
			(byte) 0x72, (byte) 0x8a, (byte) 0x0b, (byte) 0x7f, (byte) 0x46, (byte) 0x7a, 
			(byte) 0xab, (byte) 0x82, (byte) 0x5b, (byte) 0x2b, (byte) 0x03, (byte) 0x6e, 
			(byte) 0x80, (byte) 0xbc, (byte) 0x3f, (byte) 0xa8, (byte) 0x22, (byte) 0x0e,
			(byte) 0xdd, (byte) 0x95, (byte) 0x58, (byte) 0x55, (byte) 0x8a, (byte) 0x40, 
			(byte) 0xf9, (byte) 0xcd, (byte) 0x6e

		};
	
	public static byte[] privateKeyColruytBytes = new byte[]{
			(byte) 0x30, (byte) 0x7b, (byte) 0x02, (byte) 0x01, (byte) 0x00, (byte) 0x30, 
			(byte) 0x13, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48, 
			(byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01, (byte) 0x06, (byte) 0x08, 
			(byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x03, 
			(byte) 0x01, (byte) 0x01, (byte) 0x04, (byte) 0x61, (byte) 0x30, (byte) 0x5f, 
			(byte) 0x02, (byte) 0x01, (byte) 0x01, (byte) 0x04, (byte) 0x18, (byte) 0xc6, 
			(byte) 0xe7, (byte) 0x5a, (byte) 0x84, (byte) 0xcb, (byte) 0x3c, (byte) 0x0a, 
			(byte) 0x3d, (byte) 0x7a, (byte) 0xee, (byte) 0x71, (byte) 0xbc, (byte) 0x4d, 
			(byte) 0x9d, (byte) 0xc0, (byte) 0x00, (byte) 0xa3, (byte) 0x95, (byte) 0x34, 
			(byte) 0x67, (byte) 0x2f, (byte) 0x4e, (byte) 0x10, (byte) 0x77, (byte) 0xa0, 
			(byte) 0x0a, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, 
			(byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0xa1, 
			(byte) 0x34, (byte) 0x03, (byte) 0x32, (byte) 0x00, (byte) 0x04, (byte) 0x44, 
			(byte) 0xfd, (byte) 0x27, (byte) 0x94, (byte) 0xf9, (byte) 0xa8, (byte) 0x67, 
			(byte) 0x25, (byte) 0x2e, (byte) 0x02, (byte) 0x2c, (byte) 0xf0, (byte) 0xfc, 
			(byte) 0x0e, (byte) 0xe7, (byte) 0xb6, (byte) 0x1c, (byte) 0x82, (byte) 0xf8, 
			(byte) 0xbe, (byte) 0x4e, (byte) 0x72, (byte) 0x8a, (byte) 0x0b, (byte) 0x7f, 
			(byte) 0x46, (byte) 0x7a, (byte) 0xab, (byte) 0x82, (byte) 0x5b, (byte) 0x2b, 
			(byte) 0x03, (byte) 0x6e, (byte) 0x80, (byte) 0xbc, (byte) 0x3f, (byte) 0xa8, 
			(byte) 0x22, (byte) 0x0e, (byte) 0xdd, (byte) 0x95, (byte) 0x58, (byte) 0x55, 
			(byte) 0x8a, (byte) 0x40, (byte) 0xf9, (byte) 0xcd, (byte) 0x6e
		};
	
	
	
	public static void main(String []args) throws NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, IllegalStateException, NoSuchProviderException, SignatureException, OperatorCreationException, KeyStoreException, InvalidKeySpecException{
		KeyFactory kf = KeyFactory.getInstance("EC"); // or "EC" or whatever
		//PublicKey publicKeyCard = kf.generatePublic(new X509EncodedKeySpec(publicKeyCardBytes));
		//PrivateKey privateKeyCard = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyCardBytes));
		
		//PublicKey publicKeyColruyt = kf.generatePublic(new X509EncodedKeySpec(publicKeyColruytBytes));
		//PrivateKey privateKeyColruyt = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyColruytBytes));
		
		PublicKey publicKeyLCP = kf.generatePublic(new X509EncodedKeySpec(publicKeyLCPBytes));
		PrivateKey privateKeyLCP = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyLCPBytes));
		
		KeyPair kpLCP = new KeyPair(publicKeyLCP, privateKeyLCP);
		
		String directoryNaam = "keystore";
		String bestandsNaam = "LCPcert";
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
		X509Certificate certificate = generateCertificate(kpLCP,privateKeyLCP);
		keyStore.setCertificateEntry("LCPcert", certificate);
		// Save the new keystore contents
		FileOutputStream out = new FileOutputStream(keystoreFile);
		keyStore.store(out, password);
		out.close();
	}
	
	public static X509Certificate generateCertificate(KeyPair keyPair,PrivateKey LCPprivateKey)
			throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException,
			SignatureException, OperatorCreationException, CertificateException, IOException {
		Date startDate = new Date();
		Date expiryDate = new Date(2016, 12, 31, 23, 59, 59);
		BigInteger serialNumber = new BigInteger("" + 1); // serial number for
															// certificate
		// keypair is the EC public/private key pair
		X500Principal dnName = new X500Principal("CN=CA LCP certificate");
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
