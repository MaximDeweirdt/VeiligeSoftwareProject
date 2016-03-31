import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

import org.bouncycastle.asn1.x9.DHPublicKey;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

public class SigningCert {
	public static byte[] privateKeyLCPbyte = new byte[]{
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
	
	private static byte[] publicKeyCARDbyte = new byte[]{
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
	
	
	
	public static void main(String []args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException, OperatorCreationException{
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		// get certificate of the card
		String directoryNaam = "keystore";
		String bestandsNaam = "cardCert";
		char[] password = "kiwikiwi".toCharArray();
		KeyStore keyStore = KeyStore.getInstance("JKS");
		String fileName = directoryNaam + "/" + bestandsNaam + "";
		File keystoreFile = new File(fileName);
		FileInputStream in = new FileInputStream(keystoreFile);
		keyStore.load(in, "kiwikiwi".toCharArray());
		X509Certificate  cardCert = (X509Certificate) keyStore.getCertificate("cardCert");
		
		
		
		KeyFactory kf = KeyFactory.getInstance("EC","BC"); // or "EC" or whatever
		ECPrivateKey privateKeyLCP = (ECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyLCPbyte));
		
		Signature signature = Signature.getInstance("SHA1withECDSA");
		signature.initSign(privateKeyLCP);
		signature.update(cardCert.getSignature());
		byte[] signedCert = signature.sign();
		
		ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privateKeyLCP);
		
		
		//new JcaX509CertificateConverter().setProvider("BC").getCertificate(cardCert.build(signer));
		
		//verify the signature
		ECPublicKey publicKeyLCP = (ECPublicKey) kf.generatePublic(new X509EncodedKeySpec(publicKeyCARDbyte));
		
		
		signature.initVerify(publicKeyLCP);
		System.out.println("verification = " + signature.verify(signedCert));
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
}
