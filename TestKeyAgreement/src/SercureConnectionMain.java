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
import java.security.cert.CertificateException;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

import org.bouncycastle.asn1.x9.DHPublicKey;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;

public class SercureConnectionMain {

	public static byte[] privateKeyCardBytes = new byte[] { 
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

	public static byte[] privateKeyColruytBytes = new byte[] { (byte) 0x30, (byte) 0x7b, (byte) 0x02, (byte) 0x01,
			(byte) 0x00, (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48,
			(byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86,
			(byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0x04, (byte) 0x61,
			(byte) 0x30, (byte) 0x5f, (byte) 0x02, (byte) 0x01, (byte) 0x01, (byte) 0x04, (byte) 0x18, (byte) 0xc6,
			(byte) 0xe7, (byte) 0x5a, (byte) 0x84, (byte) 0xcb, (byte) 0x3c, (byte) 0x0a, (byte) 0x3d, (byte) 0x7a,
			(byte) 0xee, (byte) 0x71, (byte) 0xbc, (byte) 0x4d, (byte) 0x9d, (byte) 0xc0, (byte) 0x00, (byte) 0xa3,
			(byte) 0x95, (byte) 0x34, (byte) 0x67, (byte) 0x2f, (byte) 0x4e, (byte) 0x10, (byte) 0x77, (byte) 0xa0,
			(byte) 0x0a, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d,
			(byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0xa1, (byte) 0x34, (byte) 0x03, (byte) 0x32, (byte) 0x00,
			(byte) 0x04, (byte) 0x44, (byte) 0xfd, (byte) 0x27, (byte) 0x94, (byte) 0xf9, (byte) 0xa8, (byte) 0x67,
			(byte) 0x25, (byte) 0x2e, (byte) 0x02, (byte) 0x2c, (byte) 0xf0, (byte) 0xfc, (byte) 0x0e, (byte) 0xe7,
			(byte) 0xb6, (byte) 0x1c, (byte) 0x82, (byte) 0xf8, (byte) 0xbe, (byte) 0x4e, (byte) 0x72, (byte) 0x8a,
			(byte) 0x0b, (byte) 0x7f, (byte) 0x46, (byte) 0x7a, (byte) 0xab, (byte) 0x82, (byte) 0x5b, (byte) 0x2b,
			(byte) 0x03, (byte) 0x6e, (byte) 0x80, (byte) 0xbc, (byte) 0x3f, (byte) 0xa8, (byte) 0x22, (byte) 0x0e,
			(byte) 0xdd, (byte) 0x95, (byte) 0x58, (byte) 0x55, (byte) 0x8a, (byte) 0x40, (byte) 0xf9, (byte) 0xcd,
			(byte) 0x6e };
	
	private static byte[] publicKeyLCPbyte = new byte[]{
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
	// algorithm = SHA1withECDSA
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException,
			CertificateException, IOException, InvalidKeySpecException, InvalidKeyException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());


		// get certificate of the card
		String directoryNaam = "keystore";
		String bestandsNaam = "cardCert";
		char[] password = "kiwikiwi".toCharArray();
		KeyStore keyStore = KeyStore.getInstance("JKS");
		String fileName = directoryNaam + "/" + bestandsNaam + "";
		File keystoreFile = new File(fileName);
		System.out.println(keystoreFile.exists());
		FileInputStream in = new FileInputStream(keystoreFile);
		keyStore.load(in, "kiwikiwi".toCharArray());
		java.security.cert.Certificate cardCert = keyStore.getCertificate("cardCert");
		
		KeyFactory kf = KeyFactory.getInstance("EC","BC"); // or "EC" or whatever
		
		// get public key from the certificate of card
		ECPublicKey publickeycard = (ECPublicKey) kf.generatePublic(new X509EncodedKeySpec(cardCert.getPublicKey().getEncoded()));
	//	PublicKey publickeycard =  cardCert.getPublicKey();
		// get the private key from the card
		
		ECPrivateKey privatekeycard = (ECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyCardBytes));

		// get certificate of colruyt
		bestandsNaam = "Colruytcert";
		fileName = directoryNaam + "/" + bestandsNaam + "";
		keyStore = KeyStore.getInstance("JKS");
		keystoreFile = new File(fileName);
		System.out.println(keystoreFile.exists());
		in = new FileInputStream(keystoreFile);
		keyStore.load(in, "kiwikiwi".toCharArray());
		java.security.cert.Certificate colruytCert = keyStore.getCertificate("Colruytcert");

		// get public key from the certificate of colruyt
		ECPublicKey publickeycolruyt = (ECPublicKey) kf.generatePublic(new X509EncodedKeySpec(colruytCert.getPublicKey().getEncoded()));
		
		//private and public from LCP out of byte array
		ECPublicKey publickyLCP = (ECPublicKey) kf.generatePublic(new X509EncodedKeySpec(publicKeyLCPbyte));
		ECPrivateKey privatekyLCP = (ECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyLCPbyte));
		
		// get the private key from colruyt	
		System.out.println("symmetric key = " + new BigInteger(1,kf.generatePublic(new X509EncodedKeySpec(publicKeyLCPbyte)).getEncoded()).toString(16));
		print("0"  + new BigInteger(1,publickeycard.getQ().getEncoded()).toString(16));
		System.out.println("" + new BigInteger(1,kf.generatePublic(new X509EncodedKeySpec(publicKeyLCPbyte)).getEncoded()).toString(16));
		ECPrivateKey privatekeycolruyt = (ECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyColruytBytes));
		KeyAgreement keyAgreementInTheCard = KeyAgreement.getInstance("ECDH", "BC");
		KeyAgreement keyAgreementInColruyt = KeyAgreement.getInstance("ECDH", "BC");
		KeyAgreement keyAgreementLCP = KeyAgreement.getInstance("ECDH", "BC");
		
		//set the private keys for the DH symmetric key gen
		keyAgreementInTheCard.init(privatekeycard);	
		keyAgreementInColruyt.init(privatekeycolruyt);
		keyAgreementLCP.init(privatekyLCP);
		
		keyAgreementInTheCard.doPhase(publickyLCP, true);
		keyAgreementInColruyt.doPhase(publickeycard, true);
		keyAgreementLCP.doPhase(publickeycard, true);
		
		MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
		System.out.println("symmetric key card= " + new BigInteger(1,hash.digest(keyAgreementInTheCard.generateSecret())).toString(16));
		System.out.println("symmetric key LCP= " + new BigInteger(1,hash.digest(keyAgreementLCP.generateSecret())).toString(16));
		System.out.println();
		System.out.println("" + new BigInteger(1,((hash.digest(keyAgreementLCP.generateSecret())))).toString(16));
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
