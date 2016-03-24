import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

import org.bouncycastle.asn1.x9.DHPublicKey;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;

public class SercureConnectionMain {

	public static byte[] privateKeyCardBytes = new byte[] { (byte) 0x30, (byte) 0x7b, (byte) 0x02, (byte) 0x01,
			(byte) 0x00, (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48,
			(byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86,
			(byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0x04, (byte) 0x61,
			(byte) 0x30, (byte) 0x5f, (byte) 0x02, (byte) 0x01, (byte) 0x01, (byte) 0x04, (byte) 0x18, (byte) 0x7e,
			(byte) 0x2d, (byte) 0xec, (byte) 0x75, (byte) 0xc2, (byte) 0xac, (byte) 0xee, (byte) 0x8d, (byte) 0x50,
			(byte) 0x62, (byte) 0x28, (byte) 0x05, (byte) 0x7e, (byte) 0x9a, (byte) 0x7d, (byte) 0x18, (byte) 0x9a,
			(byte) 0xb1, (byte) 0x23, (byte) 0xac, (byte) 0xf4, (byte) 0x4e, (byte) 0x32, (byte) 0x68, (byte) 0xa0,
			(byte) 0x0a, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d,
			(byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0xa1, (byte) 0x34, (byte) 0x03, (byte) 0x32, (byte) 0x00,
			(byte) 0x04, (byte) 0x22, (byte) 0x11, (byte) 0x21, (byte) 0xbd, (byte) 0x7d, (byte) 0xf3, (byte) 0x47,
			(byte) 0xfd, (byte) 0xfe, (byte) 0x3e, (byte) 0x89, (byte) 0x5d, (byte) 0xe0, (byte) 0x02, (byte) 0x65,
			(byte) 0xb3, (byte) 0x5c, (byte) 0x49, (byte) 0x91, (byte) 0x28, (byte) 0x71, (byte) 0x66, (byte) 0x2e,
			(byte) 0x29, (byte) 0xa3, (byte) 0xdf, (byte) 0x73, (byte) 0x5a, (byte) 0x52, (byte) 0x87, (byte) 0x50,
			(byte) 0x79, (byte) 0xd7, (byte) 0x5c, (byte) 0x3d, (byte) 0x56, (byte) 0x70, (byte) 0x76, (byte) 0xca,
			(byte) 0xaf, (byte) 0xad, (byte) 0x2e, (byte) 0xaf, (byte) 0x07, (byte) 0xc3, (byte) 0xa4, (byte) 0x76,
			(byte) 0xdf };

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
		PublicKey publickeycard = kf.generatePublic(new X509EncodedKeySpec(cardCert.getPublicKey().getEncoded()));
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
		PublicKey publickeycolruyt = kf.generatePublic(new X509EncodedKeySpec(colruytCert.getPublicKey().getEncoded()));
		// get the private key from colruyt
		
		ECPrivateKey privatekeycolruyt = (ECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyColruytBytes));
		
		KeyAgreement keyAgreementInTheCard = KeyAgreement.getInstance("ECDH", "BC");
		KeyAgreement keyAgreementInColruyt = KeyAgreement.getInstance("ECDH", "BC");
		
		//set the private keys for the DH symmetric key gen
		keyAgreementInTheCard.init(privatekeycard);	
		keyAgreementInColruyt.init(privatekeycolruyt);

		keyAgreementInTheCard.doPhase(publickeycolruyt, true);
		keyAgreementInColruyt.doPhase(publickeycard, true);

		MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
		System.out.println(new String(hash.digest(keyAgreementInTheCard.generateSecret())));
		System.out.println(new String(hash.digest(keyAgreementInColruyt.generateSecret())));

	}

}
