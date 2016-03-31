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

import org.bouncycastle.jce.interfaces.ECPublicKey;

public class mainCert {

	private static byte[] publicKeyParameterQ = new byte[]{
			(byte) 0x30, (byte) 0x49, (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07, 
			(byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x02, 
			(byte) 0x01, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, 
			(byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0x03, 
			(byte) 0x32, (byte) 0x00, (byte) 0x04, (byte) 0x26, (byte) 0xef, (byte) 0xb0, 
			(byte) 0xed, (byte) 0xdb, (byte) 0xd8, (byte) 0xca, (byte) 0x4b, (byte) 0x14, 
			(byte) 0xc6, (byte) 0x49, (byte) 0x6e, (byte) 0xa1, (byte) 0xfe, (byte) 0x4e, 
			(byte) 0xa9, (byte) 0x4d, (byte) 0x0e, (byte) 0x25, (byte) 0x85, (byte) 0x99, 
			(byte) 0x80, (byte) 0x81, (byte) 0x8c, (byte) 0x94, (byte) 0x55, (byte) 0x27, 
			(byte) 0x65, (byte) 0x1a, (byte) 0x96, (byte) 0xff, (byte) 0x08, (byte) 0xac, 
			(byte) 0x93, (byte) 0xc3, (byte) 0xdc, (byte) 0x5a, (byte) 0xb8, (byte) 0xf7, 
			(byte) 0x53, (byte) 0xba, (byte) 0xa7, (byte) 0xf7, (byte) 0x36, (byte) 0x6c, 
			(byte) 0xf1, (byte) 0x13, (byte) 0x37
		};
	
	public static void main(String[] args) throws IOException, ClassNotFoundException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException{
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		KeyFactory kf = KeyFactory.getInstance("EC","BC"); // or "EC" or whatever
		ECPublicKey publickeycard = (ECPublicKey) kf.generatePublic(new X509EncodedKeySpec(publicKeyParameterQ));
		String certtext = "0" +  new BigInteger(1, publickeycard.getQ().getEncoded()).toString(16);
		print(certtext);
		
		
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
