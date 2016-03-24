import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECJavaPublicKeyGen {
	public static void main(String[] args) throws Exception{
		Security.addProvider(new BouncyCastleProvider());
		
		KeyPair kp = ECJavaPublicKeyGen.generateECCKeyPair();
		
		String directoryNaam = "pornomap";
		String bestandsNaam = "pornoprentje1";
		
		KeyStore keyStore = KeyStore.getInstance("JKS");
		String fileName = directoryNaam + bestandsNaam + ".jks";
		
		FileInputStream fis = new FileInputStream(fileName);
		keyStore.load(fis, "kiwikiwi".toCharArray());
		
		
		
		ECPrivateKey pKey = (ECPrivateKey)kp.getPrivate();
		/*System.out.println("private key");
		print("" + new BigInteger(1, pKey.getD().toByteArray()).toString(16));*/
		
		System.out.println("public key parameter Q");
		ECPublicKey publickey = (ECPublicKey) kp.getPublic();
		print("" + new BigInteger(1, publickey.getQ().getEncoded()).toString(16));
		//ECJavaPublicKeyGen.printSecret((ECPublicKey) kp.getPublic());
		
		ECPrivateKey privateKey = (ECPrivateKey) kp.getPrivate();
		System.out.println("private key parameter D");
		print("" + new BigInteger(1, privateKey.getD().toByteArray()).toString(16));
		
		System.out.println("public key");
		print("" + new BigInteger(1,publickey.getEncoded()).toString(16));
		
		System.out.println("private key");
		print("" + new BigInteger(1,privateKey.getEncoded()).toString(16));
		
		//ECJavaPublicKeyGen.printSecret((ECPrivateKey) kp.getPrivate());
		//ECJavaPublicKeyGen.printSecret((ECPublicKey) kp.getPublic());
		
		PrivateKey priv =  kp.getPrivate();
		PublicKey pub = kp.getPublic();
		//System.out.println(new BigInteger(1, priv.getEncoded()).toString(16));
		//System.out.println(new BigInteger(1, pub.getEncoded()).toString(16));
		
		byte[] testPriv = priv.getEncoded();
		
		
		byte[] testPub = pub.getEncoded();
		KeyFactory kf = KeyFactory.getInstance("EC"); // or "EC" or whatever
		//PrivateKey privateK = kf.generatePrivate(new PKCS8EncodedKeySpec(lcpPrivateKey));
		PublicKey publicK = kf.generatePublic(new X509EncodedKeySpec(testPub));
		/*ECGenParameterSpec ecParamSpec = new ECGenParameterSpec("prime192v1");
	    ISigner signer = SignerUtilities.GetSigner("SHA-256withECDSA");*/
		
	}
	
	public static KeyPair generateECCKeyPair() throws NoSuchProviderException{
		try{
			ECGenParameterSpec ecParamSpec = new ECGenParameterSpec("prime192v1");
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
			kpg.initialize(ecParamSpec);
			return kpg.generateKeyPair();
		} catch(NoSuchAlgorithmException e){
			throw new IllegalStateException(e.getLocalizedMessage());
		} catch(InvalidAlgorithmParameterException e){
			throw new IllegalStateException(e.getLocalizedMessage());
		}
	}
	
	public static void printSecret(ECPrivateKey key){
		System.out.println("S: "+ new BigInteger(1, key.getD().toByteArray()).toString(16));
	}
	
	public static void printSecret(ECPublicKey key){
		System.out.println("W: "+ new BigInteger(1, key.getQ().getEncoded()).toString(16));
	}
	
	public static void print(String byteText){
		for(int i = 0; i < byteText.length(); i++){
			System.out.print("(byte) 0x" + byteText.charAt(i));
			if(i!=byteText.length()-1){
				i++;
				System.out.print(byteText.charAt(i));
			}
			
			if(i!=byteText.length()-1)System.out.print(", ");
		}
		System.out.println();
	}
}
