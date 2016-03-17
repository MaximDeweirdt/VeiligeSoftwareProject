import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECJavaPublicKeyGen {
	public static void main(String[] args) throws Exception{
		Security.addProvider(new BouncyCastleProvider());
		
		KeyPair kp = ECJavaPublicKeyGen.generateECCKeyPair();
		
		ECPrivateKey pKey = (ECPrivateKey)kp.getPrivate();
		System.out.println("private key");
		print("" + new BigInteger(1, pKey.getD().toByteArray()).toString(16));
		
		System.out.println();
		System.out.println("public key");
		ECPublicKey publickey = (ECPublicKey) kp.getPublic();
		print("" + new BigInteger(1, publickey.getQ().getEncoded()).toString(16));
		//ECJavaPublicKeyGen.printSecret((ECPublicKey) kp.getPublic());
		
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
