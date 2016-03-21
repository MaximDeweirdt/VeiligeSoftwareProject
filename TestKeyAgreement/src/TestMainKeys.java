import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

public class TestMainKeys {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, ClassNotFoundException, IOException, InvalidKeySpecException {
		
		Certificate cardCert = (Certificate) Certificate.deserialize(SecurityData.cardCertificate);
		
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		EllipticCurve curve = new EllipticCurve(
				new ECFieldFp(new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16)),
				new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
				new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16));

		ECParameterSpec ecSpec = new ECParameterSpec(curve,
				new ECPoint(new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
						new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16)),
				new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), 1);

		keyGen.initialize(ecSpec, random);
		
		KeyFactory kf = KeyFactory.getInstance("EC"); // or "EC" or whatever
		PrivateKey pr = kf.generatePrivate(new PKCS8EncodedKeySpec(SecurityData.privateKeyCard));
		PublicKey pu = kf.generatePublic(new X509EncodedKeySpec(SecurityData.publicKeyCard));
		
		KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
		KeyPair aPair = keyGen.generateKeyPair();
		KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
		KeyPair bPair = keyGen.generateKeyPair();

		aKeyAgree.init(aPair.getPrivate());
		bKeyAgree.init(bPair.getPrivate());

		aKeyAgree.doPhase(bPair.getPublic(), true);
		bKeyAgree.doPhase(aPair.getPublic(), true);

		MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");

		System.out.println(new String(hash.digest(aKeyAgree.generateSecret())));
		System.out.println(new String(hash.digest(bKeyAgree.generateSecret())));

	}

}
