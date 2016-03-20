import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import javax.crypto.KeyAgreement;

public class Winkel {

	private String winkelNaam;

	public Winkel(String winkelNaam) {
		this.winkelNaam = winkelNaam;
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	public String getWinkelNaam() {
		return winkelNaam;
	}

	public void puntenToevoegen(int punten) {
		System.out.println("Er worden " + punten + " punten toegevoegd");
	}

	public void startGUI() {
		WinkelGUI gui = new WinkelGUI(this);
		gui.setVisible(true);
	}

	private void setUpKeyAgreement() throws NoSuchAlgorithmException, NoSuchProviderException,
			InvalidAlgorithmParameterException, InvalidKeyException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		EllipticCurve curve = new EllipticCurve(
				new ECFieldFp(new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16)),
				new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16),
				new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16));

		ECParameterSpec ecSpec = new ECParameterSpec(curve,
				new ECPoint(new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
						new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16)),
				new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), 1);

		keyGen.initialize(ecSpec, random);
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
