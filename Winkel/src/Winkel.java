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
}
