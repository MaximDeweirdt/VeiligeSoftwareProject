package socketListeners;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.atomic.AtomicLong;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.asn1.x9.DHPublicKey;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import main.SecurityData;
import protocols.LCPProtocol;
import socketThreads.LCPVerificationThread;
import socketThreads.RegisterThread;

public class RegisterSocketListenerThread extends Thread {

	private ServerSocket ss;
	private static AtomicLong cardShopID = new AtomicLong();
	
	public RegisterSocketListenerThread(int registerPort) throws IOException {
		super("registerSocketListenerThread");
		ss = new ServerSocket(registerPort);

	}

	public void run() {
		
			
		System.out.println("RegisterSocket Ready with secretKey");
		while (true) {
			try {
				new RegisterThread(ss.accept()).start();
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
	}

	public static AtomicLong getCardShopID() {
		return cardShopID;
	}
}
