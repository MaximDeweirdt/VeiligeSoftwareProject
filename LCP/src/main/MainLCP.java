package main;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.ServerSocket;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedActionException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import socketListeners.registerSocketListenerThread;
import socketListeners.verificationSocketListenerThread;
import socketThreads.LCPVerificationThread;

public class MainLCP {

	private static List<WinkelData> winkelDataList = new ArrayList<>();
	private static KeyStore keyStoreLCP;
	
	public static void main(String[] args) throws IOException, ClassNotFoundException {
		
//		winkelDataList = makeWinkelData();
		
		int registerPort = 4443; // Port where the SSL Server needs to listen for new requests from the client
		int verificationPort = 4444;
		
		
		new registerSocketListenerThread(registerPort).start();
		new verificationSocketListenerThread(verificationPort).start();
		
	}
}
		
