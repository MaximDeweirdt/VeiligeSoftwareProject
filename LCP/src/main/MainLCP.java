package main;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;

public class MainLCP {

	private static List<WinkelData> winkelDataList = new ArrayList<>();
	private static KeyStore keyStoreLCP;
	public static void main(String[] args) throws IOException, ClassNotFoundException {
		
		winkelDataList = makeWinkelData();
		
		try {
			// create on port 1099
			Registry registry = LocateRegistry.createRegistry(3999);
			
			registry.rebind("dispatchermethodes", new LCPMethods());
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("LCP is ready on port 3999");
		
	}
	private static List<WinkelData> makeWinkelData() throws ClassNotFoundException, IOException {
		
		List<WinkelData> wdList = new ArrayList<>();

		Certificate cert = (Certificate) Certificate.deserialize(SecurityData.colruytCertificate);
		
		WinkelData wd = new WinkelData(cert, "Colruyt");
		wdList.add(wd);
		
		return wdList;
	}
}
		

