package main;

import java.io.File;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import java.security.cert.X509Certificate;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import gui.LCPGui;
import socketListeners.RegisterSocketListenerThread;
import socketListeners.RevalidateSocketListenerThread;
import socketListeners.UpdateSocketListenerThread;
import socketListeners.VerificationSocketListenerThread;

public class MainLCP {
	
	private static ECPrivateKey privateKeyLCP;
	private static ECPublicKey publicKeyLCP;
	private static X509Certificate cardCert;
	private static X509Certificate colruytCert;
	private static X509Certificate delhaizeCert;
	private static Map<X509Certificate,CertificateData> certList = new HashMap<X509Certificate, CertificateData>();
	
	
	
	
	public static void main(String[] args) throws Exception {
		
		new LCPGui();
		makeKeysAndCerts();
//		winkelDataList = makeWinkelData();
		
		int registerPort = 4443; // poort om een virtuele klantenkaart aan te vragen
		int verificationPort = 4444; //poort om certificaten te verifieren
		int updateLogPort = 4445; //poort om log up te daten? voor later te kunnen controleren
		int hervalidatiePort = 4446; // poort om log te controleren
		
		new RegisterSocketListenerThread(registerPort).start();
		new VerificationSocketListenerThread(verificationPort).start();
		new UpdateSocketListenerThread(updateLogPort).start();
		new RevalidateSocketListenerThread(hervalidatiePort).start();
	}


	private static void makeKeysAndCerts() throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		KeyFactory kf = KeyFactory.getInstance("EC", "BC"); 
		
		// get public key and private key
		setPublicKeyLCP((ECPublicKey) kf.generatePublic(new X509EncodedKeySpec(main.SecurityData.publicKey)));
		
		setPrivateKeyLCP((ECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(main.SecurityData.privateKey)));
		
		KeyStore keyStore = KeyStore.getInstance("JKS");
		String directoryNaam = "keystore";
		String bestandsNaam = "cardCert";
		
		String fileName = directoryNaam + "/" + bestandsNaam + "";
		File keystoreFile = new File(fileName);
		System.out.println(keystoreFile.exists());
		
		FileInputStream keyIn = new FileInputStream(keystoreFile);
		keyStore.load(keyIn, "kiwikiwi".toCharArray());
		
		setCardCert((X509Certificate)keyStore.getCertificate("cardCert"));
		addCertToList(getCardCert());
		
//		System.out.println("symmetric key with card = " + new BigInteger(1,secretKey.getEncoded()).toString(16));
		
		bestandsNaam = "Colruytcert";
		fileName = directoryNaam + "/" + bestandsNaam + "";
		keystoreFile = new File(fileName);
		System.out.println(keystoreFile.exists());
		
		keyIn = new FileInputStream(keystoreFile);
		keyStore.load(keyIn, "kiwikiwi".toCharArray());
		setColruytCert((X509Certificate)keyStore.getCertificate("Colruytcert"));
		
		addCertToList( getColruytCert());
		
		bestandsNaam = "DelhaizeCert";
		fileName = directoryNaam + "/" + bestandsNaam + "";
		keystoreFile = new File(fileName);
		System.out.println(keystoreFile.exists());
		
		keyIn = new FileInputStream(keystoreFile);
		keyStore.load(keyIn, "kiwikiwi".toCharArray());
		setDelhaizeCert((X509Certificate) keyStore.getCertificate(bestandsNaam));
		addCertToList( getDelhaizeCert());
		
	}


	public static ECPrivateKey getPrivateKeyLCP() {
		return privateKeyLCP;
	}


	public static void setPrivateKeyLCP(ECPrivateKey privateKeyLCP) {
		MainLCP.privateKeyLCP = privateKeyLCP;
	}


	public static ECPublicKey getPublicKeyLCP() {
		return publicKeyLCP;
	}


	public static void setPublicKeyLCP(ECPublicKey publicKeyLCP) {
		MainLCP.publicKeyLCP = publicKeyLCP;
	}


	public static X509Certificate getCardCert() {
		return cardCert;
	}


	public static void setCardCert(X509Certificate cardCert) {
		MainLCP.cardCert = cardCert;
		
	}

	public static Map<X509Certificate, CertificateData> getCertList() {
		return certList;
	}

	public static void addCertToList(X509Certificate virtualCardCert) {
		MainLCP.certList.put(virtualCardCert, new CertificateData());
		String [] tableEntry = {virtualCardCert.getIssuerDN().getName().substring(6), virtualCardCert.getSerialNumber().toString(), ""+certList.get(virtualCardCert).isValid()};
		LCPGui.addCertToTable(tableEntry);
	}


	public static X509Certificate getColruytCert() {
		return colruytCert;
	}


	public static void setColruytCert(X509Certificate colruytCert) {
		MainLCP.colruytCert = colruytCert;
	}


	public static X509Certificate getDelhaizeCert() {
		return delhaizeCert;
	}


	public static void setDelhaizeCert(X509Certificate delhaizeCert) {
		MainLCP.delhaizeCert = delhaizeCert;
	}
	
	public static void invalidateCert(X509Certificate cert){
		if(MainLCP.certList.containsKey(cert)){
			MainLCP.certList.get(cert).setValid(false);
		}
	}
	
	public static X509Certificate getCert(BigInteger serienummer){
		for(Map.Entry<X509Certificate, CertificateData> entry : certList.entrySet()){
			if(entry.getKey().getSerialNumber().equals(serienummer)) return entry.getKey();
		}
		return null;
	}
	
	public static boolean certIsValid(BigInteger serienummer){
		for(Map.Entry<X509Certificate, CertificateData> entry : certList.entrySet()){
			if(entry.getKey().getSerialNumber().equals(serienummer)) return certList.get(entry.getKey()).isValid();
		}
		return false;
	}
}
		

