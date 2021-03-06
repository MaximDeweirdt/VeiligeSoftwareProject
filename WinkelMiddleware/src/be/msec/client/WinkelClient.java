package be.msec.client;

import be.msec.client.connection.Connection;
import be.msec.client.connection.IConnection;
import be.msec.client.connection.SimulatedConnection;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.*;
import javax.swing.JDialog;
import javax.swing.JOptionPane;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import com.sun.org.apache.xml.internal.security.utils.Base64;

public class WinkelClient {

	private final static byte IDENTITY_CARD_CLA =(byte)0x80;
	private static final byte VALIDATE_PIN_INS = 0x01;
	
	private static final byte KEY_AGREEMENT_LCP_INS = 0x02;
	//private static final byte ENCRYPT_DATA_LCP_INS = 0x03;
	//private static final byte DECRYPT_DATA_LCP_INS = 0x04;
	private static final byte SET_ID_SHOP_INS = 0x05;
	private static final byte SET_PSEUDONIEM_INS = 0x06;
	private static final byte GET_PART1_CERTIFICATE = 0x07;
	private static final byte GET_PART2_CERTIFICATE = 0x08;
	private static final byte CHECK_CERT_INS = 0x09;
	private static final byte ENCRYPT_SHOP_ID_INS = 0x11;
	
	
	private static final byte REQ_PSEUDONIEM_INS = 0x40;
	private static final byte CERT_SHOP_INFO_INS = 0x41;
	private static final byte KEY_AGREEMENT_SHOP_INS = 0x42;
	private static final byte DECRYPT_SHOP_TEXT_INS = 0x43;
	private static final byte REQ_SHOP_POINTS_INS = 0x44;
	private static final byte UPD_POINTS_INS = 0x45;
	private static final byte REQ_TRANS_AMOUNT = 0x46;
	private static final byte REQ_TRANS_BUFFER = 0x47;
	private static final byte CHECK_TRANS_AMOUNT_INS = 0x48;
	
	
	
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	
	private static final Scanner SCANNER = new Scanner(System.in);
	/**
	 * @param args
	 */
	public static byte[] cardCertificate ={
			(byte) 0x30, (byte) 0x82, (byte) 0x01, (byte) 0x03, (byte) 0x30, (byte) 0x81, (byte) 0xbb, (byte) 0x02, (byte) 0x01, (byte) 0x02, (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x04, (byte) 0x01, (byte) 0x30, (byte) 0x1e, (byte) 0x31, (byte) 0x1c, (byte) 0x30, (byte) 0x1a, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x13, (byte) 0x13, (byte) 0x43, (byte) 0x41, (byte) 0x20, (byte) 0x63, (byte) 0x61, (byte) 0x72, (byte) 0x64, (byte) 0x20, (byte) 0x63, (byte) 0x65, (byte) 0x72, (byte) 0x74, (byte) 0x69, (byte) 0x66, (byte) 0x69, (byte) 0x63, (byte) 0x61, (byte) 0x74, (byte) 0x65, (byte) 0x30, (byte) 0x20, (byte) 0x17, (byte) 0x0d, (byte) 0x31, (byte) 0x36, (byte) 0x30, (byte) 0x33, (byte) 0x33, (byte) 0x31, (byte) 0x31, (byte) 0x33, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x33, (byte) 0x5a, (byte) 0x18, (byte) 0x0f, (byte) 0x33, (byte) 0x39, (byte) 0x31, (byte) 0x37, (byte) 0x30, (byte) 0x31, (byte) 0x33, (byte) 0x31, (byte) 0x32, (byte) 0x32, (byte) 0x35, (byte) 0x39, (byte) 0x35, (byte) 0x39, (byte) 0x5a, (byte) 0x30, (byte) 0x1e, (byte) 0x31, (byte) 0x1c, (byte) 0x30, (byte) 0x1a, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x13, (byte) 0x13, (byte) 0x43, (byte) 0x41, (byte) 0x20, (byte) 0x63, (byte) 0x61, (byte) 0x72, (byte) 0x64, (byte) 0x20, (byte) 0x63, (byte) 0x65, (byte) 0x72, (byte) 0x74, (byte) 0x69, (byte) 0x66, (byte) 0x69, (byte) 0x63, (byte) 0x61, (byte) 0x74, (byte) 0x65, (byte) 0x30, (byte) 0x49, (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0x03, (byte) 0x32, (byte) 0x00, (byte) 0x04, (byte) 0x22, (byte) 0x11, (byte) 0x21, (byte) 0xbd, (byte) 0x7d, (byte) 0xf3, (byte) 0x47, (byte) 0xfd, (byte) 0xfe, (byte) 0x3e, (byte) 0x89, (byte) 0x5d, (byte) 0xe0, (byte) 0x02, (byte) 0x65, (byte) 0xb3, (byte) 0x5c, (byte) 0x49, (byte) 0x91, (byte) 0x28, (byte) 0x71, (byte) 0x66, (byte) 0x2e, (byte) 0x29, (byte) 0xa3, (byte) 0xdf, (byte) 0x73, (byte) 0x5a, (byte) 0x52, (byte) 0x87, (byte) 0x50, (byte) 0x79, (byte) 0xd7, (byte) 0x5c, (byte) 0x3d, (byte) 0x56, (byte) 0x70, (byte) 0x76, (byte) 0xca, (byte) 0xaf, (byte) 0xad, (byte) 0x2e, (byte) 0xaf, (byte) 0x07, (byte) 0xc3, (byte) 0xa4, (byte) 0x76, (byte) 0xdf, (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x04, (byte) 0x01, (byte) 0x03, (byte) 0x38, (byte) 0x00, (byte) 0x30, (byte) 0x35, (byte) 0x02, (byte) 0x19, (byte) 0x00, (byte) 0xe1, (byte) 0x10, (byte) 0x53, (byte) 0x30, (byte) 0xbb, (byte) 0x7a, (byte) 0x1a, (byte) 0xd1, (byte) 0x90, (byte) 0x15, (byte) 0xca, (byte) 0x3d, (byte) 0xe8, (byte) 0x13, (byte) 0x87, (byte) 0x5c, (byte) 0xaf, (byte) 0x81, (byte) 0xb0, (byte) 0x32, (byte) 0xe7, (byte) 0x30, (byte) 0x56, (byte) 0x22, (byte) 0x02, (byte) 0x18, (byte) 0x30, (byte) 0x02, (byte) 0x12, (byte) 0xa9, (byte) 0x01, (byte) 0xf6, (byte) 0x6e, (byte) 0x35, (byte) 0xce, (byte) 0xba, (byte) 0x25, (byte) 0x35, (byte) 0xd6, (byte) 0x7e, (byte) 0x9f, (byte) 0xf7, (byte) 0x79, (byte) 0xe5, (byte) 0x8f, (byte) 0xc2, (byte) 0x69, (byte) 0x23, (byte) 0x2c, (byte) 0x41
	};
	private static byte[] publicKeyParameterQFromLCP = new byte[]{
			(byte) 0x04, (byte) 0xa9, (byte) 0xfe, (byte) 0x35, (byte) 0x45, (byte) 0xf0, 
			(byte) 0xaf, (byte) 0x79, (byte) 0x60, (byte) 0x8f, (byte) 0xd5, (byte) 0x79, 
			(byte) 0x09, (byte) 0xcb, (byte) 0x32, (byte) 0x9b, (byte) 0x77, (byte) 0xde, 
			(byte) 0x96, (byte) 0x8a, (byte) 0x9c, (byte) 0x2e, (byte) 0x3f, (byte) 0x3c, 
			(byte) 0x63, (byte) 0x8d, (byte) 0xc4, (byte) 0x36, (byte) 0x94, (byte) 0x3e, 
			(byte) 0x62, (byte) 0x1c, (byte) 0x95, (byte) 0xb3, (byte) 0xa0, (byte) 0x4b, 
			(byte) 0x3b, (byte) 0x90, (byte) 0xab, (byte) 0x0b, (byte) 0xdf, (byte) 0x14, 
			(byte) 0x19, (byte) 0xba, (byte) 0x0a, (byte) 0xed, (byte) 0x4d, (byte) 0x90, 
			(byte) 0x2c

		};
	
	public static void main(String[] args) throws Exception {
		WinkelMiddelwareGUI gui = new WinkelMiddelwareGUI();
		IConnection c;
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		//Real Card:
		c = new Connection();
		((Connection)c).setTerminal(0); //depending on which cardreader you use
		
		c.connect(); 
		
		String hostname = "localhost";
		int verifyCertPortNumber = 4444;
		
		int winkelStartPortNumber = 5000;
		int winkelPortNumber;
		
		Socket verifyCertSocket = new Socket(hostname, verifyCertPortNumber);
		
		Socket winkelSocket;
		
		ObjectOutputStream verifyOut = new ObjectOutputStream(verifyCertSocket.getOutputStream());
		ObjectInputStream verifyIn = new ObjectInputStream(verifyCertSocket.getInputStream());
		
		ObjectOutputStream winkelOut;
		ObjectInputStream winkelIn;
		
		WinkelMiddelwareGUI.addText("winkelkeuze = ");
		JDialog.setDefaultLookAndFeelDecorated(true);
		byte [] winkelKeuze;
		String [] keuzes = {"Colruyt", "Delhaize", "Alienware", "Razor"};
		String winkel = (String) JOptionPane.showInputDialog(null, "Kies een winkel", "Winkel kiezen", JOptionPane.QUESTION_MESSAGE, null, keuzes, keuzes[0]);
		WinkelMiddelwareGUI.addText(winkel);
		int winkelNummer = 0;
		if(winkel == null || (winkel != null && winkel.equals(""))) System.exit(0);
		else if(winkel.equals("Colruyt")) winkelNummer = 0;
		else if(winkel.equals("Delhaize")) winkelNummer = 1;
		else if(winkel.equals("Alienware")) winkelNummer = 2;
		else  winkelNummer = 3;
		winkelKeuze = shortToByte((short) winkelNummer);
		winkelPortNumber = winkelStartPortNumber + winkelNummer; 
		
		winkelSocket = new Socket(hostname, winkelPortNumber);
		
		winkelOut = new ObjectOutputStream(winkelSocket.getOutputStream());
		winkelIn = new ObjectInputStream(winkelSocket.getInputStream());
		
		Object ob;
		
		try {

			CommandAPDU a = null;
			ResponseAPDU r = null;

			//Send PIN
			byte[] pin = new byte[]{0x01,0x02,0x03,0x04};
			loginCard(a,r,c,pin);
			
			//opvragen van het certificaat van de kaart
			byte[] cardCert = requestCertificate(a, r, c);
			
			//certificaat naar de LCP sturen voor keyAgreement
			verifyOut.writeObject(cardCert);
			//keyagreement in de kaart met de LCP
			keyAgreementLCPAndCard(a,r,c);
			
			byte[] input = (byte[])verifyIn.readObject();
			boolean correctCert = checkCorrectCertificate(a,r,c,input);
			if(correctCert==false){
				loginCard(a,r,c,pin);
			}
			else{
				//certificaat van de winkel vragen om te controleren of de winkel betrouwbaar is
				//terwijl ook eigen psuedoniem certificaat naar de winkel sturen zodat deze kan controleren of die nog geldig is
				
				winkelOut.writeObject("gimmeCert");
				input = (byte[])winkelIn.readObject();//het ganse X509 certificaat dat doorgestuurd wordt naar de LCP voor controle
	
				verifyOut.writeObject(input);
				input = (byte[]) verifyIn.readObject();
				if(input.length==8){
					WinkelMiddelwareGUI.addText("winkelCertificaat niet geldig");
				}
				else{
					System.out.println("input =" + new BigInteger(1,input).toString(16));
					// hier dan mss best da eenvoudig certificaat returnen, ofwel accepted of denied
					/* als we me accepted en denied werken, moeten we daarna weer aan de winkel het eenvoudig certificaat vragen,
					 * met die public key parameter. probleem daarmee is da de winkel het correcte certificaat kan sturen eerst en
					 * daarna ne foute parameter voor die key en dan ist nie veilig
					 * 
					 * we kunnen als het klopt da eenvoudig certificaat terug sturen, als het niet klopt denied en dan kunde in 
					 * de kaart aan de lengte ervan zien of het just is of niet zeker
					 * 
					 * dus deze input is da eenvoudig certificaat voorlopig
					 * bestaande uit: {qparameter,shopNumber,serialnumber}
					*/
					setCertInfoShop(a,r,c,input);//hier wordt de Q parameter en het winkel id in de kaart geset
					
					byte[] pseudoniemKaart = requestPseudoniem(a,r,c);//give it to me card (niet geencrypteerd)
					if(pseudoniemKaart.length == 0){
						winkelOut.writeObject("close connection"); 
					}
					else{
						winkelOut.writeObject(pseudoniemKaart);//winkel checkt pseudoniem en geeft zijnn eigen cert 
						
						//nu beschikken ze alletwee over elkaars public key en zullen ze dus ne symmetric key kunnen vormen elk
						keyAgreementWithShop(a,r,c);
						
						input = (byte[])winkelIn.readObject();//accepted of denied naargelang het cert van kaart
						//INSTRUCTION CARD CHECK ACCPETED OR DENIED (deze input tekst is geencrypteerd)
						System.out.println(input.length + "!!!!");
						String accepted = decryptShopCardText(a,r,c,input);
						System.out.println("accepted = " + accepted);
						//TEKST BALLON OP LATEN KOMEN ALS DE RESPONSE GELIJK IS AAN DENIEDED => weergegeven dat hij opnieuw moet registreren bij de LCP voor diene winkel
						
						
						boolean transAllowed;
						if(accepted.equals("accepted")){
							transAllowed = true;
						}else{
							transAllowed = false;
						}
						//trans hangt af of de server denieded of accepted terug stuurt na het verzende van het aantal transacties
						while(transAllowed){
							
							winkelOut.writeObject(requestTransActionAmount(a,r,c));
							input = (byte[])winkelIn.readObject();
							transAllowed= checkTransAllowed(a,r,c,input); //hier moet de kaart dus vertalen of de server accepted of denied terug gestuurd heeft
							//en zeggen of transactie nog mag of niet
							//accepted teruggekregen =>true
							if(transAllowed){
								byte[] encryptedPunten = requestShopPoints(a,r,c); //hier moet het aantal punten op de kaart komen, geencrypteerd
								winkelOut.writeObject(encryptedPunten);
								input = (byte[]) winkelIn.readObject(); //de wijziging in punten terug krijgen
								transAllowed = updatePointsShop(a,r,c,input);
							}
							else{
								System.out.println("maximum aantal transacties bereikt");
							}
							//dit herhalen tot als we allemaal content zijn dan een 0 van de winkel dan stoppen die handel
							//da zou het moeten zijn denk'k
							
						}
						byte[] transBuffer = requestTransActionBuffer(a,r,c);//is geencrypteerd met de key van de LCP en is klaar om anar de LCP verstuurd te worden
						//deze methode moet zeker best in client????
					}
				}
			}
			
		} catch (Exception e) {
			throw e;
		}
		finally {
			
			verifyOut.writeObject("close connection");
			winkelOut.writeObject("close connection");
			c.close();  // close the connection with the card
			
			verifyCertSocket.close();
			winkelSocket.close();
		}


	}
	

	private static boolean checkTransAllowed(CommandAPDU a, ResponseAPDU r, IConnection c, byte[] input) throws Exception {
		a = new CommandAPDU(IDENTITY_CARD_CLA, CHECK_TRANS_AMOUNT_INS, (byte) (input.length&0xff), 0x00,input);
		r = c.transmit(a);
		System.out.println("response check trans amount = " + r);
		byte[] response = r.getData();
		System.out.println("response van de check = " + response[0]);
		if(response[0]==1) return true;
		else return false;
	}


	private static byte[] requestTransActionBuffer(CommandAPDU a, ResponseAPDU r, IConnection c) throws Exception {
		a = new CommandAPDU(IDENTITY_CARD_CLA, REQ_TRANS_BUFFER ,0x00, 0x00,new byte[]{0x00});
		r = c.transmit(a);
		System.out.println("status transaction buffer = " + r);
		byte[] transactionBuffer = r.getData();
		System.out.println("transaction buffer geencrypteerd = " + new BigInteger(1,transactionBuffer).toString(16));
		return transactionBuffer;		
	}


	private static byte[] requestTransActionAmount(CommandAPDU a, ResponseAPDU r, IConnection c) throws Exception {
		a = new CommandAPDU(IDENTITY_CARD_CLA, REQ_TRANS_AMOUNT ,0x00, 0x00,new byte[]{0x00});
		r = c.transmit(a);
		System.out.println("status aantal transacties oprvagen = " + r);
		byte[] transActieAmount = r.getData();
		System.out.println("aantal encrypted transacties = " + new BigInteger(1,transActieAmount).toString(16));
		return transActieAmount;
	}


	private static boolean updatePointsShop(CommandAPDU a, ResponseAPDU r, IConnection c, byte[] encryptedChangedPoints) throws Exception {
		a = new CommandAPDU(IDENTITY_CARD_CLA, UPD_POINTS_INS ,(byte) (encryptedChangedPoints.length&0xff), 0x00,encryptedChangedPoints);
		r = c.transmit(a);
		System.out.println("update points status" + r);
		byte[] pointsByte = r.getData();
		short points = byteArrayToShort(pointsByte);
		System.out.println("new points = " + points);
		if(points==0) return false;
		else return true;
	}


	private static byte[] requestShopPoints(CommandAPDU a, ResponseAPDU r, IConnection c) throws Exception {
		a = new CommandAPDU(IDENTITY_CARD_CLA, REQ_SHOP_POINTS_INS ,0x00, 0x00,new byte[]{0x00});
		r = c.transmit(a);
		byte[] textByte = r.getData();
		byte[] encryptedPunten = r.getData();
		System.out.println(r);
		System.out.println("Encrtypted punten = " + new BigInteger(1,encryptedPunten).toString(16));
		return encryptedPunten;
	}

	private static String decryptShopCardText(CommandAPDU a, ResponseAPDU r, IConnection c, byte[] decryptedText) throws Exception {
		a = new CommandAPDU(IDENTITY_CARD_CLA, DECRYPT_SHOP_TEXT_INS ,(byte) (decryptedText.length&0xff), 0x00,decryptedText);
		r = c.transmit(a);
		byte[] textByte = r.getData();
		String text = new String(textByte);
		System.out.println(r);
		System.out.println("Accpeted or denied pseudoniem = " + text);
		return text;
	}

	private static void keyAgreementWithShop(CommandAPDU a, ResponseAPDU r, IConnection c) throws Exception {
		a = new CommandAPDU(IDENTITY_CARD_CLA, KEY_AGREEMENT_SHOP_INS , 0x00, 0x00,new byte[]{0x00});
		r = c.transmit(a);
		System.out.println("key agreement status : " + r);
		byte[] seckey = r.getData();
		System.out.println("secret key = " + new BigInteger(1,r.getData()).toString(16));
	}

	private static void setCertInfoShop(CommandAPDU a, ResponseAPDU r, IConnection c, byte[] input) throws Exception {
		a = new CommandAPDU(IDENTITY_CARD_CLA, CERT_SHOP_INFO_INS, (byte) (input.length&0xff), 0x00,input);
		r = c.transmit(a);
		System.out.println("cert parsing status : " + r);
		System.out.println("cert van de winkel= " + new BigInteger(1,r.getData()).toString(16));
	}

	private static void setShopIdAndPseudoniem(CommandAPDU a, ResponseAPDU r, IConnection c, byte[] shopId) throws Exception {
		//versturen van winkelkeuze naar de kaart
		a = new CommandAPDU(IDENTITY_CARD_CLA, SET_ID_SHOP_INS, (byte) (shopId.length&0xff), 0x00,shopId);
		r = c.transmit(a);
		System.out.println("winkel nummer is geset in de kaart" + r);
		System.out.println(new BigInteger(1,r.getData()).toString(16));
	}

	private static byte[] requestPseudoniem(CommandAPDU a, ResponseAPDU r, IConnection c) throws Exception {
		byte[] pseudoniem = new byte[5];
		a = new CommandAPDU(IDENTITY_CARD_CLA, REQ_PSEUDONIEM_INS, 0x00, 0x00,new byte[]{0x00});
		r = c.transmit(a);
		pseudoniem = r.getData();
		System.out.println("pseudoniem = " + r);
		System.out.println("pseudoniem = " + new BigInteger(1,pseudoniem).toString(16));
		int i = 0;
		while(i < 250 && pseudoniem[i]==0){
			i++;
		}
		if(i==250) return new byte[0];
		byte[] dest = new byte[pseudoniem.length-i];
		System.arraycopy(pseudoniem, i, dest, 0, pseudoniem.length-i);
		return dest;
	}

	private static boolean checkCorrectCertificate(CommandAPDU a, ResponseAPDU r, IConnection c, byte[] input) throws Exception {
		a = new CommandAPDU(IDENTITY_CARD_CLA, CHECK_CERT_INS, (byte) (input.length&0xff), 0x00,input);
		r = c.transmit(a);
		System.out.println(r);
		String response = new String(r.getData());
		System.out.println(new String(response )+ " certificate");
		if(!response.equals("accepted")){
			return false;
		}
		else return true;
	}

	private static void loginCard(CommandAPDU a, ResponseAPDU r, IConnection c,byte[] pin) throws Exception{
		boolean correctPin = false;
		System.out.print("PIN (pin is 1234) = ");
		String pinInput = JOptionPane.showInputDialog("Geef u PIN");
		byte[] p = new byte[]{
				(byte)(Integer.parseInt("" + pinInput.charAt(0))),
				(byte)(Integer.parseInt("" + pinInput.charAt(1))),
				(byte)(Integer.parseInt("" + pinInput.charAt(2))),
				(byte)(Integer.parseInt("" + pinInput.charAt(3))),
		};
		a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00,p);
		r = c.transmit(a);
		WinkelMiddelwareGUI.addText(r.toString());
		if (r.getSW()==SW_VERIFICATION_FAILED)WinkelMiddelwareGUI.addText("pin is incorrect");
		else if(r.getSW()!=0x9000)WinkelMiddelwareGUI.addText("pin is incorrect");
		else correctPin = true;
		WinkelMiddelwareGUI.addText("PIN Verified");
		
		
		System.out.println(r);
		int tries = 1;

		while(!correctPin && tries<3){
			WinkelMiddelwareGUI.addText("PIN (pin is 1234) = ");
			pinInput = JOptionPane.showInputDialog("Geef u PIN");
			p = new byte[]{
					(byte)(Integer.parseInt("" + pinInput.charAt(0))),
					(byte)(Integer.parseInt("" + pinInput.charAt(1))),
					(byte)(Integer.parseInt("" + pinInput.charAt(2))),
					(byte)(Integer.parseInt("" + pinInput.charAt(3))),
			};
			WinkelMiddelwareGUI.addText(p[1] + "  " + pin[1]);
			a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00,p);
			r = c.transmit(a);
			WinkelMiddelwareGUI.addText(r + "!!!!!!!");
			if (r.getSW()==SW_VERIFICATION_FAILED)WinkelMiddelwareGUI.addText("pin is incorrect");
			else if(r.getSW()!=0x9000) WinkelMiddelwareGUI.addText("pin is incorrect");
			else correctPin = true;
			tries++;
		}
		if(correctPin)WinkelMiddelwareGUI.addText("PIN Verified");
		WinkelMiddelwareGUI.addText("");
	}
	
	private static byte[] keyAgreementLCPAndCard(CommandAPDU a, ResponseAPDU r, IConnection c) throws Exception{
		KeyFactory kf = KeyFactory.getInstance("EC","BC"); // or "EC" or whatever
		a = new CommandAPDU(IDENTITY_CARD_CLA, KEY_AGREEMENT_LCP_INS , (byte)(publicKeyParameterQFromLCP.length &0xff) , 0x00,publicKeyParameterQFromLCP);
		r = c.transmit(a);
		byte[] symmetricKey = r.getData();
		//System.out.println("serialnumber = " + serialNumber);
		WinkelMiddelwareGUI.addText("key agreement with the LCP in the card: " + r);
		WinkelMiddelwareGUI.addText("symmetric key with LCP = " + new BigInteger(1,symmetricKey).toString(16));
		WinkelMiddelwareGUI.addText("");
		return symmetricKey;
	}
	
	private static byte[] requestCertificate(CommandAPDU a, ResponseAPDU r, IConnection c) throws Exception{
		ByteBuffer bb = ByteBuffer.allocate(263);
		byte[] certificate = new byte[263];
		a = new CommandAPDU(IDENTITY_CARD_CLA, GET_PART1_CERTIFICATE , 0x00 , 0x00,new byte[]{(byte)0xff});
		r = c.transmit(a);
		WinkelMiddelwareGUI.addText("part1 " + r);
		bb.put(r.getData());
		a = new CommandAPDU(IDENTITY_CARD_CLA, GET_PART2_CERTIFICATE , 0x00 , 0x00,new byte[]{(byte)0xff});
		r = c.transmit(a);
		WinkelMiddelwareGUI.addText("part2 " + r);
		bb.put(r.getData());
		certificate = bb.array();
		WinkelMiddelwareGUI.addText("certificaat = " + new BigInteger(1,certificate).toString(16));
		return certificate;
	}
	
	private static void setShopIdAndPseudoniem(CommandAPDU a, ResponseAPDU r, IConnection c,byte[] shopId, byte[] textinCipher) throws Exception{
		//versturen van winkelkeuze naar de kaart
		a = new CommandAPDU(IDENTITY_CARD_CLA, SET_ID_SHOP_INS, (byte) (shopId.length&0xff), 0x00,shopId);
		r = c.transmit(a);
		WinkelMiddelwareGUI.addText(r.toString());
		short lngth = (short) textinCipher.length;
		//System.out.println(byteToShort((byte)(lngth&0xff)));
		//setten van pseudoniem in de kaart
		byte []pseudoniem = textinCipher;
		a = new CommandAPDU(IDENTITY_CARD_CLA, SET_PSEUDONIEM_INS, lngth, 0x00,pseudoniem);
		r = c.transmit(a);
		WinkelMiddelwareGUI.addText(r.toString());
	//	System.err.println(byteArrayToShort(r.getData()));
	}
	
	private static short byteToShort(byte b) {
		return (short) (b & 0xff);
	}

	private static short byteArrayToShort(byte[] b) {
		short value = (short) (((b[0] << 8)) | ((b[1] & 0xff)));
		return value;
	}

	private static byte[] shortToByte(short s) {
		byte[] shortByte = new byte[2];
		shortByte[0] = (byte) ((s >> 8) & 0xff);
		shortByte[1] = (byte) (s & 0xff);
		return shortByte;
	}
}
