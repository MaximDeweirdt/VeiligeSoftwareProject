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
		
		System.out.print("winkelkeuze = ");
		int winkelnummer = Integer.parseInt(SCANNER.nextLine());
		byte[] winkelKeuze;
		while (winkelnummer < 0 || winkelnummer > 3) {
			System.err.println("Het ingegeven winkelnummer is niet correct");
			winkelnummer = Integer.parseInt(SCANNER.nextLine());
		}
		
		winkelKeuze = shortToByte((short)winkelnummer);
		winkelPortNumber = winkelStartPortNumber + winkelnummer; 
		
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
			
			//certificaat van de winkel vragen om te controleren of de winkel betrouwbaar is
			//terwijl ook eigen psuedoniem certificaat naar de winkel sturen zodat deze kan controleren of die nog geldig is
			
			winkelOut.writeObject("gimmeCert");
			input = (byte[])winkelIn.readObject();//het ganse X509 certificaat dat doorgestuurd wordt naar de LCP voor controle

			verifyOut.writeObject(input);
			input = (byte[]) verifyIn.readObject();
			System.out.println("input =" + new BigInteger(1,input));
			// hier dan mss best da eenvoudig certificaat returnen, ofwel accepted of denied
			/* als we me accepted en denied werken, moeten we daarna weer aan de winkel het eenvoudig certificaat vragen,
			 * met die public key parameter. probleem daarmee is da de winkel het correcte certificaat kan sturen eerst en
			 * daarna ne foute parameter voor die key en dan ist nie veilig
			 * 
			 * we kunnen als het klopt da eenvoudig certificaat terug sturen, als het niet klopt denied en dan kunde in 
			 * de kaart aan de lengte ervan zien of het just is of niet zeker
			 * 
			 * dus deze input is da eenvoudig certificaat voorlopig
			 * bestaande uit: {qparameter,shopNumber,seriallength}
			*/
			setCertInfoShop(a,r,c,input);
			//
			//eerst moeten we de id van de winkel setten waarmee we bezig zijn in de kaart
			setShopIdAndPseudoniem(a,r,c,shortToByte((short)winkelnummer));
			
			byte[] pseudoniemKaart = requestPseudoniem(a,r,c);//give it to me card (niet geencrypteerd)
			
			winkelOut.writeObject(pseudoniemKaart);//winkel checkt pseudoniem en geeft zijnn eigen cert 
			
			
			input = (byte[])winkelIn.readObject();//accepted of denied naargelang het cert van kaart
			
			
			
			//nu beschikken ze alletwee over elkaars public key en zullen ze dus ne symmetric key kunnen vormen elk
			input = shortToByte((short)5);
			while(byteArrayToShort(input)!=(short)0){
				
				byte[] aantalpunten = input; //hier moet het aantal punten op de kaart komen, geencrypteerd
				winkelOut.writeObject(aantalpunten);
				input = (byte[]) winkelIn.readObject(); //de wijziging in punten terug krijgen
				//dit herhalen tot als we allemaal content zijn dan een 0 van de winkel dan stoppen die handel
				//da zou het moeten zijn denk'k
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
	
	private static void setCertInfoShop(CommandAPDU a, ResponseAPDU r, IConnection c, byte[] input) throws Exception {
		a = new CommandAPDU(IDENTITY_CARD_CLA, CERT_SHOP_INFO_INS, (byte) (input.length&0xff), 0x00,input);
		r = c.transmit(a);
		System.out.println("cert winkel : " + r);
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
		return pseudoniem;
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
		String pinInput = SCANNER.nextLine();
		byte[] p = new byte[]{
				(byte)(Integer.parseInt("" + pinInput.charAt(0))),
				(byte)(Integer.parseInt("" + pinInput.charAt(1))),
				(byte)(Integer.parseInt("" + pinInput.charAt(2))),
				(byte)(Integer.parseInt("" + pinInput.charAt(3))),
		};
		a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00,p);
		r = c.transmit(a);
		System.out.println(r);
		if (r.getSW()==SW_VERIFICATION_FAILED)System.out.println("pin is incorrect");
		else if(r.getSW()!=0x9000)System.out.println("pin is incorrect");
		else correctPin = true;
		System.out.println("PIN Verified");
		
		
		System.out.println(r);
		int tries = 1;

		while(!correctPin && tries<3){
			System.out.print("PIN (pin is 1234) = ");
			pinInput = SCANNER.nextLine();
			p = new byte[]{
					(byte)(Integer.parseInt("" + pinInput.charAt(0))),
					(byte)(Integer.parseInt("" + pinInput.charAt(1))),
					(byte)(Integer.parseInt("" + pinInput.charAt(2))),
					(byte)(Integer.parseInt("" + pinInput.charAt(3))),
			};
			System.out.println(p[1] + "  " + pin[1]);
			a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00,p);
			r = c.transmit(a);
			System.out.println(r + "!!!!!!!");
			if (r.getSW()==SW_VERIFICATION_FAILED)System.out.println("pin is incorrect");
			else if(r.getSW()!=0x9000) System.out.println("pin is incorrect");
			else correctPin = true;
			tries++;
		}
		if(correctPin)System.out.println("PIN Verified");
		System.out.println();
	}
	
	private static byte[] keyAgreementLCPAndCard(CommandAPDU a, ResponseAPDU r, IConnection c) throws Exception{
		KeyFactory kf = KeyFactory.getInstance("EC","BC"); // or "EC" or whatever
		a = new CommandAPDU(IDENTITY_CARD_CLA, KEY_AGREEMENT_LCP_INS , (byte)(publicKeyParameterQFromLCP.length &0xff) , 0x00,publicKeyParameterQFromLCP);
		r = c.transmit(a);
		byte[] symmetricKey = r.getData();
		//System.out.println("serialnumber = " + serialNumber);
		System.out.println("key agreement with the LCP in the card: " + r);
		System.out.println("symmetric key with LCP = " + new BigInteger(1,symmetricKey).toString(16));
		System.out.println();
		return symmetricKey;
	}
	
	private static byte[] requestCertificate(CommandAPDU a, ResponseAPDU r, IConnection c) throws Exception{
		ByteBuffer bb = ByteBuffer.allocate(263);
		byte[] certificate = new byte[263];
		a = new CommandAPDU(IDENTITY_CARD_CLA, GET_PART1_CERTIFICATE , 0x00 , 0x00,new byte[]{(byte)0xff});
		r = c.transmit(a);
		System.out.println("part1 " + r);
		bb.put(r.getData());
		a = new CommandAPDU(IDENTITY_CARD_CLA, GET_PART2_CERTIFICATE , 0x00 , 0x00,new byte[]{(byte)0xff});
		r = c.transmit(a);
		System.out.println("part2 " + r);
		bb.put(r.getData());
		certificate = bb.array();
		System.out.println("certificaat = " + new BigInteger(1,certificate).toString(16));
		return certificate;
	}
	
	private static void setShopIdAndPseudoniem(CommandAPDU a, ResponseAPDU r, IConnection c,byte[] shopId, byte[] textinCipher) throws Exception{
		//versturen van winkelkeuze naar de kaart
		a = new CommandAPDU(IDENTITY_CARD_CLA, SET_ID_SHOP_INS, (byte) (shopId.length&0xff), 0x00,shopId);
		r = c.transmit(a);
		System.out.println(r);
		short lngth = (short) textinCipher.length;
		//System.out.println(byteToShort((byte)(lngth&0xff)));
		//setten van pseudoniem in de kaart
		byte []pseudoniem = textinCipher;
		a = new CommandAPDU(IDENTITY_CARD_CLA, SET_PSEUDONIEM_INS, lngth, 0x00,pseudoniem);
		r = c.transmit(a);
		System.out.println(r);
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
