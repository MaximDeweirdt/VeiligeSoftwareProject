package be.msec.client;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.Security;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import be.msec.client.connection.Connection;
import be.msec.client.connection.IConnection;
import gui.MiddelwareGui;

public class Client {

	private final static byte IDENTITY_CARD_CLA = (byte) 0x80;
	private static final byte VALIDATE_PIN_INS = 0x01;

	private static final byte KEY_AGREEMENT_LCP_INS = 0x02;
	// private static final byte ENCRYPT_DATA_LCP_INS = 0x03;
	// private static final byte DECRYPT_DATA_LCP_INS = 0x04;
	private static final byte SET_ID_SHOP_INS = 0x05;
	private static final byte SET_PSEUDONIEM_INS = 0x06;
	private static final byte GET_PART1_CERTIFICATE = 0x07;
	private static final byte GET_PART2_CERTIFICATE = 0x08;
	private static final byte CHECK_CERT_INS = 0x09;
	private static final byte ENCRYPT_SHOP_ID_INS = 0x11;

	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;

	public final static int PIN_TRY_MAXIMUM = 3;
	private static final int ENTER_PIN = 100;
	private static final int ENTER_STORE = 101;

	public static byte[] cardCertificate = { (byte) 0x30, (byte) 0x82, (byte) 0x01, (byte) 0x03, (byte) 0x30,
			(byte) 0x81, (byte) 0xbb, (byte) 0x02, (byte) 0x01, (byte) 0x02, (byte) 0x30, (byte) 0x09, (byte) 0x06,
			(byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x04, (byte) 0x01,
			(byte) 0x30, (byte) 0x1e, (byte) 0x31, (byte) 0x1c, (byte) 0x30, (byte) 0x1a, (byte) 0x06, (byte) 0x03,
			(byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x13, (byte) 0x13, (byte) 0x43, (byte) 0x41, (byte) 0x20,
			(byte) 0x63, (byte) 0x61, (byte) 0x72, (byte) 0x64, (byte) 0x20, (byte) 0x63, (byte) 0x65, (byte) 0x72,
			(byte) 0x74, (byte) 0x69, (byte) 0x66, (byte) 0x69, (byte) 0x63, (byte) 0x61, (byte) 0x74, (byte) 0x65,
			(byte) 0x30, (byte) 0x20, (byte) 0x17, (byte) 0x0d, (byte) 0x31, (byte) 0x36, (byte) 0x30, (byte) 0x33,
			(byte) 0x33, (byte) 0x31, (byte) 0x31, (byte) 0x33, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x33,
			(byte) 0x5a, (byte) 0x18, (byte) 0x0f, (byte) 0x33, (byte) 0x39, (byte) 0x31, (byte) 0x37, (byte) 0x30,
			(byte) 0x31, (byte) 0x33, (byte) 0x31, (byte) 0x32, (byte) 0x32, (byte) 0x35, (byte) 0x39, (byte) 0x35,
			(byte) 0x39, (byte) 0x5a, (byte) 0x30, (byte) 0x1e, (byte) 0x31, (byte) 0x1c, (byte) 0x30, (byte) 0x1a,
			(byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x13, (byte) 0x13, (byte) 0x43,
			(byte) 0x41, (byte) 0x20, (byte) 0x63, (byte) 0x61, (byte) 0x72, (byte) 0x64, (byte) 0x20, (byte) 0x63,
			(byte) 0x65, (byte) 0x72, (byte) 0x74, (byte) 0x69, (byte) 0x66, (byte) 0x69, (byte) 0x63, (byte) 0x61,
			(byte) 0x74, (byte) 0x65, (byte) 0x30, (byte) 0x49, (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07,
			(byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01, (byte) 0x06,
			(byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01,
			(byte) 0x01, (byte) 0x03, (byte) 0x32, (byte) 0x00, (byte) 0x04, (byte) 0x22, (byte) 0x11, (byte) 0x21,
			(byte) 0xbd, (byte) 0x7d, (byte) 0xf3, (byte) 0x47, (byte) 0xfd, (byte) 0xfe, (byte) 0x3e, (byte) 0x89,
			(byte) 0x5d, (byte) 0xe0, (byte) 0x02, (byte) 0x65, (byte) 0xb3, (byte) 0x5c, (byte) 0x49, (byte) 0x91,
			(byte) 0x28, (byte) 0x71, (byte) 0x66, (byte) 0x2e, (byte) 0x29, (byte) 0xa3, (byte) 0xdf, (byte) 0x73,
			(byte) 0x5a, (byte) 0x52, (byte) 0x87, (byte) 0x50, (byte) 0x79, (byte) 0xd7, (byte) 0x5c, (byte) 0x3d,
			(byte) 0x56, (byte) 0x70, (byte) 0x76, (byte) 0xca, (byte) 0xaf, (byte) 0xad, (byte) 0x2e, (byte) 0xaf,
			(byte) 0x07, (byte) 0xc3, (byte) 0xa4, (byte) 0x76, (byte) 0xdf, (byte) 0x30, (byte) 0x09, (byte) 0x06,
			(byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x04, (byte) 0x01,
			(byte) 0x03, (byte) 0x38, (byte) 0x00, (byte) 0x30, (byte) 0x35, (byte) 0x02, (byte) 0x19, (byte) 0x00,
			(byte) 0xe1, (byte) 0x10, (byte) 0x53, (byte) 0x30, (byte) 0xbb, (byte) 0x7a, (byte) 0x1a, (byte) 0xd1,
			(byte) 0x90, (byte) 0x15, (byte) 0xca, (byte) 0x3d, (byte) 0xe8, (byte) 0x13, (byte) 0x87, (byte) 0x5c,
			(byte) 0xaf, (byte) 0x81, (byte) 0xb0, (byte) 0x32, (byte) 0xe7, (byte) 0x30, (byte) 0x56, (byte) 0x22,
			(byte) 0x02, (byte) 0x18, (byte) 0x30, (byte) 0x02, (byte) 0x12, (byte) 0xa9, (byte) 0x01, (byte) 0xf6,
			(byte) 0x6e, (byte) 0x35, (byte) 0xce, (byte) 0xba, (byte) 0x25, (byte) 0x35, (byte) 0xd6, (byte) 0x7e,
			(byte) 0x9f, (byte) 0xf7, (byte) 0x79, (byte) 0xe5, (byte) 0x8f, (byte) 0xc2, (byte) 0x69, (byte) 0x23,
			(byte) 0x2c, (byte) 0x41 };

	private static byte[] publicKeyParameterQFromLCP = new byte[] { (byte) 0x04, (byte) 0xa9, (byte) 0xfe, (byte) 0x35,
			(byte) 0x45, (byte) 0xf0, (byte) 0xaf, (byte) 0x79, (byte) 0x60, (byte) 0x8f, (byte) 0xd5, (byte) 0x79,
			(byte) 0x09, (byte) 0xcb, (byte) 0x32, (byte) 0x9b, (byte) 0x77, (byte) 0xde, (byte) 0x96, (byte) 0x8a,
			(byte) 0x9c, (byte) 0x2e, (byte) 0x3f, (byte) 0x3c, (byte) 0x63, (byte) 0x8d, (byte) 0xc4, (byte) 0x36,
			(byte) 0x94, (byte) 0x3e, (byte) 0x62, (byte) 0x1c, (byte) 0x95, (byte) 0xb3, (byte) 0xa0, (byte) 0x4b,
			(byte) 0x3b, (byte) 0x90, (byte) 0xab, (byte) 0x0b, (byte) 0xdf, (byte) 0x14, (byte) 0x19, (byte) 0xba,
			(byte) 0x0a, (byte) 0xed, (byte) 0x4d, (byte) 0x90, (byte) 0x2c

	};

	private static byte[] publicKeyLCP = new byte[] { (byte) 0x30, (byte) 0x49, (byte) 0x30, (byte) 0x13, (byte) 0x06,
			(byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01,
			(byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x03,
			(byte) 0x01, (byte) 0x01, (byte) 0x03, (byte) 0x32, (byte) 0x00, (byte) 0x04, (byte) 0xa9, (byte) 0xfe,
			(byte) 0x35, (byte) 0x45, (byte) 0xf0, (byte) 0xaf, (byte) 0x79, (byte) 0x60, (byte) 0x8f, (byte) 0xd5,
			(byte) 0x79, (byte) 0x09, (byte) 0xcb, (byte) 0x32, (byte) 0x9b, (byte) 0x77, (byte) 0xde, (byte) 0x96,
			(byte) 0x8a, (byte) 0x9c, (byte) 0x2e, (byte) 0x3f, (byte) 0x3c, (byte) 0x63, (byte) 0x8d, (byte) 0xc4,
			(byte) 0x36, (byte) 0x94, (byte) 0x3e, (byte) 0x62, (byte) 0x1c, (byte) 0x95, (byte) 0xb3, (byte) 0xa0,
			(byte) 0x4b, (byte) 0x3b, (byte) 0x90, (byte) 0xab, (byte) 0x0b, (byte) 0xdf, (byte) 0x14, (byte) 0x19,
			(byte) 0xba, (byte) 0x0a, (byte) 0xed, (byte) 0x4d, (byte) 0x90, (byte) 0x2c };

	private MiddelwareGui gui;
	private IConnection c;
	private CommandAPDU a;
	private ResponseAPDU r;
	private boolean pinValid, correctCardCert;
	private byte[] symmetricKey, cardCert;
	private int pinTries;
	private Socket socket;
	private ObjectOutputStream out;
	private ObjectInputStream in;
	private int state;

	public Client() {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		gui = new MiddelwareGui(this);
		state = ENTER_PIN;
		pinTries = 0;
		pinValid = false;
		correctCardCert = false;
		c = new Connection();
	}

	public void connect() throws Exception {
		((Connection) c).setTerminal(0);
		c.connect();
		socket = new Socket(ClientMain.HOSTNAME, ClientMain.PORT_NUMBER);
		out = new ObjectOutputStream(socket.getOutputStream());
		in = new ObjectInputStream(socket.getInputStream());
	}
	
	public int getState(){
		return state;
	}

	public boolean isCorrectCardCert() {
		return correctCardCert;
	}

	public void startGui() {
		gui.setVisible(true);
	}

	public IConnection getC() {
		return c;
	}

	public int getPinTries() {
		return pinTries;
	}
	
	public void incrementPINTries(){
		this.pinTries++;
	}

	public boolean pinValid() {
		return pinValid;
	}

	public void resetPinTries() {
		pinTries = 0;
	}
	
	public boolean validStore(short storeID){
		return storeID >= 0 && storeID < 4;
	}

	public void loginCard(String pin) throws Exception {
		
		gui.addText("De ingegeven PIN code wordt nu gecontroleerd.");
		gui.addText("PIN (pin is 1234) = " + pin);
		String pinInput = pin;
		ByteBuffer buffer = ByteBuffer.allocate(pin.length());
		for(int i = 0; i < pin.length(); i++){
			buffer.put((byte) Integer.parseInt(""+pinInput.charAt(i)));
		}
		byte [] p = buffer.compact().array();
//		byte[] p = new byte[] { (byte) (Integer.parseInt("" + pinInput.charAt(0))),
//				(byte) (Integer.parseInt("" + pinInput.charAt(1))), (byte) (Integer.parseInt("" + pinInput.charAt(2))),
//				(byte) (Integer.parseInt("" + pinInput.charAt(3))), };
		a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00, p);
		long time1 = System.currentTimeMillis();
		r = c.transmit(a);
		long time2 = System.currentTimeMillis();
		gui.addText("Tranmissie en controle duurde: "+(time2-time1)+" milliseconden.");
		gui.addText("Response PIN validatie: " + r + "\n");
		if (r.getSW() == SW_VERIFICATION_FAILED) {
			gui.addText("pin is incorrect");
			pinTries++;
		} else if (r.getSW() != 0x9000) {
			gui.addText("pin is incorrect");
			pinTries++;
		} else {
			pinValid = true;
		}

		if (pinValid)
			System.out.println("PIN Verified");
		System.out.println(pinValid);
	}

	public void keyAgreementLCPAndCard() throws Exception {
		gui.addText("Er wordt nu gestart de Key Agreement tussen de LCP en de smartcard.");
		KeyFactory kf = KeyFactory.getInstance("EC", "BC"); // or "EC" or
															// whatever
		a = new CommandAPDU(IDENTITY_CARD_CLA, KEY_AGREEMENT_LCP_INS, (byte) (publicKeyParameterQFromLCP.length & 0xff),
				0x00, publicKeyParameterQFromLCP);
		long time1 = System.currentTimeMillis();
		r = c.transmit(a);
		long time2 = System.currentTimeMillis();
		gui.addText("Communicatie tussen LCP en smartcard duurde: " + (time2-time1) + " milliseconden.");
		symmetricKey = r.getData();
		// System.out.println("serialnumber = " + serialNumber);
		gui.addText(r.toString());
		gui.addText("Symmetrische sleutel met de LCP is: " + new BigInteger(1, symmetricKey).toString(16) + "\n");
	}

	public void requestCertificate() throws Exception {
		gui.addText("Opvragen van het certificaat van de LCP. Dit gebeurt in twee stappen.");
		ByteBuffer bb = ByteBuffer.allocate(263);
		cardCert = new byte[263];
		a = new CommandAPDU(IDENTITY_CARD_CLA, GET_PART1_CERTIFICATE, 0x00, 0x00, new byte[] { (byte) 0xff });
		long time1 = System.currentTimeMillis();
		r = c.transmit(a);
		long time2 = System.currentTimeMillis();
		gui.addText("Eerste deel van het certificaat is ontvangen:  " + r);
		gui.addText("Het versturen en ontvangen van het eerste deel duurde: " +(time2-time1) +" milliseconden.");
		bb.put(r.getData());
		a = new CommandAPDU(IDENTITY_CARD_CLA, GET_PART2_CERTIFICATE, 0x00, 0x00, new byte[] { (byte) 0xff });
		time1 = System.currentTimeMillis();
		r = c.transmit(a);
		time2 = System.currentTimeMillis();
		gui.addText("Tweede deel van het certificaat ontvangen: " + r);
		gui.addText("Het versturen en ontvangen van het tweede deel duurde: " +(time2-time1) +" milliseconden.");
		bb.put(r.getData());
		cardCert = bb.array();
		gui.addText("Het ontvangen certificaat = " + new BigInteger(1, cardCert).toString(16));
		gui.addText("Nu wordt het certificaat van de smartcard verstuurd naar de LCP.\n");
		out.writeObject(cardCert);
		byte[] input = (byte[]) in.readObject();
		checkCorrectCertificate(input);
		if(correctCardCert){
			state = ENTER_STORE;
		}

	}

	private void checkCorrectCertificate(byte[] input) throws Exception {
		gui.addText("Het certificaat van de LCP wordt gecontroleerd.");
		a = new CommandAPDU(IDENTITY_CARD_CLA, CHECK_CERT_INS, (byte) (input.length & 0xff), 0x00, input);
		long time1= System.currentTimeMillis();
		r = c.transmit(a);
		long time2 = System.currentTimeMillis();
		gui.addText("De controle duurde: " +(time2-time1) + " milliseconden.");
		gui.addText(r.toString());
		String response = new String(r.getData());
		if (!response.equals("accepted")) {
			gui.addText("Certificaat werd niet geaccepteerd");
			correctCardCert = false;
		} else {
			gui.addText("Certificaat werd geaccepteerd");
			correctCardCert = true;
		}
	}

	public void addStoreProcedure(short storeID) throws Exception {
		byte [] winkelKeuze = ClientMain.shortToByte(storeID);
		a = new CommandAPDU(IDENTITY_CARD_CLA, ENCRYPT_SHOP_ID_INS, (byte) (winkelKeuze.length&0xff), 0x00,winkelKeuze);
		r = c.transmit(a);
		byte[] encryptedShopId = r.getData();
		gui.addText(r + "!!");
		gui.addText(new BigInteger(1,r.getData()).toString(16));
		out.writeObject(encryptedShopId);
		byte [] textinCipher = (byte[]) in.readObject();
		gui.addText(new BigInteger(1,textinCipher).toString(16));
		setShopIdAndPseudoniem(winkelKeuze, textinCipher);
	}
	
	private void setShopIdAndPseudoniem(byte[] shopId, byte[] textinCipher) throws Exception{
		//versturen van winkelkeuze naar de kaart
		a = new CommandAPDU(IDENTITY_CARD_CLA, SET_ID_SHOP_INS, (byte) (shopId.length&0xff), 0x00,shopId);
		r = c.transmit(a);
		gui.addText(r.toString());
		short lngth = (short) textinCipher.length;
		//System.out.println(byteToShort((byte)(lngth&0xff)));
		//setten van pseudoniem in de kaart
		byte [] pseudoniem = textinCipher;
		a = new CommandAPDU(IDENTITY_CARD_CLA, SET_PSEUDONIEM_INS, lngth, 0x00,pseudoniem);
		r = c.transmit(a);
		System.out.println(r);
	//	System.err.println(byteArrayToShort(r.getData()));
	}
	
	public void closeConnections() throws Exception{
		out.writeObject("close connection");
		c.close();
		socket.close();
	}

}
