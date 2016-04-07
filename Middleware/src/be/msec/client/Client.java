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
		long time1 = System.currentTimeMillis();
		a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00, p);
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
	}

	public void keyAgreementLCPAndCard() throws Exception {
		gui.addText("Er wordt nu gestart de Key Agreement tussen de LCP en de smartcard.");
		KeyFactory kf = KeyFactory.getInstance("EC", "BC"); // or "EC" or
		long time1 = System.currentTimeMillis();													// whatever
		a = new CommandAPDU(IDENTITY_CARD_CLA, KEY_AGREEMENT_LCP_INS, 0x00,
				0x00, new byte[]{0x00});
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
		long time1 = System.currentTimeMillis();
		a = new CommandAPDU(IDENTITY_CARD_CLA, GET_PART1_CERTIFICATE, 0x00, 0x00, new byte[] { (byte) 0xff });
		r = c.transmit(a);
		long time2 = System.currentTimeMillis();
		gui.addText("Eerste deel van het certificaat is ontvangen:  " + r);
		gui.addText("Het versturen en ontvangen van het eerste deel duurde: " +(time2-time1) +" milliseconden.");
		bb.put(r.getData());
		time1 = System.currentTimeMillis();
		a = new CommandAPDU(IDENTITY_CARD_CLA, GET_PART2_CERTIFICATE, 0x00, 0x00, new byte[] { (byte) 0xff });
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

	private boolean checkCorrectCertificate(byte[] input) throws Exception {
		gui.addText("Het certificaat van de LCP wordt gecontroleerd.");
		long time1= System.currentTimeMillis();
		a = new CommandAPDU(IDENTITY_CARD_CLA, CHECK_CERT_INS, (byte) (input.length & 0xff), 0x00, input);
		r = c.transmit(a);
		long time2 = System.currentTimeMillis();
		gui.addText("De controle duurde: " +(time2-time1) + " milliseconden.");
		gui.addText(r.toString());
		String response = new String(r.getData());
		if (!response.equals("accepted")) {
			gui.addText("Certificaat werd niet geaccepteerd.\n");
			correctCardCert = false;
		} else {
			gui.addText("Certificaat werd geaccepteerd.\n");
			correctCardCert = true;
		}
		return correctCardCert;
	}

	public void addStoreProcedure(short storeID) throws Exception {
		
		gui.addText("De keuze van winkel wordt nu geencrypteerd en dan doorgestuurd naar de LCP.");
		
		byte [] winkelKeuze = ClientMain.shortToByte(storeID);
		long time1 = System.currentTimeMillis();
		a = new CommandAPDU(IDENTITY_CARD_CLA, ENCRYPT_SHOP_ID_INS, (byte) (winkelKeuze.length&0xff), 0x00,winkelKeuze);
		r = c.transmit(a);
		long time2 = System.currentTimeMillis();
		gui.addText("Tranmissie en encoderen duurde in totaal " + (time2-time1) + " milliseconden.");
		byte[] encryptedShopId = r.getData();
		gui.addText(r.toString());
		gui.addText("Het geencrypteerde winkelID is: " + new BigInteger(1,r.getData()).toString(16));
		gui.addText("Dit ID wordt nu naar de LCP gestuurd die een pseudoniem voor de kaart zal terug sturen.");
		out.writeObject(encryptedShopId);
		byte [] textinCipher = (byte[]) in.readObject();
		gui.addText("Het geencrypteerde pseudoniem: " + new BigInteger(1,textinCipher).toString(16) + "\n");
		setShopIdAndPseudoniem(winkelKeuze, textinCipher);
	}
	
	private void setShopIdAndPseudoniem(byte[] shopId, byte[] textinCipher) throws Exception{
		//versturen van winkelkeuze naar de kaart
		gui.addText("De kaart wordt nu klaar gemaakt voor gebruik. Het pseudomiem voor de klant wordt op de kaart geplaatst.");
		gui.addText("Als eerste stap wordt het winkelID op de kaart geplaatst.");
		long time1 = System.currentTimeMillis();
		a = new CommandAPDU(IDENTITY_CARD_CLA, SET_ID_SHOP_INS, (byte) (shopId.length&0xff), 0x00,shopId);
		r = c.transmit(a);
		long time2 = System.currentTimeMillis();
		gui.addText("Het plaatsen van het winkelID duurde " +(time2-time1)+" milliseconden.");
		gui.addText(r.toString());
		short lngth = (short) textinCipher.length;
		//System.out.println(byteToShort((byte)(lngth&0xff)));
		//setten van pseudoniem in de kaart
		byte [] pseudoniem = textinCipher;
		gui.addText("Het pseudoniem zal nu op de kaart geplaasts worden bij het correcte winkelID.");
		time1 = System.currentTimeMillis();
		a = new CommandAPDU(IDENTITY_CARD_CLA, SET_PSEUDONIEM_INS, lngth, 0x00,pseudoniem);
		r = c.transmit(a);
		time2 = System.currentTimeMillis();
		gui.addText("Het plaatsen van het pseudoniem duurde " + (time2-time1) + " milliseconden.");
		gui.addText(r.toString());
		gui.addText("\n De kaart is nu klaar voor gebruik.");
	//	System.err.println(byteArrayToShort(r.getData()));
	}
	
	public void closeConnections() throws Exception{
		out.writeObject("close connection");
		c.close();
		socket.close();
	}

	public void emptyBuffer() throws Exception {
		System.out.println("KEY AGREEMENT");
		byte[] secretKey = ClientMain.keyAgreementLCPAndCard(a, r, c);//keyagreement with the LCP, return the secret key
		Socket socketBuffer = new Socket(ClientMain.HOSTNAME, ClientMain.EMPTY_BUFFER_PORT_NUMBER);
		ObjectOutputStream outBuffer = new ObjectOutputStream(socketBuffer.getOutputStream());
		ObjectInputStream inBuffer = new ObjectInputStream(socketBuffer.getInputStream());
				
		byte[] cardCertificate = ClientMain.requestCertificate(a, r, c);
		
		outBuffer.writeObject(cardCertificate);//card certificaat verzonden naar de LCP
		byte[] response = (byte[]) inBuffer.readObject();//response van de LCP of dit kaart certificaat legit is (accepted of denied)
		//------START CHECKING RESPONSE VAN DE KAART
		checkCorrectCertificate(response);
		//------EINDE CHECKING
		
		boolean correctPseudoniem = true;
		boolean correctBuffer = true;
		boolean registered = true;
		for(int winkelId=0;winkelId<4;winkelId++){
			registered = true;
			byte[] encryptedPseudoniem = ClientMain.requestPseudoniem(a,r,c,winkelId);
			if(encryptedPseudoniem.length == 0){//client is niet geregistreerd in deze winkel
				registered = false;
			}
			else{
				outBuffer.writeObject(encryptedPseudoniem);
				response = (byte[]) inBuffer.readObject();
				correctPseudoniem = checkCorrectCertificate(response);//CHECKT OF HET PSEUDONIEM CORRECT IS OF NIET
			}
			if(correctPseudoniem == true && registered == true){
				byte[] transactionBuffer = ClientMain.requestTransactionBuffer(a,r,c,winkelId);
				outBuffer.writeObject(transactionBuffer);
				response = (byte[]) inBuffer.readObject();//de LCP checkt of de transcaties overeenkomen, zoniet geeft hij denied terug
				correctBuffer = checkCorrectCertificate(response);	
				if(correctBuffer == false) System.err.println("foute overeenkomst in de buffer van winkel " + winkelId);//kijkt of de response denied was of niet van de LCP		
			}else{
				System.err.println("fout pseudoniem voor winkel of niet geregistreerd " + winkelId);
			}
		}
		
		System.out.println(new String(response));
	}

}
