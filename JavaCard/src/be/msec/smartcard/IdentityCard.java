package be.msec.smartcard;

import com.sun.javacard.crypto.s;
import com.sun.javacard.crypto.u;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import javacardx.crypto.Cipher;
import javacardx.framework.math.BigNumber;

public class IdentityCard extends Applet {
	public static byte[] cardCertificate ={
			(byte) 0x30, (byte) 0x82, (byte) 0x01, (byte) 0x03, (byte) 0x30, (byte) 0x81, (byte) 0xbb, (byte) 0x02, (byte) 0x01, (byte) 0x02, (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x04, (byte) 0x01, (byte) 0x30, (byte) 0x1e, (byte) 0x31, (byte) 0x1c, (byte) 0x30, (byte) 0x1a, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x13, (byte) 0x13, (byte) 0x43, (byte) 0x41, (byte) 0x20, (byte) 0x63, (byte) 0x61, (byte) 0x72, (byte) 0x64, (byte) 0x20, (byte) 0x63, (byte) 0x65, (byte) 0x72, (byte) 0x74, (byte) 0x69, (byte) 0x66, (byte) 0x69, (byte) 0x63, (byte) 0x61, (byte) 0x74, (byte) 0x65, (byte) 0x30, (byte) 0x20, (byte) 0x17, (byte) 0x0d, (byte) 0x31, (byte) 0x36, (byte) 0x30, (byte) 0x33, (byte) 0x33, (byte) 0x31, (byte) 0x31, (byte) 0x33, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x33, (byte) 0x5a, (byte) 0x18, (byte) 0x0f, (byte) 0x33, (byte) 0x39, (byte) 0x31, (byte) 0x37, (byte) 0x30, (byte) 0x31, (byte) 0x33, (byte) 0x31, (byte) 0x32, (byte) 0x32, (byte) 0x35, (byte) 0x39, (byte) 0x35, (byte) 0x39, (byte) 0x5a, (byte) 0x30, (byte) 0x1e, (byte) 0x31, (byte) 0x1c, (byte) 0x30, (byte) 0x1a, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x13, (byte) 0x13, (byte) 0x43, (byte) 0x41, (byte) 0x20, (byte) 0x63, (byte) 0x61, (byte) 0x72, (byte) 0x64, (byte) 0x20, (byte) 0x63, (byte) 0x65, (byte) 0x72, (byte) 0x74, (byte) 0x69, (byte) 0x66, (byte) 0x69, (byte) 0x63, (byte) 0x61, (byte) 0x74, (byte) 0x65, (byte) 0x30, (byte) 0x49, (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0x03, (byte) 0x32, (byte) 0x00, (byte) 0x04, (byte) 0x22, (byte) 0x11, (byte) 0x21, (byte) 0xbd, (byte) 0x7d, (byte) 0xf3, (byte) 0x47, (byte) 0xfd, (byte) 0xfe, (byte) 0x3e, (byte) 0x89, (byte) 0x5d, (byte) 0xe0, (byte) 0x02, (byte) 0x65, (byte) 0xb3, (byte) 0x5c, (byte) 0x49, (byte) 0x91, (byte) 0x28, (byte) 0x71, (byte) 0x66, (byte) 0x2e, (byte) 0x29, (byte) 0xa3, (byte) 0xdf, (byte) 0x73, (byte) 0x5a, (byte) 0x52, (byte) 0x87, (byte) 0x50, (byte) 0x79, (byte) 0xd7, (byte) 0x5c, (byte) 0x3d, (byte) 0x56, (byte) 0x70, (byte) 0x76, (byte) 0xca, (byte) 0xaf, (byte) 0xad, (byte) 0x2e, (byte) 0xaf, (byte) 0x07, (byte) 0xc3, (byte) 0xa4, (byte) 0x76, (byte) 0xdf, (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x04, (byte) 0x01, (byte) 0x03, (byte) 0x38, (byte) 0x00, (byte) 0x30, (byte) 0x35, (byte) 0x02, (byte) 0x19, (byte) 0x00, (byte) 0xe1, (byte) 0x10, (byte) 0x53, (byte) 0x30, (byte) 0xbb, (byte) 0x7a, (byte) 0x1a, (byte) 0xd1, (byte) 0x90, (byte) 0x15, (byte) 0xca, (byte) 0x3d, (byte) 0xe8, (byte) 0x13, (byte) 0x87, (byte) 0x5c, (byte) 0xaf, (byte) 0x81, (byte) 0xb0, (byte) 0x32, (byte) 0xe7, (byte) 0x30, (byte) 0x56, (byte) 0x22, (byte) 0x02, (byte) 0x18, (byte) 0x30, (byte) 0x02, (byte) 0x12, (byte) 0xa9, (byte) 0x01, (byte) 0xf6, (byte) 0x6e, (byte) 0x35, (byte) 0xce, (byte) 0xba, (byte) 0x25, (byte) 0x35, (byte) 0xd6, (byte) 0x7e, (byte) 0x9f, (byte) 0xf7, (byte) 0x79, (byte) 0xe5, (byte) 0x8f, (byte) 0xc2, (byte) 0x69, (byte) 0x23, (byte) 0x2c, (byte) 0x41
	};

	
	private final static byte IDENTITY_CARD_CLA = (byte) 0x80;

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
	private static final byte REQ_PSEUDONIEM_SHOP = 0x12;
	private static final byte REQ_TRANS_BUFFER_SHOP = 0x13;
	private static final byte REQ_INFO_CLIENT = 0x14;
	
	private static final byte REQ_PSEUDONIEM_INS = 0x40;
	private static final byte CERT_SHOP_INFO_INS = 0x41;
	private static final byte KEY_AGREEMENT_SHOP_INS = 0x42;
	private static final byte DECRYPT_SHOP_TEXT_INS = 0x43;
	private static final byte REQ_SHOP_POINTS_INS = 0x44;
	private static final byte UPD_POINTS_INS = 0x45;
	private static final byte REQ_TRANS_AMOUNT = 0x46;
	private static final byte REQ_TRANS_BUFFER = 0x47;
	private static final byte CHECK_TRANS_AMOUNT_INS = 0x48;
	
	
	private final static byte PIN_TRY_LIMIT = (byte) 0x03;
	private final static byte PIN_SIZE = (byte) 0x04;

	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;

	private static byte[] publicKeyParameterQFromLCP = new byte[] { (byte) 0x04, (byte) 0xa9, (byte) 0xfe, (byte) 0x35,
			(byte) 0x45, (byte) 0xf0, (byte) 0xaf, (byte) 0x79, (byte) 0x60, (byte) 0x8f, (byte) 0xd5, (byte) 0x79,
			(byte) 0x09, (byte) 0xcb, (byte) 0x32, (byte) 0x9b, (byte) 0x77, (byte) 0xde, (byte) 0x96, (byte) 0x8a,
			(byte) 0x9c, (byte) 0x2e, (byte) 0x3f, (byte) 0x3c, (byte) 0x63, (byte) 0x8d, (byte) 0xc4, (byte) 0x36,
			(byte) 0x94, (byte) 0x3e, (byte) 0x62, (byte) 0x1c, (byte) 0x95, (byte) 0xb3, (byte) 0xa0, (byte) 0x4b,
			(byte) 0x3b, (byte) 0x90, (byte) 0xab, (byte) 0x0b, (byte) 0xdf, (byte) 0x14, (byte) 0x19, (byte) 0xba,
			(byte) 0x0a, (byte) 0xed, (byte) 0x4d, (byte) 0x90, (byte) 0x2c

	};
	
	private short idShop;
	
	private OwnerPIN pin;
	private DESKey secretDesKeyWithLCP;
	private Cipher cipherWithLCP;
	
	private DESKey secretDesKeyWithShop;
	private Cipher cipherWithShop;
	
	//NOG 3 pseudoniemen te maken
	private byte[] pseudoniemColruyt = new byte[250];
	short colruytPoints;
	
	private byte[] pseudoniemDelhaize = new byte[250];
	short delhaizePoints;
	
	private byte[] pseudoniemAlienWare = new byte[250];
	short alienWarePoints;
	
	private byte[] pseudoniemRazor = new byte[250];
	short razorPoints;
	
	private byte[] QparamColruyt = new byte[52];
	private byte[] QparamDelhaize = new byte[52];
	private byte[] QparamAlienWare = new byte[52];
	private byte[] QparamRazor = new byte[52];
	
	private byte[] transactionsColruyt = new byte[160];//elke short neemt 2 bytes in
	short transactionCounterColruyt = 0;
	private byte[] transactionsDelhaize = new byte[160];//elke short neemt 2 bytes in
	short transactionCounterDelhaize = 0;
	private byte[] transactionsAlienware = new byte[160];//elke short neemt 2 bytes in
	short transactionCounterAlienware = 0;
	private byte[] transactionsRazor = new byte[160];//elke short neemt 2 bytes in
	short transactionCounterRazor = 0;
	
	
	short transactionCounter = 0;
	
	public static byte[] privateKeyCard = new byte[] { (byte) 0x30, (byte) 0x7b, (byte) 0x02, (byte) 0x01, (byte) 0x00,
			(byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce,
			(byte) 0x3d, (byte) 0x02, (byte) 0x01, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48,
			(byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0x04, (byte) 0x61, (byte) 0x30,
			(byte) 0x5f, (byte) 0x02, (byte) 0x01, (byte) 0x01, (byte) 0x04, (byte) 0x18, (byte) 0x7e, (byte) 0x2d,
			(byte) 0xec, (byte) 0x75, (byte) 0xc2, (byte) 0xac, (byte) 0xee, (byte) 0x8d, (byte) 0x50, (byte) 0x62,
			(byte) 0x28, (byte) 0x05, (byte) 0x7e, (byte) 0x9a, (byte) 0x7d, (byte) 0x18, (byte) 0x9a, (byte) 0xb1,
			(byte) 0x23, (byte) 0xac, (byte) 0xf4, (byte) 0x4e, (byte) 0x32, (byte) 0x68, (byte) 0xa0, (byte) 0x0a,
			(byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x03,
			(byte) 0x01, (byte) 0x01, (byte) 0xa1, (byte) 0x34, (byte) 0x03, (byte) 0x32, (byte) 0x00, (byte) 0x04,
			(byte) 0x22, (byte) 0x11, (byte) 0x21, (byte) 0xbd, (byte) 0x7d, (byte) 0xf3, (byte) 0x47, (byte) 0xfd,
			(byte) 0xfe, (byte) 0x3e, (byte) 0x89, (byte) 0x5d, (byte) 0xe0, (byte) 0x02, (byte) 0x65, (byte) 0xb3,
			(byte) 0x5c, (byte) 0x49, (byte) 0x91, (byte) 0x28, (byte) 0x71, (byte) 0x66, (byte) 0x2e, (byte) 0x29,
			(byte) 0xa3, (byte) 0xdf, (byte) 0x73, (byte) 0x5a, (byte) 0x52, (byte) 0x87, (byte) 0x50, (byte) 0x79,
			(byte) 0xd7, (byte) 0x5c, (byte) 0x3d, (byte) 0x56, (byte) 0x70, (byte) 0x76, (byte) 0xca, (byte) 0xaf,
			(byte) 0xad, (byte) 0x2e, (byte) 0xaf, (byte) 0x07, (byte) 0xc3, (byte) 0xa4, (byte) 0x76, (byte) 0xdf

	};

	private IdentityCard() {
		/*
		 * During instantiation of the applet, all objects are created. In this
		 * example, this is the 'pin' object.
		 */
		pin = new OwnerPIN(PIN_TRY_LIMIT, PIN_SIZE);
		pin.update(new byte[] { 0x01, 0x02, 0x03, 0x04 }, (short) 0, PIN_SIZE);

		/*
		 * This method registers the applet with the JCRE on the card.
		 */
		register();
	}

	/*
	 * This method is called by the JCRE when installing the applet on the card.
	 */
	public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
		new IdentityCard();
	}

	/*
	 * If no tries are remaining, the applet refuses selection. The card can,
	 * therefore, no longer be used for identification.
	 */
	public boolean select() {
		if (pin.getTriesRemaining() == 0)
			return false;
		return true;
	}

	/*
	 * This method is called when the applet is selected and an APDU arrives.
	 */
	public void process(APDU apdu) throws ISOException {
		// A reference to the buffer, where the APDU data is stored, is
		// retrieved.
		byte[] buffer = apdu.getBuffer();

		// If the APDU selects the applet, no further processing is required.
		if (this.selectingApplet())
			return;

		// Check whether the indicated class of instructions is compatible with
		// this applet.
		if (buffer[ISO7816.OFFSET_CLA] != IDENTITY_CARD_CLA)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		// A switch statement is used to select a method depending on the
		// instruction
		switch (buffer[ISO7816.OFFSET_INS]) {
		case VALIDATE_PIN_INS:
			validatePIN(apdu);
			break;
		case KEY_AGREEMENT_LCP_INS:
			keyAgreementLCP(apdu);
			break;
		case SET_ID_SHOP_INS:
			setIDshop(apdu);
			break;
		case SET_PSEUDONIEM_INS:
			safePseudoniemData(apdu);
			break;
		case GET_PART1_CERTIFICATE:
			sendPart1Certificate(apdu);
			break;
		case GET_PART2_CERTIFICATE:
			sendPart2Certificate(apdu);
			break;
		case CHECK_CERT_INS:
			checkCertificateCorrect(apdu);
			break;
		case ENCRYPT_SHOP_ID_INS:
			encryptShopId(apdu);
			break;
		case REQ_PSEUDONIEM_INS:
			sendPseudoniem(apdu);
			break;
		case CERT_SHOP_INFO_INS:
			safeCertInfoShop(apdu);
			break;
		case KEY_AGREEMENT_SHOP_INS:
			keyAgreementSHOP(apdu);
			break;
		case DECRYPT_SHOP_TEXT_INS:
			decryptShopText(apdu);
			break;
		case REQ_SHOP_POINTS_INS:
			encryptShopPoints(apdu);
			break;
		case UPD_POINTS_INS:
			updatePointsTransaction(apdu);
			break;
		case REQ_TRANS_AMOUNT:
			sendTransAmount(apdu);
			break;
		case REQ_TRANS_BUFFER:
			requestTransBuffer(apdu);
			break;
		case CHECK_TRANS_AMOUNT_INS:
			checkTransAmount(apdu);
			break;
		case REQ_PSEUDONIEM_SHOP:
			sendPseudoniemShop(apdu);
			break;
		case REQ_TRANS_BUFFER_SHOP:
			sendTransBufferShop(apdu);
			break;
		case REQ_INFO_CLIENT:
			infoClient(apdu);
			break;
		// If no matching instructions are found it is indicated in the status
		// word of the response.
		// This can be done by using this method. As an argument a short is
		// given that indicates
		// the type of warning. There are several predefined warnings in the
		// 'ISO7816' class.
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			break;
		}
	}

	private void infoClient(APDU apdu) {
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			apdu.setIncomingAndReceive();
			byte[] info = new byte[10];
			
			//opslaan aantal transacties
			byte[]amountOfTransActions = shortToByte(transactionCounter);
			info[0] = amountOfTransActions[0];
			info[1] = amountOfTransActions[1];
			
			//opslaan van de punten
			byte[] colruytPointsByte = shortToByte(colruytPoints);//COLRUYT
			info[2] = colruytPointsByte[0];
			info[3] = colruytPointsByte[1];
			
			byte[] delhaizePointsByte = shortToByte(delhaizePoints);//DELHIZE
			info[4] = delhaizePointsByte[0];
			info[5] = delhaizePointsByte[1];
			
			byte[] alienwarePointsByte = shortToByte(alienWarePoints);//ALIENWARE
			info[6] = alienwarePointsByte[0];
			info[7] = alienwarePointsByte[1];
			
			byte[] razorPointsByte = shortToByte(razorPoints);//RAZOR
			info[8] = razorPointsByte[0];
			info[9] = razorPointsByte[1];
			
			//send back info
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) info.length);
			apdu.sendBytesLong(info, (short) 0, (short) info.length);
		}
		
	}

	private void sendTransBufferShop(APDU apdu) {
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			//load shopId
			byte[] buffer = apdu.getBuffer();
			short dataLength = apdu.setIncomingAndReceive();
			short length = byteToShort(buffer[ISO7816.OFFSET_P1]);
			byte[] shopIdByte = new byte[length];
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, shopIdByte, (short) 0, length);
			
			short winkelId = byteArrayToShort(shopIdByte);
			byte[] transBuffer = new byte[5];
			if(winkelId == 0){
				transBuffer = transactionsColruyt;
			} else if(winkelId == 1){
				transBuffer = transactionsDelhaize;
			} else if(winkelId == 2){
				transBuffer = transactionsAlienware;
			}else if(winkelId == 3){
				transBuffer = transactionsRazor;
			}
			
			byte[]transBufferEncrypted = encryptDataLCP(transBuffer);
			
			//reset data
			if(winkelId == 0){
				transactionsColruyt = new byte[160];
				transactionCounterColruyt = 0;
			} else if(winkelId == 1){
				transactionsDelhaize= new byte[160];
				transactionCounterDelhaize = 0;
			} else if(winkelId == 2){
				transactionsAlienware= new byte[160];
				transactionCounterAlienware = 0;
			}else if(winkelId == 3){
				transactionsRazor= new byte[160];
				transactionCounterRazor = 0;
			}
			transactionCounter = 0;
			
			//send back pseudoniem
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) transBufferEncrypted.length);
			apdu.sendBytesLong(transBufferEncrypted, (short) 0, (short) transBufferEncrypted.length);
		}
		
	}

	private void sendPseudoniemShop(APDU apdu) {
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			//load shopId
			byte[] buffer = apdu.getBuffer();
			short dataLength = apdu.setIncomingAndReceive();
			short length = byteToShort(buffer[ISO7816.OFFSET_P1]);
			byte[] shopIdByte = new byte[length];
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, shopIdByte, (short) 0, length);
			
			short winkelId = byteArrayToShort(shopIdByte);
			byte[] pseudoniem = new byte[5];
			if(winkelId == 0){
				pseudoniem = pseudoniemColruyt;
			} else if(winkelId == 1){
				pseudoniem = pseudoniemDelhaize;
			} else if(winkelId == 2){
				pseudoniem = pseudoniemAlienWare;
			}else if(winkelId == 3){
				pseudoniem = pseudoniemRazor;
			}
			
			byte[]pseudoniemEncrypted = encryptDataLCP(pseudoniem);
			//send back pseudoniem
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) pseudoniemEncrypted.length);
			apdu.sendBytesLong(pseudoniemEncrypted, (short) 0, (short) pseudoniemEncrypted.length);
		}
		
	}

	private void checkTransAmount(APDU apdu) {
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			//load text
			byte[] buffer = apdu.getBuffer();
			short dataLength = apdu.setIncomingAndReceive();
			short length = byteToShort(buffer[ISO7816.OFFSET_P1]);
			byte[] encryptedData = new byte[length];
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, encryptedData, (short) 0, length);
		
			//encrypt text
			byte[] data = decryptDataShop(encryptedData);
			
			//check accepted or denied
			byte[] response = new byte[1];
			if(data[0]=='a'){
				response[0] = (byte) 1;
			}else{
				response[0] = (byte) 0;
			}
			
			//send back response
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) response.length);
			apdu.sendBytesLong(response, (short) 0, (short) response.length);
		}
		
	}

	private void requestTransBuffer(APDU apdu) {
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			/*apdu.setIncomingAndReceive();
			
			//encrypt buffer
			byte[] encryptedBuffer = encryptDataLCP(transactions);
			
			//empty buffer
			transactions = new byte[120];

			
			//return encrypted trans amount
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) encryptedBuffer.length);
			apdu.sendBytesLong(encryptedBuffer, (short) 0, (short) encryptedBuffer.length);*/
			
		}
		
	}

	private void sendTransAmount(APDU apdu) {
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			apdu.setIncomingAndReceive();
			byte[] transAmountByte = shortToByte(transactionCounter);
			
			byte[] transactionAmountByte = new byte[(short)8];
			transactionAmountByte[(short)0] = transAmountByte[(short)0];
			transactionAmountByte[(short)1] = transAmountByte[(short)1];
			transactionAmountByte[(short)2] = (byte)0x00;
			transactionAmountByte[(short)3] = (byte)0x00;
			transactionAmountByte[(short)4] = (byte)0x00;
			transactionAmountByte[(short)5] = (byte)0x00;
			transactionAmountByte[(short)6] = (byte)0x00;
			transactionAmountByte[(short)7] = (byte)0x00;
			
			byte[] encryptedTransAmount = encryptDataShop(transactionAmountByte);
			
			//return encrypted trans amount
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) encryptedTransAmount.length);
			apdu.sendBytesLong(encryptedTransAmount, (short) 0, (short) encryptedTransAmount.length);
		}
		
	}

	private void updatePointsTransaction(APDU apdu) {
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			//load text
			byte[] buffer = apdu.getBuffer();
			short dataLength = apdu.setIncomingAndReceive();
			short length = byteToShort(buffer[ISO7816.OFFSET_P1]);
			byte[] encryptedPoints = new byte[length];
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, encryptedPoints, (short) 0, length);
			
			//decrypt points
			byte[] decryptedText = decryptDataShop(encryptedPoints);
			byte[] updateByte = new byte[2];
			Util.arrayCopy(decryptedText,(short) 6 , updateByte, (short) 0, (short)2);
			short update = byteArrayToShort(updateByte);
			
			short points = 0;
			//update points
			byte[] shopIdByte = shortToByte(idShop);

			
			if(idShop == 0){
				short previousPoints = (short) (colruytPoints);
				byte[] previousPointsByte = shortToByte(previousPoints);
				colruytPoints = (short) (colruytPoints + update);
				points = colruytPoints;

				short i1 = (short) (transactionCounterColruyt*8);
				short i2 = (short) ((short) (transactionCounterColruyt*8) + 1);
				short i3 = (short) ((short) (transactionCounterColruyt*8) + 2);
				short i4 = (short) ((short) (transactionCounterColruyt*8) + 3);
				short i5 = (short) ((short) (transactionCounterColruyt*8) + 4);
				short i6 = (short) ((short) (transactionCounterColruyt*8) + 5);
				short i7 = (short) ((short) (transactionCounterColruyt*8) + 6);
				short i8 = (short) ((short) (transactionCounterColruyt*8) + 7);
				transactionsColruyt[i1] = shopIdByte[0]; 
				transactionsColruyt[i2]	= shopIdByte[1]; 
				transactionsColruyt[i3]	= previousPointsByte[0]; 
				transactionsColruyt[i4]	= previousPointsByte[1]; 			
				transactionsColruyt[i5] = updateByte[0];
				transactionsColruyt[i6] = updateByte[1];
				transactionsColruyt[i7] = (byte) 0x00;
				transactionsColruyt[i8] = (byte) 0x00;
				transactionCounterColruyt = (short) (transactionCounterColruyt + 1);
			}else if(idShop == 1){
				short previousPoints = (short) (delhaizePoints);
				byte[] previousPointsByte = shortToByte(previousPoints);
				delhaizePoints = (short) (delhaizePoints + update);
				points = delhaizePoints;
				short i1 = (short) (transactionCounterDelhaize*8);
				short i2 = (short) ((short) (transactionCounterDelhaize*8) + 1);
				short i3 = (short) ((short) (transactionCounterDelhaize*8) + 2);
				short i4 = (short) ((short) (transactionCounterDelhaize*8) + 3);
				short i5 = (short) ((short) (transactionCounterDelhaize*8) + 4);
				short i6 = (short) ((short) (transactionCounterDelhaize*8) + 5);
				short i7 = (short) ((short) (transactionCounterDelhaize*8) + 6);
				short i8 = (short) ((short) (transactionCounterDelhaize*8) + 7);
				transactionsDelhaize[i1] = shopIdByte[0]; 
				transactionsDelhaize[i2]	= shopIdByte[1]; 
				transactionsDelhaize[i3]	= previousPointsByte[0]; 
				transactionsDelhaize[i4]	= previousPointsByte[1]; 			
				transactionsDelhaize[i5] = updateByte[0];
				transactionsDelhaize[i6] = updateByte[1];
				transactionsDelhaize[i7] = (byte) 0x00;
				transactionsDelhaize[i8] = (byte) 0x00;
				transactionCounterDelhaize = (short) (transactionCounterDelhaize + 1);
			}else if(idShop == 2){
				short previousPoints = (short) (alienWarePoints);
				byte[] previousPointsByte = shortToByte(previousPoints);
				alienWarePoints = (short) (alienWarePoints + update);
				points = alienWarePoints;
				short i1 = (short) (transactionCounterAlienware*8);
				short i2 = (short) ((short) (transactionCounterAlienware*8) + 1);
				short i3 = (short) ((short) (transactionCounterAlienware*8) + 2);
				short i4 = (short) ((short) (transactionCounterAlienware*8) + 3);
				short i5 = (short) ((short) (transactionCounterAlienware*8) + 4);
				short i6 = (short) ((short) (transactionCounterAlienware*8) + 5);
				short i7 = (short) ((short) (transactionCounterAlienware*8) + 6);
				short i8 = (short) ((short) (transactionCounterAlienware*8) + 7);
				transactionsAlienware[i1] = shopIdByte[0]; 
				transactionsAlienware[i2]	= shopIdByte[1]; 
				transactionsAlienware[i3]	= previousPointsByte[0]; 
				transactionsAlienware[i4]	= previousPointsByte[1]; 			
				transactionsAlienware[i5] = updateByte[0];
				transactionsAlienware[i6] = updateByte[1];
				transactionsAlienware[i7] = (byte) 0x00;
				transactionsAlienware[i8] = (byte) 0x00;
				transactionCounterAlienware = (short) (transactionCounterAlienware + 1);
			}else if(idShop == 3){
				short previousPoints = (short) (razorPoints);
				byte[] previousPointsByte = shortToByte(previousPoints);
				razorPoints = (short) (razorPoints + update);
				points = razorPoints;
				short i1 = (short) (transactionCounterRazor*8);
				short i2 = (short) ((short) (transactionCounterRazor*8) + 1);
				short i3 = (short) ((short) (transactionCounterRazor*8) + 2);
				short i4 = (short) ((short) (transactionCounterRazor*8) + 3);
				short i5 = (short) ((short) (transactionCounterRazor*8) + 4);
				short i6 = (short) ((short) (transactionCounterRazor*8) + 5);
				short i7 = (short) ((short) (transactionCounterRazor*8) + 6);
				short i8 = (short) ((short) (transactionCounterRazor*8) + 7);
				transactionsRazor[i1] = shopIdByte[0]; 
				transactionsRazor[i2]	= shopIdByte[1]; 
				transactionsRazor[i3]	= previousPointsByte[0]; 
				transactionsRazor[i4]	= previousPointsByte[1]; 			
				transactionsRazor[i5] = updateByte[0];
				transactionsRazor[i6] = updateByte[1];
				transactionsRazor[i7] = (byte) 0x00;
				transactionsRazor[i8] = (byte) 0x00;
				transactionCounterRazor = (short) (transactionCounterRazor + 1);
			}
			
			
			transactionCounter = (short) (transactionCounter + 1);
			
			//return points
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) 2);
			apdu.sendBytesLong(shortToByte(update), (short) 0, (short) 2);
		}
		
	}

	private void encryptShopPoints(APDU apdu) {
		apdu.setIncomingAndReceive();
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			
			byte[] points = new byte[8];
			if(idShop == 0){
				byte[] colruytPointsByte = shortToByte(colruytPoints);
				points[0] = colruytPointsByte[0];
				points[1] = colruytPointsByte[1];
			}else if(idShop == 1){
				byte[] delhaizePointsByte = shortToByte(delhaizePoints);
				points[0] = delhaizePointsByte[0];
				points[1] = delhaizePointsByte[1];
			}else if(idShop == 2){
				byte[] alienPointsByte = shortToByte(alienWarePoints);
				points[0] = alienPointsByte[0];
				points[1] = alienPointsByte[1];
			}else if(idShop == 3){
				byte[] razorPointsByte = shortToByte(razorPoints);
				points[0] = razorPointsByte[0];
				points[1] = razorPointsByte[1];
			}
			points[2] = 0;
			points[3] = 0;
			points[4] = 0;
			points[5] = 0;
			points[6] = 0;
			points[7] = 0;
			
			//encrypt data
			byte[] encryptedData = encryptDataShop(points);
			
			//send ecnrypted data back
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) encryptedData.length);
			apdu.sendBytesLong(encryptedData, (short) 0, (short) encryptedData.length);
		}
	}

	private void decryptShopText(APDU apdu) {
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			//load text
			byte[] buffer = apdu.getBuffer();
			short dataLength = apdu.setIncomingAndReceive();
			short length = byteToShort(buffer[ISO7816.OFFSET_P1]);
			byte[] encryptedText = new byte[length];
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, encryptedText, (short) 0, length);
			
			//decrypt text
			byte[] data = new byte[length];
			cipherWithShop.init(secretDesKeyWithShop,Cipher.MODE_DECRYPT);
			cipherWithShop.doFinal(encryptedText, (short) 0 , (short) encryptedText.length, data, (short) 0); 
			
			//send back decrypted text
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) data.length);
			apdu.sendBytesLong(data, (short) 0, (short) data.length);
		}
		

		
	}

	private void keyAgreementSHOP(APDU apdu) {
		// get public key out of the data from the apdu data field
		apdu.setIncomingAndReceive();
		byte[] pubParamWshop;
		if(idShop == 0){
			pubParamWshop = QparamColruyt;
		}else if(idShop == 1){
			pubParamWshop = QparamDelhaize;
		}else if(idShop == 2){
			pubParamWshop = QparamAlienWare;
		}else{
			pubParamWshop = QparamRazor;
		}
		short length = (short) (pubParamWshop.length-3);
		byte[] pubParamw = new byte[length];
		Util.arrayCopy(pubParamWshop, (short) 3, pubParamw, (short) 0, (short)length);
		byte[] secret = new byte[250];

		// create symmetric key with public key
		PrivateKey cardPrivKey = getprivateKey();
		KeyAgreement keyAgreement= KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
		keyAgreement.init(cardPrivKey);
		short secretKeyLength = keyAgreement.generateSecret(pubParamw, (short)0, (short) pubParamw.length, secret, (short)0);
		
		//copy secret key to secretkey byte array with adjusted size
		byte[] secretKey = new byte[secretKeyLength];
		Util.arrayCopy(secret, (short)0, secretKey,(short) 0, secretKeyLength);
		
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			generateCipherShop(secretKey);
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) secretKey.length);
			apdu.sendBytesLong(secretKey, (short) 0, (short) secretKey.length);
		}
		
	}

	private void generateCipherShop(byte[] secretKey) {
		DESKey m_desKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES,false);
		// SET KEY VALUE
		m_desKey.setKey(secretKey, (short) 0); 
		secretDesKeyWithShop = m_desKey;
		cipherWithShop = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
		
	}

	private void safeCertInfoShop(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short dataLength = apdu.setIncomingAndReceive();
		
		short length = byteToShort(buffer[ISO7816.OFFSET_P1]);
		byte[] certShopEncrypted = new byte[length];
		Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, certShopEncrypted, (short) 0, length);
		
		byte[] certShop = decryptDataLCP(certShopEncrypted);
		
		byte[] QparamShop = new byte[52];
		Util.arrayCopy(certShop, (short) 0, QparamShop, (short) 0, (short)52);
		
		byte[] shopNumber = new byte[2];
		Util.arrayCopy(certShop, (short) 52, shopNumber, (short) 0, (short)2);
		
		byte[] serialNumber = new byte[2];
		Util.arrayCopy(certShop, (short) 54, serialNumber, (short) 0, (short)2);
		
		if(byteArrayToShort(shopNumber)==(short)0){
			QparamColruyt = QparamShop;
			idShop = 0;
		}
		if(byteArrayToShort(shopNumber)==(short)1){
			QparamDelhaize = QparamShop;
			idShop = 1;
		}
		if(byteArrayToShort(shopNumber)==(short)2){
			QparamAlienWare = QparamShop;
			idShop = 2;
		}
		if(byteArrayToShort(shopNumber)==(short)3){
			QparamRazor = QparamShop;
			idShop = 3;
		}
		
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) QparamShop.length);
			apdu.sendBytesLong(QparamShop, (short) 0, (short) QparamShop.length);
		}


	}

	private void sendPseudoniem(APDU apdu) {
		short dataLength = apdu.setIncomingAndReceive();
		byte[] pseudoniem = new byte[5];
		if(idShop==0){//send colruyt pseudoniem
			pseudoniem = pseudoniemColruyt;
		}
		if(idShop==1){//send colruyt pseudoniem
			pseudoniem = pseudoniemDelhaize;
		}
		if(idShop==2){//send colruyt pseudoniem
			pseudoniem = pseudoniemAlienWare;
		}
		if(idShop==3){//send colruyt pseudoniem
			pseudoniem = pseudoniemRazor;
		}
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) pseudoniem.length);
			apdu.sendBytesLong(pseudoniem, (short) 0, (short) pseudoniem.length);
		}

	}

	private void encryptShopId(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short dataLength = apdu.setIncomingAndReceive();
		
		short length = byteToShort(buffer[ISO7816.OFFSET_P1]);
		byte[] shopIdByte = new byte[8];
		Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, shopIdByte, (short) 0, length);
		shopIdByte[2] = (byte) 0x00;
		shopIdByte[3] = (byte) 0x00;
		shopIdByte[4] = (byte) 0x00;
		shopIdByte[5] = (byte) 0x00;
		shopIdByte[6] = (byte) 0x00;
		shopIdByte[7] = (byte) 0x00;
		byte[] encryptedShopId = encryptDataLCP(shopIdByte);
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) encryptedShopId.length);
			apdu.sendBytesLong(encryptedShopId, (short) 0, (short) encryptedShopId.length);
		}
	}

	private void checkCertificateCorrect(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short dataLength = apdu.setIncomingAndReceive();
		
		short length = byteToShort(buffer[ISO7816.OFFSET_P1]);
		byte[] response = new byte[length];
		Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, response, (short) 0, length);
		byte[] checkCorrect = decryptDataLCP(response);
		if(checkCorrect[0]!='a'){
			pin.reset();
		}
		if(pin.isValidated()){
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) checkCorrect.length);
			apdu.sendBytesLong(checkCorrect, (short) 0, (short) checkCorrect.length);
		}
	}

	private void sendPart1Certificate(APDU apdu) {
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			apdu.setIncomingAndReceive();
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) 240);
			apdu.sendBytesLong(cardCertificate, (short) 0, (short) 240);
		}
	}

	private void sendPart2Certificate(APDU apdu) {
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			apdu.setIncomingAndReceive();
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) 23);
			apdu.sendBytesLong(cardCertificate, (short) 240, (short) 23);
		}
	}
	
	private void safePseudoniemData(APDU apdu) {
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			byte[] buffer = apdu.getBuffer();
			short dataLength = apdu.setIncomingAndReceive();
			
			short length = byteToShort(buffer[ISO7816.OFFSET_P1]);
			byte[] pseudoniemEncrypted = new byte[length];
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, pseudoniemEncrypted, (short) 0, length);
			
			byte[]pseudoniem = decryptDataLCP(pseudoniemEncrypted);
			
			if(idShop == (short)0){
				pseudoniemColruyt = pseudoniem;
				colruytPoints = 0;
			}else if(idShop == (short)1){
				pseudoniemDelhaize = pseudoniem;
				delhaizePoints = 0;
			}
			else if(idShop == (short)2){
				pseudoniemAlienWare = pseudoniem;
				alienWarePoints = 0;
			}
			else if(idShop == (short)3){
				pseudoniemRazor = pseudoniem;
				razorPoints = 0;
			}
			byte[] response = new byte[]{(byte) 0xff};
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) 2);
			apdu.sendBytesLong(shortToByte(length), (short) 0, (short) 2);
		}
	}
	
	
	private void setIDshop(APDU apdu) {
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{	
			byte[] buffer = apdu.getBuffer();
			short dataLength = apdu.setIncomingAndReceive();
			byte[] idBytes = new byte[2];
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, idBytes, (short) 0, (short) 2);
			idShop = byteArrayToShort(idBytes);
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) 2);
			apdu.sendBytesLong(shortToByte(idShop), (short) 0, (short) 2);
		}
	}

	private byte[] decryptDataLCP(byte[] dataEncrypted){
		byte[] data = new byte[dataEncrypted.length];
		cipherWithLCP.init(secretDesKeyWithLCP,Cipher.MODE_DECRYPT);
		cipherWithLCP.doFinal(dataEncrypted, (short) 0 , (short) dataEncrypted.length, data, (short) 0); 
		return data;
	}
	
	private byte[] encryptDataLCP(byte[] data){
		byte[] encryptedData = new byte[data.length];
		cipherWithLCP.init(secretDesKeyWithLCP,Cipher.MODE_ENCRYPT);
		cipherWithLCP.doFinal(data, (short) 0 , (short) data.length, encryptedData, (short) 0); 
		return encryptedData;
	}
	
	private byte[] decryptDataShop(byte[] dataEncrypted){
		byte[] data = new byte[dataEncrypted.length];
		cipherWithShop.init(secretDesKeyWithShop,Cipher.MODE_DECRYPT);
		cipherWithShop.doFinal(dataEncrypted, (short) 0 , (short) dataEncrypted.length, data, (short) 0); 
		return data;
	}
	
	private byte[] encryptDataShop(byte[] data){
		byte[] encryptedData = new byte[data.length];
		cipherWithShop.init(secretDesKeyWithShop,Cipher.MODE_ENCRYPT);
		cipherWithShop.doFinal(data, (short) 0 , (short) data.length, encryptedData, (short) 0); 
		return encryptedData;
	}

	private void keyAgreementLCP(APDU apdu) {
		// get public key out of the data from the apdu data field
		short length2 = apdu.setIncomingAndReceive();
		byte[] pubParamWOther = publicKeyParameterQFromLCP;
		
		byte[] secret = new byte[250];
		
		// create symmetric key with public key
		PrivateKey cardPrivKey = getprivateKey();
		KeyAgreement keyAgreement= KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
		keyAgreement.init(cardPrivKey);
		short secretKeyLength = keyAgreement.generateSecret(pubParamWOther, (short)0, (short) pubParamWOther.length, secret, (short)0);
		
		//copy secret key to secretkey byte array with adjusted size
		byte[] secretKey = new byte[secretKeyLength];
		Util.arrayCopy(secret, (short)0, secretKey,(short) 0, secretKeyLength);
		
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			generateCipherLCP(secretKey);
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) secretKeyLength);
			apdu.sendBytesLong(secretKey, (short) 0, (short) secretKeyLength);
		}
		
	}

	private void generateCipherLCP(byte[] secretKey) {
		DESKey m_desKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES,false);
		// SET KEY VALUE
		m_desKey.setKey(secretKey, (short) 0); 
		secretDesKeyWithLCP = m_desKey;
		cipherWithLCP = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
	}
	
	/*
	 * This method is used to authenticate the owner of the card using a PIN
	 * code.
	 */
	private void validatePIN(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		// The input data needs to be of length 'PIN_SIZE'.
		// Note that the byte values in the Lc and Le fields represent values
		// between
		// 0 and 255. Therefore, if a short representation is required, the
		// following
		// code needs to be used: short Lc = (short) (buffer[ISO7816.OFFSET_LC]
		// & 0x00FF);
		if (buffer[ISO7816.OFFSET_LC] == PIN_SIZE) {
			// This method is used to copy the incoming data in the APDU buffer.
			apdu.setIncomingAndReceive();
			// Note that the incoming APDU data size may be bigger than the APDU
			// buffer
			// size and may, therefore, need to be read in portions by the
			// applet.
			// Most recent smart cards, however, have buffers that can contain
			// the maximum
			// data size. This can be found in the smart card specifications.
			// If the buffer is not large enough, the following method can be
			// used:
			//
			// byte[] buffer = apdu.getBuffer();
			// short bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
			// Util.arrayCopy(buffer, START, storage, START, (short)5);
			// short readCount = apdu.setIncomingAndReceive();
			// short i = ISO7816.OFFSET_CDATA;
			// while ( bytesLeft > 0){
			// Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, storage, i,
			// readCount);
			// bytesLeft -= readCount;
			// i+=readCount;
			// readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
			// }
			if (pin.check(buffer, ISO7816.OFFSET_CDATA, PIN_SIZE) == false)
				ISOException.throwIt(SW_VERIFICATION_FAILED);
		} else
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}

	/*
	 * This method checks whether the user is authenticated and sends the serial
	 * number.
	 */

	private short byteToShort(byte b) {
		return (short) (b & 0xff);
	}

	private short byteArrayToShort(byte[] b) {
		short value = (short) (((b[0] << 8)) | ((b[1] & 0xff)));
		return value;
	}

	private byte[] shortToByte(short s) {
		byte[] shortByte = new byte[2];
		shortByte[0] = (byte) ((s >> 8) & 0xff);
		shortByte[1] = (byte) (s & 0xff);
		return shortByte;
	}

	// zaken nodig voor Elliptic curve sleutels:
	// Bij EC worden de sessie sleutels automatisch geencrypteerd
	// ECCdomainparameters
	private static byte[] a = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFE, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFC };
	private static byte[] p = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFE, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF };

	private static byte[] n = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x99, (byte) 0xDE,
			(byte) 0xF8, (byte) 0x36, (byte) 0x14, (byte) 0x6B, (byte) 0xC9, (byte) 0xB1, (byte) 0xB4, (byte) 0xD2,
			(byte) 0x28, (byte) 0x31 };

	private static byte[] b = new byte[] { (byte) 0x64, (byte) 0x21, (byte) 0x05, (byte) 0x19, (byte) 0xE5, (byte) 0x9C,
			(byte) 0x80, (byte) 0xE7, (byte) 0x0F, (byte) 0xA7, (byte) 0xE9, (byte) 0xAB, (byte) 0x72, (byte) 0x24,
			(byte) 0x30, (byte) 0x49, (byte) 0xFE, (byte) 0xB8, (byte) 0xDE, (byte) 0xEC, (byte) 0xC1, (byte) 0x46,
			(byte) 0xB9, (byte) 0xB1 };

	private static byte[] G = new byte[] { (byte) 0x04, (byte) 0x18, (byte) 0x8D, (byte) 0xA8, (byte) 0x0E, (byte) 0xB0,
			(byte) 0x30, (byte) 0x90, (byte) 0xF6, (byte) 0x7C, (byte) 0xBF, (byte) 0x20, (byte) 0xEB, (byte) 0x43,
			(byte) 0xA1, (byte) 0x88, (byte) 0x00, (byte) 0xF4, (byte) 0xFF, (byte) 0x0A, (byte) 0xFD, (byte) 0x82,
			(byte) 0xFF, (byte) 0x10, (byte) 0x12, (byte) 0x07, (byte) 0x19, (byte) 0x2B, (byte) 0x95, (byte) 0xFF,
			(byte) 0xC8, (byte) 0xDA, (byte) 0x78, (byte) 0x63, (byte) 0x10, (byte) 0x11, (byte) 0xED, (byte) 0x6B,
			(byte) 0x24, (byte) 0xCD, (byte) 0xD5, (byte) 0x73, (byte) 0xF9, (byte) 0x77, (byte) 0xA1, (byte) 0x1E,
			(byte) 0x79, (byte) 0x48, (byte) 0x11 };

	public static void setDomainParameters(ECKey key) {
		key.setA(a, (short) 0, (short) a.length);
		key.setB(b, (short) 0, (short) b.length);
		key.setR(n, (short) 0, (short) n.length);
		key.setK((short) 1);
		key.setG(G, (short) 0, (short) G.length);
		key.setFieldFP(p, (short) 0, (short) p.length);
	}
	
	private static byte[] Wcom = new byte[]{
			(byte) 0x04, (byte) 0x1c, (byte) 0x82, (byte) 0x30, (byte) 0x2a, (byte) 0x7b, 
			(byte) 0x67, (byte) 0x3b, (byte) 0xa3, (byte) 0x4c, (byte) 0xcd, (byte) 0x82, 
			(byte) 0xa9, (byte) 0x98, (byte) 0x4b, (byte) 0x7c, (byte) 0xa8, (byte) 0x24, 
			(byte) 0x45, (byte) 0x54, (byte) 0xe3, (byte) 0xb1, (byte) 0xf6, (byte) 0xdb, 
			(byte) 0x5a, (byte) 0xc3, (byte) 0xa8, (byte) 0xad, (byte) 0x51, (byte) 0x5e, 
			(byte) 0xbd, (byte) 0x05, (byte) 0xdb, (byte) 0x0d, (byte) 0x2b, (byte) 0xa1, 
			(byte) 0x95, (byte) 0xa1, (byte) 0xe6, (byte) 0x5d, (byte) 0x64, (byte) 0x08, 
			(byte) 0x3b, (byte) 0x50, (byte) 0x53, (byte) 0xc9, (byte) 0x8e, (byte) 0x82, 
			(byte) 0xcd
	};
	private static byte[] Scom = new byte[]{
			(byte) 0x7e, (byte) 0x2d, (byte) 0xec, (byte) 0x75, (byte) 0xc2, (byte) 0xac, 
			(byte) 0xee, (byte) 0x8d, (byte) 0x50, (byte) 0x62, (byte) 0x28, (byte) 0x05, 
			(byte) 0x7e, (byte) 0x9a, (byte) 0x7d, (byte) 0x18, (byte) 0x9a, (byte) 0xb1, 
			(byte) 0x23, (byte) 0xac, (byte) 0xf4, (byte) 0x4e, (byte) 0x32, (byte) 0x68
	};
	
	public static ECPublicKey getCommonKeyPublic() {
		ECPublicKey pubKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC,
				KeyBuilder.LENGTH_EC_FP_192, false);
		setDomainParameters(pubKey);
		pubKey.setW(Wcom, (short) 0, (short) Wcom.length);
		return pubKey;
	}

	public static ECPrivateKey getprivateKey() {
		ECPrivateKey priKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE,
				KeyBuilder.LENGTH_EC_FP_192, false);
		setDomainParameters(priKey);
		priKey.setS(Scom, (short) 0, (short) Scom.length);
		
		
		return priKey;
	}

	public void setWcom(byte[] w) {
		Wcom = w;
	}

}
