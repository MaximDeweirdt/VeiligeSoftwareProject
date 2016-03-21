package be.msec.smartcard;

import com.sun.javacard.crypto.s;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.security.ECKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.PublicKey;
import javacard.security.RSAPrivateKey;
import javacard.security.Signature;



public class IdentityCard extends Applet {
	private final static byte IDENTITY_CARD_CLA =(byte)0x80;
	
	private static final byte VALIDATE_PIN_INS = 0x22;
	private static final byte GET_NAME_INS = 0x24;
	private static final byte GET_SERIAL_INS = 0x26;
	private static final byte GET_CHALL_INS = 0x28;
	private static final byte GET_CERT_SIZE=0x30;
	private static final byte GET_CERT_INS1 = 0x32;
	private static final byte GET_CERT_INS2 = 0x34;
	private static final byte GET_CERT_INS = 0x36;
	
	private final static byte PIN_TRY_LIMIT =(byte)0x03;
	private final static byte PIN_SIZE =(byte)0x04;
	
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;

	private byte[] privModulus = new byte[]{(byte)-73, (byte)-43, (byte)96, (byte)-107, (byte)82, (byte)25, (byte)-66, (byte)34, (byte)5, (byte)-58, (byte)75, (byte)-39, (byte)-54, (byte)43, (byte)25, (byte)-117, (byte)80, (byte)-62, (byte)51, (byte)19, (byte)59, (byte)-70, (byte)-100, (byte)85, (byte)24, (byte)-57, (byte)108, (byte)-98, (byte)-2, (byte)1, (byte)-80, (byte)-39, (byte)63, (byte)93, (byte)112, (byte)7, (byte)4, (byte)18, (byte)-11, (byte)-98, (byte)17, (byte)126, (byte)-54, (byte)27, (byte)-56, (byte)33, (byte)77, (byte)-111, (byte)-74, (byte)-78, (byte)88, (byte)70, (byte)-22, (byte)-3, (byte)15, (byte)16, (byte)37, (byte)-18, (byte)92, (byte)74, (byte)124, (byte)-107, (byte)-116, (byte)-125};
	private byte[] privExponent = new byte[]{(byte)24, (byte)75, (byte)93, (byte)-79, (byte)62, (byte)33, (byte)98, (byte)-52, (byte)50, (byte)65, (byte)43, (byte)-125, (byte)3, (byte)-63, (byte)-64, (byte)101, (byte)117, (byte)-19, (byte)-60, (byte)60, (byte)53, (byte)119, (byte)-118, (byte)-13, (byte)-128, (byte)11, (byte)-46, (byte)-30, (byte)12, (byte)37, (byte)-125, (byte)14, (byte)104, (byte)-5, (byte)-15, (byte)-120, (byte)-113, (byte)-49, (byte)-70, (byte)-78, (byte)114, (byte)122, (byte)34, (byte)114, (byte)-99, (byte)-102, (byte)43, (byte)-43, (byte)-102, (byte)71, (byte)115, (byte)116, (byte)-105, (byte)-48, (byte)-80, (byte)109, (byte)117, (byte)106, (byte)88, (byte)6, (byte)-69, (byte)-42, (byte)-83, (byte)25};

	private byte[] certificate = new byte[]{(byte)48, (byte)-126, (byte)1, (byte)-67, (byte)48, (byte)-126, (byte)1, (byte)103, (byte)-96, (byte)3, (byte)2, (byte)1, (byte)2, (byte)2, (byte)5, (byte)0, (byte)-73, (byte)-43, (byte)96, (byte)-107, (byte)48, (byte)13, (byte)6, (byte)9, (byte)42, (byte)-122, (byte)72, (byte)-122, (byte)-9, (byte)13, (byte)1, (byte)1, (byte)5, (byte)5, (byte)0, (byte)48, (byte)100, (byte)49, (byte)11, (byte)48, (byte)9, (byte)6, (byte)3, (byte)85, (byte)4, (byte)6, (byte)19, (byte)2, (byte)66, (byte)69, (byte)49, (byte)13, (byte)48, (byte)11, (byte)6, (byte)3, (byte)85, (byte)4, (byte)7, (byte)12, (byte)4, (byte)71, (byte)101, (byte)110, (byte)116, (byte)49, (byte)25, (byte)48, (byte)23, (byte)6, (byte)3, (byte)85, (byte)4, (byte)10, (byte)12, (byte)16, (byte)75, (byte)97, (byte)72, (byte)111, (byte)32, (byte)83, (byte)105, (byte)110, (byte)116, (byte)45, (byte)76, (byte)105, (byte)101, (byte)118, (byte)101, (byte)110, (byte)49, (byte)20, (byte)48, (byte)18, (byte)6, (byte)3, (byte)85, (byte)4, (byte)11, (byte)12, (byte)11, (byte)86, (byte)97, (byte)107, (byte)103, (byte)114, (byte)111, (byte)101, (byte)112, (byte)32, (byte)73, (byte)84, (byte)49, (byte)21, (byte)48, (byte)19, (byte)6, (byte)3, (byte)85, (byte)4, (byte)3, (byte)12, (byte)12, (byte)74, (byte)97, (byte)110, (byte)32, (byte)86, (byte)111, (byte)115, (byte)115, (byte)97, (byte)101, (byte)114, (byte)116, (byte)48, (byte)32, (byte)23, (byte)13, (byte)49, (byte)48, (byte)48, (byte)50, (byte)50, (byte)52, (byte)48, (byte)57, (byte)52, (byte)51, (byte)48, (byte)50, (byte)90, (byte)24, (byte)15, (byte)53, (byte)49, (byte)55, (byte)57, (byte)48, (byte)49, (byte)48, (byte)57, (byte)49, (byte)57, (byte)50, (byte)57, (byte)52, (byte)50, (byte)90, (byte)48, (byte)100, (byte)49, (byte)11, (byte)48, (byte)9, (byte)6, (byte)3, (byte)85, (byte)4, (byte)6, (byte)19, (byte)2, (byte)66, (byte)69, (byte)49, (byte)13, (byte)48, (byte)11, (byte)6, (byte)3, (byte)85, (byte)4, (byte)7, (byte)12, (byte)4, (byte)71, (byte)101, (byte)110, (byte)116, (byte)49, (byte)25, (byte)48, (byte)23, (byte)6, (byte)3, (byte)85, (byte)4, (byte)10, (byte)12, (byte)16, (byte)75, (byte)97, (byte)72, (byte)111, (byte)32, (byte)83, (byte)105, (byte)110, (byte)116, (byte)45, (byte)76, (byte)105, (byte)101, (byte)118, (byte)101, (byte)110, (byte)49, (byte)20, (byte)48, (byte)18, (byte)6, (byte)3, (byte)85, (byte)4, (byte)11, (byte)12, (byte)11, (byte)86, (byte)97, (byte)107, (byte)103, (byte)114, (byte)111, (byte)101, (byte)112, (byte)32, (byte)73, (byte)84, (byte)49, (byte)21, (byte)48, (byte)19, (byte)6, (byte)3, (byte)85, (byte)4, (byte)3, (byte)12, (byte)12, (byte)74, (byte)97, (byte)110, (byte)32, (byte)86, (byte)111, (byte)115, (byte)115, (byte)97, (byte)101, (byte)114, (byte)116, (byte)48, (byte)92, (byte)48, (byte)13, (byte)6, (byte)9, (byte)42, (byte)-122, (byte)72, (byte)-122, (byte)-9, (byte)13, (byte)1, (byte)1, (byte)1, (byte)5, (byte)0, (byte)3, (byte)75, (byte)0, (byte)48, (byte)72, (byte)2, (byte)65, (byte)0, (byte)-73, (byte)-43, (byte)96, (byte)-107, (byte)82, (byte)25, (byte)-66, (byte)34, (byte)5, (byte)-58, (byte)75, (byte)-39, (byte)-54, (byte)43, (byte)25, (byte)-117, (byte)80, (byte)-62, (byte)51, (byte)19, (byte)59, (byte)-70, (byte)-100, (byte)85, (byte)24, (byte)-57, (byte)108, (byte)-98, (byte)-2, (byte)1, (byte)-80, (byte)-39, (byte)63, (byte)93, (byte)112, (byte)7, (byte)4, (byte)18, (byte)-11, (byte)-98, (byte)17, (byte)126, (byte)-54, (byte)27, (byte)-56, (byte)33, (byte)77, (byte)-111, (byte)-74, (byte)-78, (byte)88, (byte)70, (byte)-22, (byte)-3, (byte)15, (byte)16, (byte)37, (byte)-18, (byte)92, (byte)74, (byte)124, (byte)-107, (byte)-116, (byte)-125, (byte)2, (byte)3, (byte)1, (byte)0, (byte)1, (byte)48, (byte)13, (byte)6, (byte)9, (byte)42, (byte)-122, (byte)72, (byte)-122, (byte)-9, (byte)13, (byte)1, (byte)1, (byte)5, (byte)5, (byte)0, (byte)3, (byte)65, (byte)0, (byte)33, (byte)97, (byte)121, (byte)-25, (byte)43, (byte)-47, (byte)113, (byte)-104, (byte)-11, (byte)-42, (byte)-46, (byte)-17, (byte)1, (byte)-38, (byte)50, (byte)59, (byte)-63, (byte)-74, (byte)-33, (byte)90, (byte)92, (byte)-59, (byte)99, (byte)-17, (byte)-60, (byte)17, (byte)25, (byte)79, (byte)68, (byte)68, (byte)-57, (byte)-8, (byte)-64, (byte)35, (byte)-19, (byte)-114, (byte)110, (byte)-116, (byte)31, (byte)-126, (byte)-24, (byte)54, (byte)71, (byte)82, (byte)-53, (byte)-78, (byte)-84, (byte)-45, (byte)-83, (byte)87, (byte)68, (byte)124, (byte)-1, (byte)-128, (byte)-49, (byte)124, (byte)103, (byte)28, (byte)56, (byte)-114, (byte)-10, (byte)97, (byte)-78, (byte)54};
	
	
	private byte[] serial = new byte[]{(byte)0x4A, (byte)0x61, (byte)0x6e};
	private byte[] name = new byte[]{0x4A, 0x61, 0x6E, 0x20, 0x56, 0x6F, 0x73, 0x73, 0x61, 0x65, 0x72, 0x74};
	private OwnerPIN pin;

	
	private IdentityCard() {
		/*
		 * During instantiation of the applet, all objects are created.
		 * In this example, this is the 'pin' object.
		 */
		pin = new OwnerPIN(PIN_TRY_LIMIT,PIN_SIZE);
		pin.update(new byte[]{0x01,0x02,0x03,0x04},(short) 0, PIN_SIZE);
	

		/*
		 * This method registers the applet with the JCRE on the card.
		 */
		register();
	}

	/*
	 * This method is called by the JCRE when installing the applet on the card.
	 */
	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
		new IdentityCard();
	}
	
	/*
	 * If no tries are remaining, the applet refuses selection.
	 * The card can, therefore, no longer be used for identification.
	 */
	public boolean select() {
		if (pin.getTriesRemaining()==0)
			return false;
		return true;
	}

	/*
	 * This method is called when the applet is selected and an APDU arrives.
	 */
	public void process(APDU apdu) throws ISOException {
		//A reference to the buffer, where the APDU data is stored, is retrieved.
		byte[] buffer = apdu.getBuffer();
		
		//If the APDU selects the applet, no further processing is required.
		if(this.selectingApplet())
			return;
		
		//Check whether the indicated class of instructions is compatible with this applet.
		if (buffer[ISO7816.OFFSET_CLA] != IDENTITY_CARD_CLA)ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		//A switch statement is used to select a method depending on the instruction
		switch(buffer[ISO7816.OFFSET_INS]){
		case VALIDATE_PIN_INS:
			validatePIN(apdu);
			break;
		case GET_SERIAL_INS:
			getSerial(apdu);
			break;
		case GET_NAME_INS:
			getName(apdu);
			break;
		case GET_CHALL_INS:
			challengeResponse(apdu);
			break;
		case GET_CERT_SIZE:
			getCertificateSize(apdu);
			break;
		case GET_CERT_INS1:
			getCertificate1(apdu);
			break;
		case GET_CERT_INS2:
			getCertificate2(apdu);
			break;
		case GET_CERT_INS:
			getCertificate(apdu);
		//If no matching instructions are found it is indicated in the status word of the response.
		//This can be done by using this method. As an argument a short is given that indicates
		//the type of warning. There are several predefined warnings in the 'ISO7816' class.
		default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	private void getCertificate(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		
		byte P1 = buffer[ISO7816.OFFSET_P1];
		byte P2 = buffer[ISO7816.OFFSET_P2];
			
		//short size = (short)((P2 - P1)&(short)(0xff));
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) (P2&0xff));
		byteToShort(P1);
		apdu.sendBytesLong(certificate, (short) ((short) (P1&0xff)*240), (short) (P2&0xff));
		
	}

	private void getCertificateSize(APDU apdu) {
		byte[] sizeByte = new byte[2];
		sizeByte[1] = (byte)(certificate.length & 0xff);
		sizeByte[0] = (byte)((certificate.length >> 8) & 0xff);
		//sizeByte[0] = (byte)(certificate.length);
		//sizeByte[1] = (byte)((certificate.length >> 8) & 0xff);
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) sizeByte.length);
		apdu.sendBytesLong(sizeByte, (short)0, (short)sizeByte.length);
	}

	private void getCertificate1(APDU apdu) {
		
		byte[] buffer = new byte[240];
		byte[] buffer2 = apdu.getBuffer();
		
		
		short i = 0;
		
		apdu.setOutgoing();
		apdu.setOutgoingLength((short)240);
		apdu.sendBytesLong(certificate, (short)0, (short)240);
		
	}
	
	private void getCertificate2(APDU apdu) {
		
		byte[] buffer = new byte[240];
		
		short i = 0;
		apdu.setOutgoing();
		apdu.setOutgoingLength((short)209);
		apdu.sendBytesLong(certificate, (short)240, (short)209);
		
	}

	private void challengeResponse(APDU apdu) {
		short offset = 0;
		short keySizeInBytes = 64;
	    short keySizeInBits = 512;
	    RSAPrivateKey privKey;
	    //Building RSA private keys on smart cards
		privKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, keySizeInBits, false);
	    privKey.setExponent(privExponent, offset, keySizeInBytes);
	    privKey.setModulus(privModulus, offset, keySizeInBytes);
	    
	    //Generation of a digital signature on a smart card
	    Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
	    signature.init(privKey,  Signature.MODE_SIGN);
	    byte[] buffer = apdu.getBuffer();
	    short dataLength = apdu.setIncomingAndReceive();
	    
	    byte[] output = new byte[256];
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
		    short sigLength = signature.sign(buffer,  ISO7816.OFFSET_CDATA,  dataLength,  output,  (short) 0);
			apdu.setOutgoing();
			apdu.setOutgoingLength(sigLength);
			apdu.sendBytesLong(output,(short)0,sigLength);
			
		}
	   
	}

	/*
	 * This method is used to authenticate the owner of the card using a PIN code.
	 */
	private void validatePIN(APDU apdu){
		byte[] buffer = apdu.getBuffer();
		//The input data needs to be of length 'PIN_SIZE'.
		//Note that the byte values in the Lc and Le fields represent values between
		//0 and 255. Therefore, if a short representation is required, the following
		//code needs to be used: short Lc = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
		if(buffer[ISO7816.OFFSET_LC]==PIN_SIZE){
			//This method is used to copy the incoming data in the APDU buffer.
			apdu.setIncomingAndReceive();
			//Note that the incoming APDU data size may be bigger than the APDU buffer 
			//size and may, therefore, need to be read in portions by the applet. 
			//Most recent smart cards, however, have buffers that can contain the maximum
			//data size. This can be found in the smart card specifications.
			//If the buffer is not large enough, the following method can be used:
			//
			//byte[] buffer = apdu.getBuffer();
			//short bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
			//Util.arrayCopy(buffer, START, storage, START, (short)5);
			//short readCount = apdu.setIncomingAndReceive();
			//short i = ISO7816.OFFSET_CDATA;
			//while ( bytesLeft > 0){
			//	Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, storage, i, readCount);
			//	bytesLeft -= readCount;
			//	i+=readCount;
			//	readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
			//}
			if (pin.check(buffer, ISO7816.OFFSET_CDATA,PIN_SIZE)==false)
				ISOException.throwIt(SW_VERIFICATION_FAILED);
		}else ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}
	
	/*
	 * This method checks whether the user is authenticated and sends
	 * the serial number.
	 */
	private void getSerial(APDU apdu){
		//If the pin is not validated, a response APDU with the
		//'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			//This sequence of three methods sends the data contained in
			//'serial' with offset '0' and length 'serial.length'
			//to the host application.
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)serial.length);
			apdu.sendBytesLong(serial,(short)0,(short)serial.length);
		}
	}
	
	private void getName(APDU apdu){
		//If the pin is not validated, a response APDU with the
		//'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			//This sequence of three methods sends the data contained in
			//'serial' with offset '0' and length 'serial.length'
			//to the host application.
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)name.length);
			apdu.sendBytesLong(name,(short)0,(short)name.length);
		}
	}
	
	private short byteToShort(byte b){
		return (short) (b & 0xff);
	}
	
	private short byteArrayToShort(byte[] b){
		short value = (short)(((b[0] << 8)) | ((b[1] & 0xff)));
		return value;
	}
	
	private byte[] shortToByte(short s){
		byte[] shortByte = new byte[2];
		shortByte[0] = (byte)((s >> 8) & 0xff);
		shortByte[1] = (byte)(s & 0xff);
		return shortByte;
	}
	
	//zaken nodig voor Elliptic curve sleutels:
	//Bij EC worden de sessie sleutels automatisch geencrypteerd
	//ECC domain parameters
	private static byte[] a = new byte[] {
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0xFF, (byte) 0xFF,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC
	};
			
	private static byte[] p = new byte[] {
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0xFF, (byte) 0xFF,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
	};
			
	private static byte[] n = new byte[] {
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		(byte) 0x99, (byte) 0xDE, (byte) 0xF8, (byte) 0x36, (byte) 0x14, (byte) 0x6B,
		(byte) 0xC9, (byte) 0xB1, (byte) 0xB4, (byte) 0xD2, (byte) 0x28, (byte) 0x31
	};
			
	private static byte[] b = new byte[] {
		(byte) 0x64, (byte) 0x21, (byte) 0x05, (byte) 0x19, (byte) 0xE5, (byte) 0x9C,
		(byte) 0x80, (byte) 0xE7, (byte) 0x0F, (byte) 0xA7, (byte) 0xE9, (byte) 0xAB,
		(byte) 0x72, (byte) 0x24, (byte) 0x30, (byte) 0x49, (byte) 0xFE, (byte) 0xB8,
		(byte) 0xDE, (byte) 0xEC, (byte) 0xC1, (byte) 0x46, (byte) 0xB9, (byte) 0xB1
	};
			
	private static byte[] G = new byte[] {
		(byte) 0x04, (byte) 0x18, (byte) 0x8D, (byte) 0xA8, (byte) 0x0E, (byte) 0xB0,
		(byte) 0x30, (byte) 0x90, (byte) 0xF6, (byte) 0x7C, (byte) 0xBF, (byte) 0x20,
		(byte) 0xEB, (byte) 0x43, (byte) 0xA1, (byte) 0x88, (byte) 0x00, (byte) 0xF4,
		(byte) 0xFF, (byte) 0x0A, (byte) 0xFD, (byte) 0x82, (byte) 0xFF, (byte) 0x10,
		(byte) 0x12, (byte) 0x07, (byte) 0x19, (byte) 0x2B, (byte) 0x95, (byte) 0xFF,
		(byte) 0xC8, (byte) 0xDA, (byte) 0x78, (byte) 0x63, (byte) 0x10, (byte) 0x11,
		(byte) 0xED, (byte) 0x6B, (byte) 0x24, (byte) 0xCD, (byte) 0xD5, (byte) 0x73,
		(byte) 0xF9, (byte) 0x77, (byte) 0xA1, (byte) 0x1E, (byte) 0x79, (byte) 0x48,
		(byte) 0x11
	};

	
	private static byte[] publicKey = new byte[]{
		(byte) 0x48, (byte) 0x93, (byte) 0x43, (byte) 0x2d, (byte) 0xbf, (byte) 0x28, 
		(byte) 0x86, (byte) 0xe6, (byte) 0x2a, (byte) 0x13, (byte) 0x77, (byte) 0xf4, 
		(byte) 0xe4, (byte) 0x8c, (byte) 0xdc, (byte) 0x72, (byte) 0x27, (byte) 0x83, 
		(byte) 0xe2, (byte) 0xf7, (byte) 0x0a, (byte) 0x71, (byte) 0x45, (byte) 0x53, 
		(byte) 0xda, (byte) 0x24, (byte) 0x83, (byte) 0x91, (byte) 0x9d, (byte) 0xe1, 
		(byte) 0xf8, (byte) 0x01, (byte) 0x62, (byte) 0xf1, (byte) 0xce, (byte) 0x44, 
		(byte) 0x60, (byte) 0x84, (byte) 0x03, (byte) 0x68, (byte) 0x0c, (byte) 0x6e, 
		(byte) 0x37, (byte) 0x11, (byte) 0xc4, (byte) 0x6e, (byte) 0x37, (byte) 0x79, 
		(byte) 0x6
	};
		
	public static byte[] privateKey = new byte[]{
		(byte) 0xa6, (byte) 0xfb, (byte) 0xc8, (byte) 0x15, (byte) 0xe2, (byte) 0x23, 
		(byte) 0x3e, (byte) 0x34, (byte) 0x10, (byte) 0x6e, (byte) 0x31, (byte) 0x90, 
		(byte) 0x7f, (byte) 0x0c, (byte) 0xfb, (byte) 0xad, (byte) 0x10, (byte) 0x12, 
		(byte) 0x4d, (byte) 0x5c, (byte) 0x83, (byte) 0xf2, (byte) 0xf9, (byte) 0x22
	};
	
	public static byte[] Wcom = new byte[]{};

	public static void setDomainParameters(ECKey key){
		key.setA(a, (short)0, (short)a.length);
		key.setB(b, (short)0, (short)b.length);
		key.setR(n, (short)0, (short)n.length);
		key.setK((short)1);
		key.setG(G, (short)0, (short)G.length);
		key.setFieldFP(p, (short)0, (short)p.length);
	}
	
		
	public static PublicKey getCommonKeyPublic(APDU apdu){
		ECPublicKey pubKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_192, false);
		setDomainParameters(pubKey);
		pubKey.setW(Wcom, (short)0, (short)Wcom.length);
		return pubKey;
	}
	
	public void setWcom(byte[] w){
		Wcom = w;
	}
}
