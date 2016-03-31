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

public class IdentityCard extends Applet {
	private final static byte IDENTITY_CARD_CLA = (byte) 0x80;

	private static final byte VALIDATE_PIN_INS = 0x01;

	private static final byte KEY_AGREEMENT_LCP_INS = 0x02;
	//private static final byte ENCRYPT_DATA_LCP_INS = 0x03;
	//private static final byte DECRYPT_DATA_LCP_INS = 0x04;
	private static final byte SET_ID_SHOP_INS = 0x05;
	private static final byte SET_PSEUDONIEM_INS = 0x06;
	
	private final static byte PIN_TRY_LIMIT = (byte) 0x03;
	private final static byte PIN_SIZE = (byte) 0x04;

	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;

	private short idShop;
	
	private OwnerPIN pin;
	private DESKey secretDesKeyWithLCP;
	private Cipher cipherWithLCP;
	
	//NOG 3 pseudoniemen te maken
	private byte[] pseudoniemColruyt = new byte[250];
	
	private short[] loyaltypoints;
	
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
		// If no matching instructions are found it is indicated in the status
		// word of the response.
		// This can be done by using this method. As an argument a short is
		// given that indicates
		// the type of warning. There are several predefined warnings in the
		// 'ISO7816' class.
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	private void safePseudoniemData(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short dataLength = apdu.setIncomingAndReceive();
		short length = buffer[ISO7816.OFFSET_P1];
		byte[] pseudoniemEncrypted = new byte[length];
		Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, pseudoniemEncrypted, (short) 0, length);
		
		byte[]pseudoniem = decryptDataLCP(pseudoniemEncrypted);
		
		if(idShop == (short)0){
			pseudoniemColruyt = pseudoniem;
		}else if(idShop == (short)1){
			//NOG TE SCHRIJVEN
		}
		
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) length);
		apdu.sendBytesLong(pseudoniem, (short) 0, (short) length);
	}
	
	
	private void setIDshop(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short dataLength = apdu.setIncomingAndReceive();
		byte[] idBytes = new byte[2];
		Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, idBytes, (short) 0, (short) 2);
		idShop = byteArrayToShort(idBytes);
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) 2);
		apdu.sendBytesLong(idBytes, (short) 0, (short) 2);
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

	private void keyAgreementLCP(APDU apdu) {
		// get public key out of the data from the apdu data field
		byte[] buffer = apdu.getBuffer();
		short length2 = apdu.setIncomingAndReceive();
		short length = buffer[ISO7816.OFFSET_P1];
		byte[] pubParamWOther = new byte[length];
		Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, pubParamWOther, (short) 0, length);
		
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
