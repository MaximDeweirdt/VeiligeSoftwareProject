package protocols;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class RegisterProtocol {
	
	private SecretKey secretKey;
	private Cipher aesCipher;
	
	public static final int TESTCONNECTIONSTATE = -1;
	public static final int KIESWINKELSTATE = 0;
	
	int state = TESTCONNECTIONSTATE;
	
	public RegisterProtocol(SecretKey secretKey){
		this.secretKey = secretKey;
	}
	
	public byte[] processInput(Object theInput) throws Exception {

		byte[] theOutput = null;
		
		System.out.println(theInput.toString());
		
		byte[] decryptedInput = decryptInput(theInput.toString().getBytes());
		
		if(theInput != null && theInput.toString().equals("close connection")){
			theOutput = "Bye".getBytes();
		}
		else if (state == TESTCONNECTIONSTATE){
			System.out.println(decryptedInput.toString());
			theOutput = "test test".getBytes();
		}
		else if (state == KIESWINKELSTATE){
			switch(decryptedInput.toString()){
			case "1": 
				System.out.println("winkel 1 gekozen");
				break;
			case "2":
				System.out.println("winkel 2 gekozen");
				break;
			default: theOutput = "Bye".getBytes();
			}
			
		}
		
		return encryptOutput(theOutput);
	}

	private byte[] decryptInput(byte[] theInput) throws Exception {
		// Create the cipher
	    aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

	    // Initialize the cipher for encryption
	    aesCipher.init(Cipher.DECRYPT_MODE, secretKey);

	    // Decrypt the cleartext
	    byte[] decryptedText = aesCipher.doFinal(theInput);
		return decryptedText;
	}
	
	private byte[] encryptOutput(byte[] theOutput) throws Exception {

	    // Create the cipher
	    aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

	    // Initialize the cipher for encryption
	    aesCipher.init(Cipher.ENCRYPT_MODE, secretKey);

	    // Encrypt the cleartext
	    byte[] ciphertext = aesCipher.doFinal(theOutput);

		return ciphertext;
	}

}
