package socketListeners;

import java.io.IOException;
import java.net.ServerSocket;

import socketThreads.LCPVerificationThread;
import socketThreads.RegisterThread;

public class VerificationSocketListenerThread extends Thread {

	private ServerSocket ss;
	
	public VerificationSocketListenerThread(int registerPort) throws IOException {
		
		super("verificationSocketListenerThread");
		ss = new ServerSocket(registerPort);
		
		
	    
	}
	public void run() {
		System.out.println("Ready...");
		while (true) {
			try {
				new LCPVerificationThread(ss.accept()).start();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
	}
}
