package socketListeners;

import java.io.IOException;
import java.net.ServerSocket;

import socketThreads.LCPVerificationThread;
import socketThreads.UpdateThread;

public class UpdateSocketListenerThread  extends Thread {

	private ServerSocket ss;
	
	public UpdateSocketListenerThread(int registerPort) throws IOException {
		
		super("updateSocketListenerThread");
		ss = new ServerSocket(registerPort);
	    
	}
	public void run() {
		System.out.println("Update Socket Ready...");
		while (true) {
			try {
				new UpdateThread(ss.accept()).start();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
	}

}
