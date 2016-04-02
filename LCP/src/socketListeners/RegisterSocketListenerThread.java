package socketListeners;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.concurrent.atomic.AtomicLong;

import socketThreads.RegisterThread;

public class RegisterSocketListenerThread extends Thread {

	private ServerSocket ss;
	private static AtomicLong cardShopID = new AtomicLong();
	
	public RegisterSocketListenerThread(int registerPort) throws IOException {
		super("registerSocketListenerThread");
		ss = new ServerSocket(registerPort);

	}

	public void run() {
		
			
		System.out.println("RegisterSocket Ready");
		while (true) {
			try {
				new RegisterThread(ss.accept()).start();
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
	}

	public static AtomicLong getCardShopID() {
		return cardShopID;
	}
}
