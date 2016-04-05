package socketListeners;

import java.io.IOException;
import java.net.ServerSocket;

import socketThreads.RevalidateThread;
import socketThreads.UpdateThread;

public class RevalidateSocketListenerThread extends Thread {

	private ServerSocket ss;
	
	public RevalidateSocketListenerThread(int registerPort) throws IOException {
		
		super("revalidateSocketListenerThread");
		ss = new ServerSocket(registerPort);
	    
	}
	public void run() {
		System.out.println("Revalidate Socket Ready...");
		while (true) {
			try {
				new RevalidateThread(ss.accept()).start();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
	}
}
