package socketThreads;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

import javax.net.ssl.SSLSocket;

import protocols.VerificationProtocol;


public class LCPVerificationThread extends Thread {


	private Socket socket = null;
	
	private ObjectInputStream in;
	private ObjectOutputStream out;
	
	private VerificationProtocol vp;
	
	public LCPVerificationThread(Socket socket){
		super("LCPVerificationThread");
		this.socket = socket;
	}
	
	public void run(){
		
		
		
		try(
			ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
			ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
		) {
			
			this.out = out;
			this.in = in;
			vp = new VerificationProtocol();
			Object input;
			Object output;
			try{
				while ((input = in.readObject()) != null) {
					output = vp.processInput(input);
					if(output.equals("close connection"))break;
					out.writeObject(output);
					out.reset();
				}
			}catch(Exception e){
				e.printStackTrace();
			}
			socket.close();
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
