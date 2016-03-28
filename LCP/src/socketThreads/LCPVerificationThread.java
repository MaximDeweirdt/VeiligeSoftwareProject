package socketThreads;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

import javax.net.ssl.SSLSocket;

import protocols.LCPProtocol;


public class LCPVerificationThread extends Thread {


	private Socket socket = null;
	
	private ObjectInputStream in;
	private ObjectOutputStream out;
	
	private LCPProtocol lcpp;
	
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
			lcpp = new LCPProtocol();
			Object input;
			Object output;
			try{
				while((input = in.readObject()) != null){
					output = lcpp.processInput(input);
					out.writeObject(output);
					out.reset();
					if(output.toString().equals("Bye")){
						break;
					}
				}
			}catch(ClassNotFoundException e){
				e.printStackTrace();
			}
			socket.close();
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
