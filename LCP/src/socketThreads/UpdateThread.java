package socketThreads;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

import protocols.UpdateProtocol;
import protocols.VerificationProtocol;

public class UpdateThread extends Thread {


	private Socket socket = null;
	
	private ObjectInputStream in;
	private ObjectOutputStream out;
	
	private UpdateProtocol up;
	
	public UpdateThread(Socket socket){
		super("updateThread");
		this.socket = socket;
	}
	
	public void run(){
		
		try(
			ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
			ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
		) {
			
			this.out = out;
			this.in = in;
			up = new UpdateProtocol();
			Object input;
			Object output;
			try{
				while ((input = in.readObject()) != null) {
					output = up.processInput(input);
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
