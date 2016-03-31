package socketThreads;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

import javax.crypto.SecretKey;

import protocols.LCPProtocol;
import protocols.RegisterProtocol;

public class RegisterThread extends Thread {

	private Socket socket = null;

	private ObjectInputStream in;
	private ObjectOutputStream out;

	private RegisterProtocol rp;

	public boolean finishedCom = false;
	public RegisterThread(Socket socket) {
		super("ShopRegisterThread");
		this.socket = socket;
	}

	public void run() {

		try (ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
				ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());) {

			this.out = out;
			this.in = in;
			rp = new RegisterProtocol(this);
			Object input;
			Object output;
			try {
				while ((input = in.readObject()) != null&&!finishedCom) {
					output = rp.processInput(input);
					out.writeObject(output);
					out.reset();
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
			socket.close();

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
