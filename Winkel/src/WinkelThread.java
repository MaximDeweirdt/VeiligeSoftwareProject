import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

public class WinkelThread extends Thread {

	private Socket socket = null;

	private WinkelProtocol wp;

	public boolean finishedCom = false;
	public WinkelThread(Socket socket) {
		super("WinkelThread");
		this.socket = socket;
	}

	public void run() {

		try (ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
				ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());) {

			wp = new WinkelProtocol(this);
			Object input;
			Object output;
			try {
				while ((input = in.readObject()) != null) {
					output = wp.processInput(input);
					if(output.equals("close connection"))break;
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