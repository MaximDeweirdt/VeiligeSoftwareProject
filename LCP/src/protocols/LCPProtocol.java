package protocols;

public class LCPProtocol {

	public static final int CLIENTTYPESTATE = 0;
	
	private int state = CLIENTTYPESTATE;
	
	
	public Object processInput(Object theInput) {

		Object theOutput = "Bye";
		
		System.out.println(theInput.toString());
		
		if(theInput != null && theInput.toString().equals("close connection")){
			theOutput = "Bye";
		}
		
		return theOutput;
	}
}
