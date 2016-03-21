package main;

public class LCPProtocol {

	public static final int CLIENTTYPESTATE = 0;
	
	public static final int CARDKEYAGREESTATE = 1;
	public static final int WINKELKEYAGREESTATE = 2;
	public static final int CARDVALIDSTATE = 3;
	public static final int WINKELVALIDSTATE = 4;
	
	private int state = CLIENTTYPESTATE;
	
	
	public Object processInput(Object theInput) {

		Object theOutput = null;
		
		System.out.println(theInput.toString());
		
		if(theInput != null && theInput.toString().equals("close connection")){
			theOutput = "Bye";
		}
		
		else if (state == CLIENTTYPESTATE){
			if(theInput.toString().equals("SmartCard")){
				state = CARDKEYAGREESTATE;
			}
			else if(theInput.toString().equals("Winkel")){
				state = WINKELKEYAGREESTATE;
			}
			else theOutput = "Bye";
		}
		return theOutput;
	}
}
