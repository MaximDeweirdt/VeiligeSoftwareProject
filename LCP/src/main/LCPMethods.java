package main;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class LCPMethods extends UnicastRemoteObject  implements LCPInterface {

	protected LCPMethods() throws RemoteException {
		super();
		// TODO Auto-generated constructor stub
	}

	@Override
	public synchronized int keyAgreement() throws RemoteException{
		
	}
}
