package main;
import java.rmi.Remote;
import java.rmi.RemoteException;

public interface LCPInterface extends Remote{

	int keyAgreement() throws RemoteException;

}
