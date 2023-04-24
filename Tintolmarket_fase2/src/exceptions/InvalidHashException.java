package exceptions;

@SuppressWarnings("serial")
public class InvalidHashException extends Exception {

	public InvalidHashException(String msg) {
		super(msg);
	}
}
