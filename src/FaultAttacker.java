import java.io.BufferedReader;
import java.io.PrintWriter;

public class FaultAttacker extends AbstractAttacker {

	@SuppressWarnings("unused")
	private BufferedReader target_out = null;
	@SuppressWarnings("unused")
	private PrintWriter target_in = null;
	
	public FaultAttacker(BufferedReader target_out, PrintWriter target_in) {
		super(target_out, target_in);

	}

	@Override
	public void attack() {
		// TODO Auto-generated method stub

	}

}
