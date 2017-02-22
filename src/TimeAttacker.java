import java.io.BufferedReader;
import java.io.PrintWriter;

public class TimeAttacker implements IAttacker {

	private BufferedReader target_out = null;
	private PrintWriter target_in = null;
	
	public TimeAttacker(BufferedReader target_out, PrintWriter target_in) {
		this.target_out = target_out;
		this.target_in = target_in;
	}
	
	@Override
	public String getRecoveredMaterial() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public int getInteractions() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public void attack() {
		// TODO Auto-generated method stub

	}

}
