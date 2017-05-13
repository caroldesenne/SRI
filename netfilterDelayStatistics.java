import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;

/**
 * @author Carolina de Senne Garcia
 */

public class netfilterDelayStatistics {

	/* String pattern for SOCKADDR line*/
	public static final String sockaddrLine = "^type=SOCKADDR(?:.+)saddr=(.+)\\s?$";
	public static final String sockaddrLineExample = "type=SOCKADDR msg=audit(1494523111.293:1661796): saddr=01002F686F6D652F6361726F6C2F2E676E7570672F532E6770672D6167656E74";

	/* String pattern for NETFILTER_PKT line*/
	public static final String netfilterPktLine = "^type=NETFILTER_PKT(?:.+)?daddr=(\\d+\\.\\d+\\.\\d+\\.\\d+)(?:.+)?dport=(\\d+)$";
	public static final String netfilterPktLineExample = "type=NETFILTER_PKT msg=audit(1494469680.359:1606788): action=0 hook=1 len=76 inif=enp0s3 outif=? smac=52:54:00:12:35:02 dmac=08:00:27:1d:e8:ec macproto=0x0800 saddr=91.189.89.199 daddr=10.0.2.15 ipid=31284 proto=17 sport=123 dport=58139";

	/* String with the path to log file */
	public static final String logPath = "/var/log/audit/audit.log.2";

	/* Map to keep track of processed SOCKADDR records (IP:port)  and their respective line number in the log file*/
	public static Map<String, Integer> sockaddrToLineNumber = new HashMap<String,Integer>();

	/* Map from the delays found (in terms of records or lines) between SOCKADDR and first respective NETFILTER and number of occurences */
	public static Map<Integer, Integer> delayOccurences = new HashMap<Integer,Integer>();

	// Main function
	public static void main(String[] args) {
		
		// Patterns
		Pattern saddrP = Pattern.compile(sockaddrLine);
		Pattern netfilterP = Pattern.compile(netfilterPktLine);

		// Pattern Tests
		//System.out.println(parseLineToAddressString(netfilterPktLineExample, saddrP, netfilterP));
		//System.out.println(parseLineToAddressString(sockaddrLineExample, saddrP, netfilterP));

		// Process File
		ProcessLogFile(saddrP,netfilterP);
		printDelayMap();

		// Calculate mean and variance for delays
		double[] statistics = calculateStatistics();

	}

	/**
	 * Calculate the delay mean and variance
	 *
	 * @return double array with the mean in the first case and variance in the seconde one
	 */
	public static double[] calculateStatistics() {
		int n = 0;
		double mean = 0;
		double variance = 0;
		// calculate mean
		for(Map.Entry<Integer,Integer> entry: delayOccurences.entrySet()) {
			int weight = entry.getValue();
			int delay = entry.getKey();
			n = n+weight;
			mean = mean+(weight*delay);
		}
		mean = mean/n;
		// calculate variance
		for(Map.Entry<Integer,Integer> entry: delayOccurences.entrySet()) {
			int weight = entry.getValue();
			int delay = entry.getKey();
			variance = variance+(weight*(delay-mean)*(delay-mean));
		}
		variance = variance/n;
		double[] statistics = new double[2];
		statistics[0] = mean;
		statistics[1] = variance;
		return statistics;
	}

	/**
	 * Print the Delay Map in the following format:
	 * key : value
	 */
	public static void printDelayMap() {
		for(Map.Entry<Integer,Integer> entry: delayOccurences.entrySet()) {
			System.out.println(entry.getKey()+" : "+entry.getValue());
		}
	}

	/**
	 * Read lines from log file and process each SOCKADDR and NETFILTER records 
	 * 
	 * @param saddrP SOCKADDR record pattern
	 * @param netfilterP NETFILTER record pattern 
	 */
	public static void ProcessLogFile(Pattern saddrP, Pattern netfilterP) {
		BufferedReader buffer = openFile(logPath);
		int countLine = 1;
		String line;
		String address_port;
		try {
			while((line = buffer.readLine()) != null) {
				if((address_port = parseLineToAddressString(line,saddrP,netfilterP)) != null) {
					//System.out.println(countLine+": "+line);
					if(line.startsWith("type=SOCKADDR")) {
						treatSockaddrLine(address_port,countLine);
						//System.out.println("SADDR -> "+address_port);
					} else if(line.startsWith("type=NETFILTER_PKT")) {
						treatNetfilterLine(address_port,countLine);
						//System.out.println("NETFI -> "+address_port);
					}
				}
				countLine++;
			}
		} catch(IOException e) {
			System.err.println(e.getMessage());
			System.err.println("Problem reading file");
		}
	}

	/**
	 * Insert the pair \\<IP:Port, Line Number\\> in the Mapping of SOCKADDR records found until the current line
	 *
	 * @param addr string containing the IP address and port of the saddr record
	 * @param currentLine line number of the record in the log file
	 */
	public static void treatSockaddrLine(String addr, int currentLine) {
		sockaddrToLineNumber.put(addr,currentLine);
	}

	/**
	 * Check if a corresponding SOCKADDR record has been seen in the log file (checks the sockaddrToLineNumber map):
	 *
	 * If it EXISTS in the map, removes it and increment the corresponding delay Occurences number; 
	 * the delay is defined to be the records/lines number delay between a SOCKADDR record and the first corresponding NETFILTER record in the file
	 *
	 * @param addr string containing the IP address and port of the saddr record
	 * @param currentLine line number of the record in the log file
	 */
	public static void treatNetfilterLine(String addr, int currentLine) {
		Integer previousLine = null;
		if((previousLine = sockaddrToLineNumber.remove(addr)) != null) {
			System.out.println("Miracle: found a match!");
			Integer delay = currentLine-previousLine;
			Integer Occurences = delayOccurences.remove(delay);
			if(Occurences == null)
				Occurences = new Integer(0);
			delayOccurences.put(delay,++Occurences);
		}
	}

	/**
	 * Return either null or a String containing the IP address and the port in the following format:
	 * 
	 * xxxxxxxx:xxxx
	 * corresponding to
	 * IP:port
	 * where x is an hexadecimal digit
	 *
	 * If line is a SOCKADDR record, then the addres will be retrieved from saddr
	 * If line is a NETFILTER_PKT record, then the address will be retrieved from daddr and dport
	 * If line is any other type of record, then return null
	 *
	 * @param line the record line being parsed
	 * @param saddrP SOCKADDR record pattern
	 * @param netfilterP NETFILTER_PKT record pattern
	 * @return a string containing the destination IP and ports of a connection or null string
	 */
	public static String parseLineToAddressString(String line, Pattern saddrP, Pattern  netfilterP) {
		Matcher sockaddM = saddrP.matcher(line);
		Matcher netfilterM = netfilterP.matcher(line);
		if(sockaddM.find()) {
			String saddr = sockaddM.group(1);
			if(saddr.length() >= 47)
				return saddr.substring(40,48)+":"+saddr.substring(4,8);
		} else if(netfilterM.find()) {
			String res = "";
			String[] IPfields = netfilterM.group(1).split("\\.");
			for(int i=0; i<IPfields.length; i++) {
				res = res+String.format("%02X",Integer.valueOf(IPfields[i]));
			}
			return res+":"+String.format("%04X",Integer.valueOf(netfilterM.group(2)));
		}
		return null;
	}


	/**
	 * Open a file and returns its respective BufferReader
	 *
	 * @param path to file to be opened
	 * @returns buffer to read the log file explicited in path
	 */
	public static BufferedReader openFile(String path) {
		FileReader fr = null;
		try {
			fr = new FileReader(path);
		} catch(IOException e) {
			System.err.println(e.getMessage());
			System.err.println("Couldn't open the log file: "+path);
		}
		return new BufferedReader(fr);
	}
}
